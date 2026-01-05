package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	version        = "0.7.2"
	appName        = "mcrcon"
	dataBuffSize   = 4096
	maxWaitTime    = 600
	defaultPort    = "25575"
	defaultHost    = "localhost"
	rconPID        = 0xBADC0DE
)

// RCON packet types
const (
	rconExecCommand    = 2
	rconAuthenticate   = 3
	rconResponseValue  = 0
	rconAuthResponse   = 2
)

// Config holds the application configuration
type Config struct {
	Host           string
	Port           string
	Password       string
	TerminalMode   bool
	SilentMode     bool
	DisableColors  bool
	RawOutput      bool
	WaitSeconds    uint
}

// RCONPacket represents an RCON protocol packet
type RCONPacket struct {
	Size int32
	ID   int32
	Type int32
	Body string
}

// RCONClient manages the RCON connection
type RCONClient struct {
	conn   net.Conn
	config *Config
}

func main() {
	config := parseFlags()

	// Handle interrupt signals gracefully
	setupSignalHandler()

	client, err := NewRCONClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Authenticate
	if err := client.Authenticate(); err != nil {
		fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
		os.Exit(1)
	}

	// Run commands or terminal mode
	var exitCode int
	if config.TerminalMode {
		exitCode = client.RunTerminalMode()
	} else {
		exitCode = client.RunCommands(os.Args[1:])
	}

	os.Exit(exitCode)
}

// NewRCONClient creates a new RCON client connection
func NewRCONClient(config *Config) (*RCONClient, error) {
	address := net.JoinHostPort(config.Host, config.Port)

	// Add retry logic for connection
	var conn net.Conn
	var err error

	for i := 0; i < 3; i++ {
		conn, err = net.DialTimeout("tcp", address, 10*time.Second)
		if err == nil {
			break
		}
		if i < 2 {
			time.Sleep(time.Second)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}

	// Disable Nagle's algorithm for better performance
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	return &RCONClient{
		conn:   conn,
		config: config,
	}, nil
}

// Close closes the RCON connection
func (c *RCONClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Authenticate performs RCON authentication
func (c *RCONClient) Authenticate() error {
	packet := &RCONPacket{
		ID:   rconPID,
		Type: rconAuthenticate,
		Body: c.config.Password,
	}

	if err := c.sendPacket(packet); err != nil {
		return fmt.Errorf("failed to send auth packet: %w", err)
	}

	response, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive auth response: %w", err)
	}

	if response.ID == -1 {
		return errors.New("authentication rejected")
	}

	return nil
}

// ExecuteCommand sends a command and prints the response
func (c *RCONClient) ExecuteCommand(command string) error {
	// Validate command length
	if len(command) >= dataBuffSize {
		return fmt.Errorf("command too long (%d bytes). Maximum: %d", len(command), dataBuffSize-1)
	}

	packet := &RCONPacket{
		ID:   rconPID,
		Type: rconExecCommand,
		Body: command,
	}

	if err := c.sendPacket(packet); err != nil {
		return fmt.Errorf("failed to send command: %w", err)
	}

	response, err := c.receivePacket()
	if err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}

	if response.ID != rconPID {
		return errors.New("invalid response ID")
	}

	if !c.config.SilentMode && len(response.Body) > 0 {
		c.printResponse(response.Body)
	}

	return nil
}

// sendPacket sends an RCON packet
func (c *RCONClient) sendPacket(packet *RCONPacket) error {
	bodyLen := len(packet.Body)
	// Size = ID (4) + Type (4) + Body (n) + null terminator (1) + padding (1)
	packet.Size = int32(4 + 4 + bodyLen + 2)

	// Build packet in buffer to ensure atomic write
	buf := make([]byte, 4+packet.Size)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(packet.Size))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(packet.ID))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(packet.Type))
	copy(buf[12:], []byte(packet.Body))
	// Null terminators already zero in buffer

	// Send entire packet at once
	_, err := c.conn.Write(buf)
	return err
}

// receivePacket receives an RCON packet
func (c *RCONClient) receivePacket() (*RCONPacket, error) {
	// Set read timeout
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	// Read size
	var size int32
	if err := binary.Read(c.conn, binary.LittleEndian, &size); err != nil {
		return nil, fmt.Errorf("failed to read packet size: %w", err)
	}

	// Validate size
	if size < 10 || size > dataBuffSize {
		return nil, fmt.Errorf("invalid packet size: %d (must be 10-%d)", size, dataBuffSize)
	}

	// Read the rest of the packet
	payload := make([]byte, size)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, fmt.Errorf("failed to read packet payload: %w", err)
	}

	// Parse payload
	id := int32(binary.LittleEndian.Uint32(payload[0:4]))
	ptype := int32(binary.LittleEndian.Uint32(payload[4:8]))

	// Body is from byte 8 to size-2 (excluding two null terminators)
	bodySize := size - 10
	bodyStr := string(payload[8 : 8+bodySize])

	return &RCONPacket{
		Size: size,
		ID:   id,
		Type: ptype,
		Body: bodyStr,
	}, nil
}

// printResponse prints the command response with optional color handling
func (c *RCONClient) printResponse(text string) {
	if c.config.RawOutput {
		fmt.Print(text)
		return
	}

	// Strip Minecraft color codes if colors disabled
	if c.config.DisableColors {
		text = stripColorCodes(text)
	} else {
		text = convertColorCodes(text)
	}

	fmt.Print(text)
	if !strings.HasSuffix(text, "\n") {
		fmt.Println()
	}
}

// stripColorCodes removes Minecraft color codes
func stripColorCodes(text string) string {
	var result strings.Builder
	result.Grow(len(text))

	for i := 0; i < len(text); i++ {
		if i+2 < len(text) && text[i] == 0xc2 && text[i+1] == 0xa7 {
			i += 2 // Skip color code
			continue
		}
		result.WriteByte(text[i])
	}

	return result.String()
}

// convertColorCodes converts Minecraft color codes to ANSI
func convertColorCodes(text string) string {
	colorMap := map[byte]string{
		'0': "\033[0;30m",   // BLACK
		'1': "\033[0;34m",   // BLUE
		'2': "\033[0;32m",   // GREEN
		'3': "\033[0;36m",   // CYAN
		'4': "\033[0;31m",   // RED
		'5': "\033[0;35m",   // PURPLE
		'6': "\033[0;33m",   // GOLD
		'7': "\033[0;37m",   // GREY
		'8': "\033[0;1;30m", // DGREY
		'9': "\033[0;1;34m", // LBLUE
		'a': "\033[0;1;32m", // LGREEN
		'b': "\033[0;1;36m", // LCYAN
		'c': "\033[0;1;31m", // LRED
		'd': "\033[0;1;35m", // LPURPLE
		'e': "\033[0;1;33m", // YELLOW
		'f': "\033[0;1;37m", // WHITE
		'n': "\033[4m",      // UNDERLINE
		'r': "\033[0m",      // RESET
	}

	var result strings.Builder
	result.Grow(len(text))

	for i := 0; i < len(text); i++ {
		if i+2 < len(text) && text[i] == 0xc2 && text[i+1] == 0xa7 {
			colorCode := text[i+2]
			if ansi, ok := colorMap[colorCode]; ok {
				result.WriteString(ansi)
			}
			i += 2
			continue
		}
		if text[i] == '\n' {
			result.WriteString("\033[0m")
		}
		result.WriteByte(text[i])
	}

	result.WriteString("\033[0m") // Reset color at end
	return result.String()
}

// RunCommands executes multiple commands with optional delays
func (c *RCONClient) RunCommands(args []string) int {
	commands := extractCommands(args)
	if len(commands) == 0 {
		return 0
	}

	for i, cmd := range commands {
		if err := c.ExecuteCommand(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "Command failed: %v\n", err)
			return 1
		}

		// Wait between commands if configured
		if i < len(commands)-1 && c.config.WaitSeconds > 0 {
			time.Sleep(time.Duration(c.config.WaitSeconds) * time.Second)
		}
	}

	return 0
}

// RunTerminalMode runs interactive terminal mode
func (c *RCONClient) RunTerminalMode() int {
	fmt.Println("Logged in.")
	fmt.Println("Type 'Q' or press Ctrl-D / Ctrl-C to disconnect.")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")

		if !scanner.Scan() {
			break
		}

		command := strings.TrimSpace(scanner.Text())
		if len(command) == 0 {
			continue
		}

		if strings.EqualFold(command, "q") {
			break
		}

		if err := c.ExecuteCommand(command); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}

		// Exit on "stop" command to avoid server-side bug
		if strings.EqualFold(command, "stop") {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Input error: %v\n", err)
		return 1
	}

	return 0
}

// parseFlags parses command line flags and environment variables
func parseFlags() *Config {
	config := &Config{
		Host: getEnvOrDefault("MCRCON_HOST", defaultHost),
		Port: getEnvOrDefault("MCRCON_PORT", defaultPort),
		Password: os.Getenv("MCRCON_PASS"),
	}

	// Simple flag parsing
	var commands []string
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		if !strings.HasPrefix(arg, "-") {
			commands = append(commands, arg)
			continue
		}

		switch arg {
		case "-H":
			if i+1 < len(os.Args) {
				config.Host = os.Args[i+1]
				i++
			}
		case "-P":
			if i+1 < len(os.Args) {
				config.Port = os.Args[i+1]
				i++
			}
		case "-p":
			if i+1 < len(os.Args) {
				config.Password = os.Args[i+1]
				i++
			}
		case "-w":
			if i+1 < len(os.Args) {
				wait, err := parseWaitSeconds(os.Args[i+1])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				config.WaitSeconds = wait
				i++
			}
		case "-t":
			config.TerminalMode = true
		case "-s":
			config.SilentMode = true
		case "-c":
			config.DisableColors = true
		case "-r":
			config.RawOutput = true
		case "-v":
			fmt.Printf("%s %s\n", appName, version)
			fmt.Println("https://github.com/Tiiffi/mcrcon")
			os.Exit(0)
		case "-h":
			printUsage()
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "Unknown option: %s\n", arg)
			fmt.Println("Try 'mcrcon -h' for help.")
			os.Exit(1)
		}
	}

	if config.Password == "" {
		fmt.Println("You must provide password (-p password).")
		fmt.Println("Try 'mcrcon -h' for help.")
		os.Exit(1)
	}

	// Enable terminal mode if no commands given
	if len(commands) == 0 {
		config.TerminalMode = true
	}

	return config
}

func parseWaitSeconds(s string) (uint, error) {
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid wait value: %v", err)
	}

	if val <= 0 || val > maxWaitTime {
		return 0, fmt.Errorf("wait value out of range (1-%d)", maxWaitTime)
	}

	return uint(val), nil
}

func extractCommands(args []string) []string {
	var commands []string
	skipNext := false

	for i, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		if strings.HasPrefix(arg, "-") {
			// Skip flags that take arguments
			if arg == "-H" || arg == "-P" || arg == "-p" || arg == "-w" {
				skipNext = true
			}
			continue
		}

		if i > 0 { // Skip program name
			commands = append(commands, arg)
		}
	}

	return commands
}

func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nDisconnecting...")
		os.Exit(0)
	}()
}

func printUsage() {
	fmt.Printf(`Usage: %s [OPTIONS] [COMMANDS]

Send rcon commands to Minecraft server.

Options:
  -H		Server address (default: localhost)
  -P		Port (default: 25575)
  -p		Rcon password
  -t		Terminal mode
  -s		Silent mode
  -c		Disable colors
  -r		Output raw packets
  -w		Wait for specified duration (seconds) between each command (1-600s)
  -h		Print usage
  -v		Version information

Server address, port and password can be set with following environment variables:
  MCRCON_HOST
  MCRCON_PORT
  MCRCON_PASS

- mcrcon will start in terminal mode if no commands are given
- Command-line options will override environment variables
- Rcon commands with spaces must be enclosed in quotes

Example:
	%s -H my.minecraft.server -p password -w 5 "say Server is restarting!" save-all stop

`, appName, appName)
}
