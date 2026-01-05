package mcrcon

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// RCONClient manages the RCON connection
type RCONClient struct {
	conn   net.Conn
	config *Config
}

// NewRCONClient creates a new RCON client connection
func NewRCONClient(config *Config) (*RCONClient, error) {
	address := net.JoinHostPort(config.Host, config.Port)

	// Add retry logic for connection
	var conn net.Conn
	var err error

	for i := range 3 {
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
