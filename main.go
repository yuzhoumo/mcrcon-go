package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

    "mcrcon-go/mcrcon"
)

func main() {
	config := parseFlags()

	// Handle interrupt signals gracefully
	setupSignalHandler()

	client, err := mcrcon.NewRCONClient(config)
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

// parseFlags parses command line flags and environment variables
func parseFlags() *mcrcon.Config {
	config := &mcrcon.Config{
		Host: getEnvOrDefault("MCRCON_HOST", mcrcon.DefaultHost),
		Port: getEnvOrDefault("MCRCON_PORT", mcrcon.DefaultPort),
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
			fmt.Printf("%s %s\n", mcrcon.AppName, mcrcon.Version)
			fmt.Println("https://github.com/Tiiffi/mcrcon")
			os.Exit(0)
		case "-h":
			mcrcon.PrintHelp()
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

	if val <= 0 || val > mcrcon.MaxWaitTime {
		return 0, fmt.Errorf("wait value out of range (1-%d)", mcrcon.MaxWaitTime)
	}

	return uint(val), nil
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
