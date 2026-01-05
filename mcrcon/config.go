package mcrcon

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

