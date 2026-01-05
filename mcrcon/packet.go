package mcrcon

// RCON packet types
const (
	rconExecCommand    = 2
	rconAuthenticate   = 3
)

// RCONPacket represents an RCON protocol packet
type RCONPacket struct {
	Size int32
	ID   int32
	Type int32
	Body string
}
