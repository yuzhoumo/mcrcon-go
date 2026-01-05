package mcrcon

import (
    "strings"
)

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
