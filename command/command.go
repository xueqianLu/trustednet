package command

const (
	AUTH_COMMAND byte = iota
	VERIFY_COMMAND
	GETKEY_COMMAND
	DISCONNECT_COMMAND
)

func NewAuthCommand(data []byte) []byte {
	return append([]byte{AUTH_COMMAND}, data...)
}
func NewVerifyCommand(data []byte) []byte {
	return append([]byte{VERIFY_COMMAND}, data...)
}

func NewGetKeyCommand(data []byte) []byte {
	return append([]byte{GETKEY_COMMAND}, data...)
}

func NewDisconnectCommand() []byte {
	return []byte{DISCONNECT_COMMAND}
}
