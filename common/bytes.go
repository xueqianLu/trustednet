package common

func CopyBytes(data []byte) []byte {
	d := make([]byte, len(data))
	copy(d, data)
	return d
}
