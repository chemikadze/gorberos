package crypto

import "crypto/rand"

func GenerateSeqNumber() uint32 {
	buffer := make([]byte, 2)
	_, err := rand.Read(buffer)
	if err != nil {
		panic("Failed to read random data")
	}
	var result uint32
	result = uint32(buffer[0])<<8 + uint32(buffer[1])
	return result
}
