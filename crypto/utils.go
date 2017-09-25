package crypto

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

func GenerateSeqNumber() uint32 {
	buffer := make([]byte, 2)
	_, err := rand.Read(buffer)
	if err != nil {
		panic(fmt.Sprintf("Failed to read random data: %v", err.Error()))
	}
	var result uint32
	result = uint32(buffer[0])<<8 + uint32(buffer[1])
	return result
}

func GenerateNonce() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random int: %v", err.Error()))
	}
	nonce := uint32(n.Uint64())
	return nonce
}
