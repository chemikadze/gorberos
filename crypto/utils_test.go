package crypto

import (
	"testing"
)

func TestGenerateSeqNumber(t *testing.T) {
	val1 := GenerateSeqNumber()
	val2 := GenerateSeqNumber()
	// very little change to clash, fuck it
	if val1 == val2 {
		t.Error("Generate sequence number should generate random numbers")
	}
	okFirstByte := false
	okSecondByte := false
	for i := 0; i < 10; i++ {
		x := GenerateSeqNumber()
		okSecondByte = okSecondByte || (x&0xFF != 0)
		okFirstByte = okFirstByte || (x&0xFF00 != 0)
	}
	if !okFirstByte {
		t.Error("First byte should be popluated during generation")
	}
	if !okSecondByte {
		t.Error("Second byte should be popluated during generation")
	}
}
