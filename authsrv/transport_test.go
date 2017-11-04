package authsrv

import (
	"testing"
)

func TestPoisonPill(t *testing.T) {
	transport := NewUdpTransport(1234).(*udpTransport)
	if transport.shouldStop() {
		t.Error("Newly created transport should not stop")
	}
	transport.Close()
	if !transport.shouldStop() {
		t.Error("Transport should stop after close called")
	}
}
