package authsrv

import (
	"github.com/chemikadze/gorberos/logging"
	"net"
)

type Transport interface {
	Listen() error
	Join() error
	Close()
}

type udpTransport struct {
	addr       *net.UDPAddr
	net        string
	conn       *net.UDPConn
	poisonPill chan interface{}
	closed     chan error
}

func NewUdpTransport(port int) Transport {
	addr := net.UDPAddr{
		IP:   net.IPv4zero,
		Port: port,
	}
	transport := udpTransport{
		addr:       &addr,
		net:        "udp4",
		poisonPill: make(chan interface{}),
		closed:     make(chan error),
	}
	return &transport
}

func (t *udpTransport) shouldStop() bool {
	select {
	case _, ok := <-t.poisonPill:
		if !ok {
			return true
		}
		return false
	default:
		return false
	}
}

func (t *udpTransport) Listen() error {
	conn, err := net.ListenUDP(t.net, t.addr)
	if err != nil {
		logging.Infof("Failed to bind to %v: %v", t.addr, err.Error())
		return err
	}
	logging.Infof("Listening on %v", t.addr)
	t.conn = conn
	go t.doListen()
	return nil
}

func (t *udpTransport) doListen() {
	buffer := make([]byte, 1024)
	for {
		if t.shouldStop() {
			logging.Infof("Closing server on %v", t.addr)
			err := t.conn.Close()
			if err != nil {
				logging.Errorf("Failed to close: %v", err.Error())
				t.closed <- err
				return
			} else {
				t.closed <- nil
				return
			}
		}
		n, addr, err := t.conn.ReadFromUDP(buffer)
		if err != nil {
			logging.Errorf("Failed to read packet from %v: %v", addr, err.Error())
			continue
		}
		packet := buffer[:n]
		logging.Debugf("Got packet from %v: %v", addr, packet)
	}
}

func (t *udpTransport) Close() {
	close(t.poisonPill)
}

func (t *udpTransport) Join() error {
	return <-t.closed
}
