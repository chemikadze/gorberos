package main

import (
	"github.com/chemikadze/gorberos/authsrv"
)

func main() {
	port := 1088
	listener := authsrv.NewUdpTransport(port)
	listener.Listen()
	listener.Join()
}
