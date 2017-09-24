package gorberos

import (
	"github.com/chemikadze/gorberos/datamodel"
)

type ClientTransport interface {
	SendAsReq(datamodel.AsReq) (error, datamodel.AsRep)
	SendApReq(datamodel.ApReq) (error, datamodel.ApRep)
}

type Client interface {
	Authenticate() error
	AuthenticateApplication() error
}
