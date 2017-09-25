package gorberos

import (
	"github.com/chemikadze/gorberos/datamodel"
)

type ClientTransport interface {
	SendAsReq(datamodel.AsReq) (error, datamodel.AsRep)
	SendApReq(datamodel.ApReq) (error, datamodel.ApRep)
	SendTgsReq(datamodel.TgsReq) (error, datamodel.TgsRep)
}

type Client interface {
	Authenticate() error
	AuthenticateTgs() error
	AuthenticateApplication() error
}
