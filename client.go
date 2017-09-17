package gorberos

import (
	"github.com/chemikadze/gorberos/datamodel"
)

type ClientTransport interface {
	SendAsReq(datamodel.AsReq) (error, datamodel.AsRep)
}

type Client interface {
	Authenticate() error
}
