package gorberos

import (
	"github.com/chemikadze/gorberos/datamodel"
)

type ClientTransport interface {
	SendAsReq(datamodel.AS_REQ) (error, datamodel.AS_REP)
	SendApReq(datamodel.AP_REQ) (error, datamodel.AP_REP)
	SendTgsReq(datamodel.TGS_REQ) (error, datamodel.TGS_REP)
}

type Client interface {
	Authenticate() error
	AuthenticateTgs() error
	AuthenticateApplication() error
}
