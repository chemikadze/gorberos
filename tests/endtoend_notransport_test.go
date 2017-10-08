package tests

import (
	"github.com/chemikadze/gorberos/authsrv"
	clientPackage "github.com/chemikadze/gorberos/client"
	"github.com/chemikadze/gorberos/datamodel"
	"testing"
)

func TestAsEndToEnd(t *testing.T) {
	crypto := NewMockEncFactory()
	algo := crypto.Create(crypto.SupportedETypes()[0])

	db := NewMockDatabase()
	db.InsertPrincipal(newPrincInfo("chemikadze", algo.GenerateKey()))
	db.InsertPrincipal(newPrincInfo("hive/localhost", algo.GenerateKey()))

	server := authsrv.NewKdcServer("LOCALHOST", db, crypto)
	transport := newNoopTransport(server)

	params := clientPackage.SessionParams{
		CName: datamodel.PrincipalNameFromString("chemikadze"),
		SName: datamodel.PrincipalNameFromString("hive/localhost"),
		Realm: datamodel.Realm("LOCALHOST"),
	}
	client := clientPackage.New(transport, crypto, params)

	err := client.Authenticate()

	if err != nil {
		t.Errorf("auth error: %v", err.Error())
	}

	err = client.AuthenticateTgs()

	if err != nil {
		t.Errorf("tgs auth error: %v", err.Error())
	}
}
