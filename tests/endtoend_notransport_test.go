package tests

import (
	"github.com/chemikadze/gorberos/authsrv"
	clientPackage "github.com/chemikadze/gorberos/client"
	"github.com/chemikadze/gorberos/datamodel"
	"testing"
)

func TestAsEndToEnd(t *testing.T) {
	db := NewMockDatabase()
	db.InsertPrincipal(newPrincInfo("chemikadze"))
	db.InsertPrincipal(newPrincInfo("hive/localhost"))

	crypto := NewMockEncFactory()
	server := asrv.NewAuthServer("LOCALHOST", db, crypto)
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
}
