package datamodel

import "encoding/asn1"

type Serializer interface {
	Marshal(interface{}) ([]byte, error)
	Unmarshal([]byte, interface{}) error
}

type asn1Serializer struct {
}

func (asn1Serializer) Marshal(val interface{}) ([]byte, error) {
	return asn1.Marshal(val)
}

func (asn1Serializer) Unmarshal(data []byte, val interface{}) error {
	_, err := asn1.Unmarshal(data, val)
	return err
}

var _ Serializer = asn1Serializer{}

func NewSerializer() Serializer {
	return asn1Serializer{}
}