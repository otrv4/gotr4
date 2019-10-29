package gotr4

import (
	"github.com/otrv4/gotrx"
)

type tlv struct {
	tlvType   uint16
	tlvLength uint16
	tlvValue  []byte
}

const (
	tlvTypePadding           = uint16(0x00)
	tlvTypeDisconnected      = uint16(0x01)
	tlvTypeSMP1              = uint16(0x02)
	tlvTypeSMP2              = uint16(0x03)
	tlvTypeSMP3              = uint16(0x04)
	tlvTypeSMP4              = uint16(0x05)
	tlvTypeSMPAbort          = uint16(0x06)
	tlvTypeExtraSymmetricKey = uint16(0x07)
)

func (c *tlv) serialize() []byte {
	out := gotrx.AppendShort([]byte{}, c.tlvType)
	out = gotrx.AppendShort(out, c.tlvLength)
	return append(out, c.tlvValue...)
}
func serializeTLVs(tt []*tlv) []byte {
	out := []byte{}
	for _, t := range tt {
		out = append(out, t.serialize()...)
	}
	return out
}

func (c *tlv) deserialize(tt []byte) ([]byte, bool) {
	var ok bool
	tt, c.tlvType, ok = gotrx.ExtractShort(tt)
	if !ok {
		return nil, false
	}
	tt, c.tlvLength, ok = gotrx.ExtractShort(tt)
	if !ok {
		return nil, false
	}

	tt, c.tlvValue, ok = gotrx.ExtractFixedData(tt, int(c.tlvLength))
	if !ok {
		return nil, false
	}

	return tt, true
}

func (c *conversation) processTLVs(tt []*tlv) {
	for _, t := range tt {
		c.processTLV(t)
	}
}

func (c *conversation) processTLV(t *tlv) {
	switch t.tlvType {
	case tlvTypeDisconnected:
		// TODO: Inform the user
		// TODO: Forget all keys
		c.state = stateFinished{}
	}
}

func createDisconnectedTLV() *tlv {
	return &tlv{
		tlvType:   tlvTypeDisconnected,
		tlvLength: 0,
	}
}
