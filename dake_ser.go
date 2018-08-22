package gotra

import (
	"math/big"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

func (m *identityMessage) serialize() []byte {
	out := gotrax.AppendShort(nil, version)
	out = append(out, messageTypeIdentityMessage)
	out = gotrax.AppendWord(out, m.senderInstanceTag)
	out = gotrax.AppendWord(out, m.receiverInstanceTag)
	out = append(out, m.clientProfile.Serialize()...)
	out = append(out, m.y.Serialize()...)
	out = append(out, m.b.serialize()...)
	return out
}

func (m *identityMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrax.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeIdentityMessage {
		return buf, false
	}
	buf = buf[1:]

	buf, m.senderInstanceTag, ok = gotrax.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.receiverInstanceTag, ok = gotrax.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	m.clientProfile = &gotrax.ClientProfile{}
	buf, ok = m.clientProfile.Deserialize(buf)
	if !ok {
		return buf, false
	}

	var y ed448.Point
	buf, y, ok = gotrax.DeserializePoint(buf)
	if !ok {
		return buf, false
	}
	m.y = gotrax.CreatePublicKey(y, gotrax.Ed448Key)

	var b *big.Int
	buf, b, ok = gotrax.ExtractMPI(buf)
	if !ok {
		return buf, false
	}
	m.b = &dhPublicKey{k: b}

	return buf, true
}
