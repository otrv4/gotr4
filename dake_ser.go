package gotr4

import (
	"github.com/otrv4/gotrx"
)

func (m *identityMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeIdentityMessage)
	out = gotrx.AppendWord(out, m.senderInstanceTag)
	out = gotrx.AppendWord(out, m.receiverInstanceTag)
	out = append(out, m.clientProfile.Serialize()...)
	out = append(out, gotrx.SerializePoint(m.y)...)
	out = append(out, m.b.serialize()...)
	return out
}

func (m *identityMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeIdentityMessage {
		return buf, false
	}
	buf = buf[1:]

	buf, m.senderInstanceTag, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.receiverInstanceTag, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	m.clientProfile = &gotrx.ClientProfile{}
	buf, ok = m.clientProfile.Deserialize(buf)
	if !ok {
		return buf, false
	}

	buf, m.y, ok = gotrx.DeserializePoint(buf)
	if !ok {
		return buf, false
	}

	m.b = &dhPublicKey{}
	buf, m.b.k, ok = gotrx.ExtractMPI(buf)
	if !ok {
		return buf, false
	}

	return buf, true
}

func (m *authRMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeAuthRMessage)
	out = gotrx.AppendWord(out, m.senderInstanceTag)
	out = gotrx.AppendWord(out, m.receiverInstanceTag)
	out = append(out, m.clientProfile.Serialize()...)
	out = append(out, gotrx.SerializePoint(m.x)...)
	out = append(out, m.a.serialize()...)
	out = append(out, m.sigma.Serialize()...)
	return out
}

func (m *authRMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeAuthRMessage {
		return buf, false
	}
	buf = buf[1:]

	buf, m.senderInstanceTag, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.receiverInstanceTag, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	m.clientProfile = &gotrx.ClientProfile{}
	buf, ok = m.clientProfile.Deserialize(buf)
	if !ok {
		return buf, false
	}

	buf, m.x, ok = gotrx.DeserializePoint(buf)
	if !ok {
		return buf, false
	}

	m.a = &dhPublicKey{}
	buf, m.a.k, ok = gotrx.ExtractMPI(buf)
	if !ok {
		return buf, false
	}

	m.sigma = &gotrx.RingSignature{}
	if buf, ok = m.sigma.Deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}

func (m *authIMessage) serialize() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeAuthIMessage)
	out = gotrx.AppendWord(out, m.senderInstanceTag)
	out = gotrx.AppendWord(out, m.receiverInstanceTag)
	out = append(out, m.sigma.Serialize()...)
	return out
}

func (m *authIMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeAuthIMessage {
		return buf, false
	}
	buf = buf[1:]

	buf, m.senderInstanceTag, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.receiverInstanceTag, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	m.sigma = &gotrx.RingSignature{}
	if buf, ok = m.sigma.Deserialize(buf); !ok {
		return nil, false
	}

	return buf, true
}
