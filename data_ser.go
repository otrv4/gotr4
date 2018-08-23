package gotra

import "github.com/coyim/gotrax"

func (m *dataMessage) serializeForMac() []byte {
	out := gotrax.AppendShort(nil, version)
	out = append(out, messageTypeDataMessage)
	out = gotrax.AppendWord(out, m.senderInstanceTag)
	out = gotrax.AppendWord(out, m.receiverInstanceTag)
	out = append(out, m.flags)
	out = gotrax.AppendWord(out, m.pn)
	out = gotrax.AppendWord(out, m.ratchetId)
	out = gotrax.AppendWord(out, m.messageId)
	out = append(out, gotrax.SerializePoint(m.ecdh)...)
	out = append(out, m.dh.serialize()...)
	out = append(out, m.nonce[:]...)
	out = gotrax.AppendData(out, m.msg)
	return out
}

func (m *dataMessage) serialize() []byte {
	out := m.serializeForMac()
	out = append(out, m.mac[:]...)
	out = gotrax.AppendData(out, m.oldMacKeys)
	return out
}

func (m *dataMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrax.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeDataMessage {
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

	buf, m.flags, ok = gotrax.ExtractByte(buf)
	if !ok {
		return buf, false
	}

	buf, m.pn, ok = gotrax.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.ratchetId, ok = gotrax.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.messageId, ok = gotrax.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.ecdh, ok = gotrax.DeserializePoint(buf)
	if !ok {
		return buf, false
	}

	m.dh = &dhPublicKey{}
	buf, m.dh.k, ok = gotrax.ExtractMPI(buf)
	if !ok {
		return buf, false
	}

	var nonce []byte
	buf, nonce, ok = gotrax.ExtractFixedData(buf, 24)
	if !ok {
		return buf, false
	}
	copy(m.nonce[:], nonce)

	buf, m.msg, ok = gotrax.ExtractData(buf)
	if !ok {
		return buf, false
	}

	var mac []byte
	buf, mac, ok = gotrax.ExtractFixedData(buf, 64)
	if !ok {
		return buf, false
	}
	copy(m.mac[:], mac)

	buf, m.oldMacKeys, ok = gotrax.ExtractData(buf)
	if !ok {
		return buf, false
	}

	return buf, true
}
