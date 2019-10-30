package gotr4

import "github.com/otrv4/gotrx"

func (m *dataMessage) serializeForMac() []byte {
	out := gotrx.AppendShort(nil, version)
	out = append(out, messageTypeDataMessage)
	out = gotrx.AppendWord(out, m.senderInstanceTag)
	out = gotrx.AppendWord(out, m.receiverInstanceTag)
	out = append(out, m.flags)
	out = gotrx.AppendWord(out, m.pn)
	out = gotrx.AppendWord(out, m.ratchetID)
	out = gotrx.AppendWord(out, m.messageID)
	out = append(out, gotrx.SerializePoint(m.ecdh)...)
	out = append(out, m.dh.serialize()...)
	out = append(out, m.nonce[:]...)
	out = gotrx.AppendData(out, m.msg)
	return out
}

func (m *dataMessage) serialize() []byte {
	out := m.serializeForMac()
	out = append(out, m.mac[:]...)
	out = gotrx.AppendData(out, m.oldMacKeys)
	return out
}

func (m *dataMessage) deserialize(buf []byte) ([]byte, bool) {
	var ok bool
	buf, v, ok := gotrx.ExtractShort(buf)
	if !ok || v != version {
		return buf, false
	}

	if len(buf) < 1 || buf[0] != messageTypeDataMessage {
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

	buf, m.flags, ok = gotrx.ExtractByte(buf)
	if !ok {
		return buf, false
	}

	buf, m.pn, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.ratchetID, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.messageID, ok = gotrx.ExtractWord(buf)
	if !ok {
		return buf, false
	}

	buf, m.ecdh, ok = gotrx.DeserializePoint(buf)
	if !ok {
		return buf, false
	}

	m.dh = &dhPublicKey{}
	buf, m.dh.k, ok = gotrx.ExtractMPI(buf)
	if !ok {
		return buf, false
	}

	var nonce []byte
	buf, nonce, ok = gotrx.ExtractFixedData(buf, 24)
	if !ok {
		return buf, false
	}
	copy(m.nonce[:], nonce)

	buf, m.msg, ok = gotrx.ExtractData(buf)
	if !ok {
		return buf, false
	}

	var mac []byte
	buf, mac, ok = gotrx.ExtractFixedData(buf, 64)
	if !ok {
		return buf, false
	}
	copy(m.mac[:], mac)

	buf, m.oldMacKeys, ok = gotrx.ExtractData(buf)
	if !ok {
		return buf, false
	}

	return buf, true
}
