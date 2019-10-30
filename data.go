package gotr4

import (
	"bytes"

	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
	"golang.org/x/crypto/salsa20"
)

type dataMessage struct {
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	flags               uint8
	pn                  uint32
	ratchetID           uint32
	messageID           uint32
	ecdh                ed448.Point
	dh                  *dhPublicKey
	nonce               [24]byte
	msg                 []byte
	mac                 [64]byte
	oldMacKeys          []byte
}

func (m *dataMessage) validate(tag uint32) error {
	// TODO: implement
	//  - check the instance tags
	//  - we will do the other checking later on

	return nil
}

func (c *conversation) createHeartbeatDataMessage() ValidMessage {
	// No message and no TLVs - look up if this is actually the correct format
	return c.createDataMessage([]byte{0x00}, []*tlv{})
}

func (c *conversation) createDataMessage(m []byte, tt []*tlv) ValidMessage {
	c.maybeRatchetSender()

	dm := &dataMessage{}
	dm.senderInstanceTag = c.getInstanceTag()
	dm.receiverInstanceTag = c.otherInstanceTag
	// TODO: we should probably set pn somewhere
	// TODO: we need to set ignore unreadable here
	//	dm.flags =
	dm.ecdh = c.ourEcdh.Pub.K()
	dm.dh = c.ourDh.pub

	dm.messageID = c.ratchetJ
	dm.ratchetID = c.ratchetID - 1

	mke, mkm := c.deriveCurrentMK(c.sendingChainKey)
	c.sendingChainKey = gotrx.Kdf(usageNextChainKey, 64, c.sendingChainKey)
	// TODO: Securely delete the old sending chain key

	// TODO: don't ignore error here
	gotrx.RandomInto(c, dm.nonce[:])

	mm := m
	if len(tt) > 0 {
		mm = append(append(mm, 0x00), serializeTLVs(tt)...)
	}

	dm.msg = make([]byte, len(mm))
	var key [32]byte
	copy(key[:], mke)
	salsa20.XORKeyStream(dm.msg, mm, dm.nonce[:], &key)

	copy(dm.mac[:], gotrx.Kdf(usageAuthenticator, 64, append(mkm, gotrx.Kdf(usageDataMessageSections, 64, dm.serializeForMac())...)))

	// TODO: securely delete mke and mkm - oh wait, shouldn't we keep mkm for revealing?

	c.ratchetJ++

	return ValidMessage(dm.serialize())
}

func (c *conversation) receivedDataMessage(dm *dataMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO: check for out of order messages

	// TODO: what happens if we receive messageID = 1 for a new ratchet?
	// This is probably a spec problem
	if c.theirEcdh == nil || !dm.ecdh.Equals(c.theirEcdh) {
		// TODO: we need to rotate ratchet here
		// TODO: store message keys for previous ratchet, based on dm.pn
		c.theirEcdh = dm.ecdh
		c.theirDh = dm.dh.k

		c.ratchetReceiver()
	}

	// TODO: store missing messages here

	mke, mkm := c.deriveCurrentMK(c.receivingChainKey)
	auth := gotrx.Kdf(usageAuthenticator, 64, append(mkm, gotrx.Kdf(usageDataMessageSections, 64, dm.serializeForMac())...))
	if !bytes.Equal(auth, dm.mac[:]) {
		// TODO: handle this better
		// TODO: delete mke and mkm safely
		return nil, nil, nil
	}

	c.receivingChainKey = gotrx.Kdf(usageNextChainKey, 64, c.receivingChainKey)
	// TODO: securely delete the old chain key
	c.ratchetK++

	msg := make([]byte, len(dm.msg))
	var key [32]byte
	copy(key[:], mke)
	salsa20.XORKeyStream(msg, dm.msg, dm.nonce[:], &key)
	mm, t := parseMessageData(msg)

	// TODO: don't ignore return values here
	c.processTLVs(t)

	return mm, nil, nil
}

func parseMessageData(m []byte) (MessagePlaintext, []*tlv) {
	msgp := bytes.SplitN(m, []byte{0x00}, 2)
	switch len(msgp) {
	case 0:
		return MessagePlaintext{}, nil
	case 1:
		return MessagePlaintext(msgp[0]), nil
	default:
		return MessagePlaintext(msgp[0]), parseTlvs(msgp[1])
	}
}

func parseTlvs(tt []byte) []*tlv {
	res := []*tlv{}
	var ok bool
	for len(tt) > 0 {
		t := &tlv{}
		if tt, ok = t.deserialize(tt); !ok {
			return nil
		}
		res = append(res, t)
	}
	return res
}
