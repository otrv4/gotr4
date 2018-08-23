package gotra

import (
	"bytes"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
	"golang.org/x/crypto/salsa20"
)

type dataMessage struct {
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	flags               uint8
	pn                  uint32
	ratchetId           uint32
	messageId           uint32
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
	return c.createDataMessage([]byte{0x00})
}

func (c *conversation) createDataMessage(m []byte) ValidMessage {
	c.maybeRatchetSender()

	dm := &dataMessage{}
	dm.senderInstanceTag = c.getInstanceTag()
	dm.receiverInstanceTag = c.otherInstanceTag
	// TODO: we should probably set pn somewhere
	// TODO: we need to set ignore unreadable here
	//	dm.flags =
	dm.ecdh = c.our_ecdh.Pub.K()
	dm.dh = c.our_dh.pub

	dm.messageId = c.ratchetJ
	dm.ratchetId = c.ratchetId - 1

	mke, mkm := c.deriveCurrentMK(c.sendingChainKey)
	c.sendingChainKey = gotrax.Kdf(usageNextChainKey, 64, c.sendingChainKey)
	// TODO: Securely delete the old sending chain key

	// TODO: don't ignore error here
	gotrax.RandomInto(c, dm.nonce[:])

	dm.msg = make([]byte, len(m))
	var key [32]byte
	copy(key[:], mke)
	salsa20.XORKeyStream(dm.msg, m, dm.nonce[:], &key)

	copy(dm.mac[:], gotrax.Kdf(usageAuthenticator, 64, append(mkm, gotrax.Kdf(usageDataMessageSections, 64, dm.serializeForMac())...)))

	// TODO: securely delete mke and mkm - oh wait, shouldn't we keep mkm for revealing?

	c.ratchetJ++

	return ValidMessage(dm.serialize())
}

func (c *conversation) receivedDataMessage(dm *dataMessage) (plain MessagePlaintext, toSend []ValidMessage, err error) {
	// TODO: check for out of order messages

	// TODO: what happens if we receive messageId = 1 for a new ratchet?
	// This is probably a spec problem
	if c.their_ecdh == nil || !dm.ecdh.Equals(c.their_ecdh) {
		// TODO: we need to rotate ratchet here
		// TODO: store message keys for previous ratchet, based on dm.pn
		c.their_ecdh = dm.ecdh
		c.their_dh = dm.dh.k

		c.ratchetReceiver()
	}

	// TODO: store missing messages here

	mke, mkm := c.deriveCurrentMK(c.receivingChainKey)
	auth := gotrax.Kdf(usageAuthenticator, 64, append(mkm, gotrax.Kdf(usageDataMessageSections, 64, dm.serializeForMac())...))
	if !bytes.Equal(auth, dm.mac[:]) {
		// TODO: handle this better
		// TODO: delete mke and mkm safely
		return nil, nil, nil
	}

	c.receivingChainKey = gotrax.Kdf(usageNextChainKey, 64, c.receivingChainKey)
	// TODO: securely delete the old chain key
	c.ratchetK++

	msg := make([]byte, len(dm.msg))
	var key [32]byte
	copy(key[:], mke)
	salsa20.XORKeyStream(msg, dm.msg, dm.nonce[:], &key)

	msgp := bytes.Split(msg, []byte{0x00})

	return MessagePlaintext(msgp[0]), nil, nil
}
