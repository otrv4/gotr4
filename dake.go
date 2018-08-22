package gotra

import (
	"github.com/coyim/gotrax"
)

type identityMessage struct {
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	clientProfile       *gotrax.ClientProfile
	y                   *gotrax.PublicKey
	b                   *dhPublicKey
}

type authRMessage struct {
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	clientProfile       *gotrax.ClientProfile
	x                   *gotrax.PublicKey
	a                   *dhPublicKey
	// sigma
}

func (c *conversation) createIdentityMessage() ValidMessage {
	cp := c.getValidClientProfile()
	itag := c.getInstanceTag()
	ykp := gotrax.GenerateKeypair(c)
	bkp, _ := generateDHKeypair(c)

	im := &identityMessage{
		senderInstanceTag:   itag,
		receiverInstanceTag: uint32(0x00),
		clientProfile:       cp,
		y:                   ykp.Pub,
		b:                   bkp.pub,
	}

	return ValidMessage(im.serialize())
}

func (m *identityMessage) validate(tag uint32) error {
	// TODO: implement
	// Validate the Client Profile, as defined in Validating a Client Profile section.
	// Verify that the point Y received is on curve Ed448. See Verifying that a point is on the curve section for details.
	// Verify that the DH public key B is from the correct group. See Verifying that an integer is in the DH group section for details.

	return nil
}

func (c *conversation) createAuthRMessage(im *identityMessage) ValidMessage {
	return nil
}
