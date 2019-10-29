package gotr4

import (
	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
)

type identityMessage struct {
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	clientProfile       *gotrx.ClientProfile
	y                   ed448.Point
	b                   *dhPublicKey
}

type identityMessagePrivate struct {
	y *gotrx.Keypair
	b *dhKeypair
}

type authRMessage struct {
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	clientProfile       *gotrx.ClientProfile
	x                   ed448.Point
	a                   *dhPublicKey
	sigma               *gotrx.RingSignature
}

type authRMessagePrivate struct {
	x *gotrx.Keypair
	a *dhKeypair
}

type authIMessage struct {
	senderInstanceTag   uint32
	receiverInstanceTag uint32
	sigma               *gotrx.RingSignature
}

func (c *conversation) createIdentityMessage() ValidMessage {
	cp := c.getValidClientProfile()
	itag := c.getInstanceTag()
	ykp := gotrx.GenerateKeypair(c)
	bkp, _ := generateDHKeypair(c)

	im := &identityMessage{
		senderInstanceTag:   itag,
		receiverInstanceTag: uint32(0x00),
		clientProfile:       cp,
		y:                   ykp.Pub.K(),
		b:                   bkp.pub,
	}

	c.im = im
	c.imp = &identityMessagePrivate{y: ykp, b: bkp}
	return ValidMessage(im.serialize())
}

func (m *identityMessage) validate(tag uint32) error {
	// TODO: implement
	// Validate the Client Profile, as defined in Validating a Client Profile section.
	// Verify that the point Y received is on curve Ed448. See Verifying that a point is on the curve section for details.
	// Verify that the DH public key B is from the correct group. See Verifying that an integer is in the DH group section for details.

	return nil
}

func (c *conversation) createAuthRMessage() ValidMessage {
	cp := c.getValidClientProfile()
	itag := c.getInstanceTag()
	xkp := gotrx.GenerateKeypair(c)
	akp, _ := generateDHKeypair(c)

	ar := &authRMessage{
		senderInstanceTag:   itag,
		receiverInstanceTag: c.im.senderInstanceTag,
		clientProfile:       cp,
		x:                   xkp.Pub.K(),
		a:                   akp.pub,
	}

	// TODO: figure out a real phi
	phi := []byte{}

	t := []byte{0x00}
	t = append(t, gotrx.Kdf(usageAuthRBobClientProfile, 64, c.im.clientProfile.Serialize())...)
	t = append(t, gotrx.Kdf(usageAuthRAliceClientProfile, 64, cp.Serialize())...)
	t = append(t, gotrx.SerializePoint(c.im.y)...)
	t = append(t, xkp.Pub.Serialize()...)
	t = append(t, c.im.b.serialize()...)
	t = append(t, akp.pub.serialize()...)
	t = append(t, gotrx.Kdf(usageAuthRPhi, 64, phi)...)

	longTerm := c.getKeypair()
	yk := gotrx.CreatePublicKey(c.im.y, gotrx.Ed448Key)

	// TODO: don't ignore this error
	ar.sigma, _ = gotrx.GenerateSignature(c, longTerm.Priv, longTerm.Pub, c.im.clientProfile.PublicKey, longTerm.Pub, yk, t, gotrx.Kdf, usageAuth)

	c.ar = ar
	c.arp = &authRMessagePrivate{x: xkp, a: akp}
	return ValidMessage(ar.serialize())
}

func (m *authRMessage) validate(tag uint32) error {
	// TODO: implement
	// Check that the receiver's instance tag matches your sender's instance tag.
	// Validate the Client Profile as defined in Validating a Client Profile section. Extract H_a from it.
	// Verify that the point X received is on curve Ed448. See Verifying that a point is on the curve section for details.
	// Verify that the DH public key A is from the correct group. See Verifying that an integer is in the DH group section for details.
	// Compute t = 0x0 || KDF_1(usageAuthRBobClientProfile || Bob_Client_Profile, 64) || KDF_1(usageAuthRAliceClientProfile || Alice_Client_Profile, 64) || Y || X || B || A || KDF_1(usageAuthRPhi || phi, 64). phi is the shared session state as mention in its section.
	// Verify the sigma as defined in Ring Signature Authentication.

	return nil
}

func (c *conversation) createAuthIMessage() ValidMessage {
	cp := c.getValidClientProfile()
	itag := c.getInstanceTag()

	ai := &authIMessage{
		senderInstanceTag:   itag,
		receiverInstanceTag: c.ar.senderInstanceTag,
	}

	// TODO: figure out a real phi
	phi := []byte{}

	t := []byte{0x01}
	t = append(t, gotrx.Kdf(usageAuthIBobClientProfile, 64, cp.Serialize())...)
	t = append(t, gotrx.Kdf(usageAuthIAliceClientProfile, 64, c.ar.clientProfile.Serialize())...)
	t = append(t, gotrx.SerializePoint(c.im.y)...)
	t = append(t, gotrx.SerializePoint(c.ar.x)...)
	t = append(t, c.im.b.serialize()...)
	t = append(t, c.ar.a.serialize()...)
	t = append(t, gotrx.Kdf(usageAuthIPhi, 64, phi)...)

	longTerm := c.getKeypair()

	// TODO: don't ignore this error
	ai.sigma, _ = gotrx.GenerateSignature(c, longTerm.Priv, longTerm.Pub, longTerm.Pub, c.ar.clientProfile.PublicKey, gotrx.CreatePublicKey(c.ar.x, gotrx.Ed448Key), t, gotrx.Kdf, usageAuth)

	c.ai = ai
	return ValidMessage(ai.serialize())
}

func (m *authIMessage) validate(tag uint32) error {
	// TODO: implement
	// Check that the receiver's instance tag matches your sender's instance tag.
	// Compute t = 0x1 || KDF_1(usageAuthIBobClientProfile || Bobs_Client_Profile, 64) || KDF_1(usageAuthIAliceClientProfile || Alices_Client_Profile, 64) || Y || X || B || A || KDF_1(usageAuthIPhi || phi, 64). phi is the shared session state as mention in its section.
	// Verify the sigma as defined in Ring Signature Authentication.
	return nil
}
