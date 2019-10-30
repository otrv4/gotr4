package gotr4

import (
	"math/big"

	"github.com/otrv4/ed448"
	"github.com/otrv4/gotrx"
)

// This method can only be called by Bob - the person receiving the Auth-R message
func (c *conversation) initializeRatchetR() error {
	c.theirEcdh = c.ar.x
	c.theirDh = c.ar.a.k

	c.ourEcdh = c.imp.y
	c.ourDh = c.imp.b

	kEcdh := ed448.PointScalarMul(c.theirEcdh, c.ourEcdh.Priv.K())
	// TODO: Securely deletes ourEcdh.Priv.
	kDh := modExp(c.theirDh, c.ourDh.priv.k)
	// TODO: Securely deletes ourDh.priv.

	c.braceKey = gotrx.Kdf(usageThirdBraceKey, 32, gotrx.AppendMPI([]byte{}, kDh))
	// TODO: Securely deletes kDh
	k := gotrx.Kdf(usageSharedSecret, 64, append(gotrx.SerializePoint(kEcdh), c.braceKey...))
	// TODO: securely delete kEcdh and c.braceKey
	c.ssid = gotrx.Kdf(usageSSID, 8, k)

	c.ratchetID = 0
	c.ratchetJ = 0
	c.ratchetK = 0
	c.ratchetPN = 0
	c.rootKey = k

	var r1 [57]byte
	gotrx.Kdfx(usageECDHFirstEphemeral, r1[:], k)
	c.ourEcdh = gotrx.DeriveKeypair(r1)
	// TODO: securely delete r1 and old ourEcdh

	r2 := gotrx.Kdf(usageDHFirstEphemeral, 80, k)
	r2x := new(big.Int).SetBytes(r2)
	c.ourDh = &dhKeypair{
		priv: &dhPrivateKey{k: r2x},
		pub:  &dhPublicKey{k: modExp(g3, r2x)},
	}
	// TODO: securely delete ourDh and r2

	// TODO: securely delete theirEcdh and theirDh
	c.theirEcdh = nil
	c.theirDh = nil

	return nil
}

// This method can only be called by Alice - the person receiving the Auth-I message
func (c *conversation) initializeRatchetI() error {
	// TODO: Theoretically, this can actually be done after creating the Auth-R message but before sending it

	// First part starts
	c.theirEcdh = c.im.y
	c.theirDh = c.im.b.k

	c.ourEcdh = c.arp.x
	c.ourDh = c.arp.a

	kEcdh := ed448.PointScalarMul(c.theirEcdh, c.ourEcdh.Priv.K())
	// TODO: Securely deletes ourEcdh.Priv.
	kDh := modExp(c.theirDh, c.ourDh.priv.k)
	// TODO: Securely deletes ourdh.priv.

	c.braceKey = gotrx.Kdf(usageThirdBraceKey, 32, gotrx.AppendMPI([]byte{}, kDh))
	// TODO: Securely deletes kDh
	k := gotrx.Kdf(usageSharedSecret, 64, append(gotrx.SerializePoint(kEcdh), c.braceKey...))
	// TODO: securely delete kEcdh and c.braceKey
	c.ssid = gotrx.Kdf(usageSSID, 8, k)
	// First part ends

	// Second part starts
	c.ratchetID = 0
	c.ratchetJ = 0
	c.ratchetK = 0
	c.ratchetPN = 0
	c.rootKey = k

	var r1 [57]byte
	gotrx.Kdfx(usageECDHFirstEphemeral, r1[:], k)
	theirEcdh2 := gotrx.DeriveKeypair(r1)
	c.theirEcdh = theirEcdh2.Pub.K()
	// TODO: securely delete r1 and secret in theirEcdh2

	r2 := gotrx.Kdf(usageDHFirstEphemeral, 80, k)
	r2x := new(big.Int).SetBytes(r2)

	c.theirDh = modExp(g3, r2x)
	// TODO: securely delete r2 and r2x

	// Second part ends

	c.shouldRatchet = true
	return nil
}

func (c *conversation) maybeRatchetSender() {
	if !c.shouldRatchet {
		return
	}

	c.ratchetJ = 0

	// TODO: we should delete the old ourEcdh safely
	c.ourEcdh = gotrx.GenerateKeypair(c)
	kEcdh := ed448.PointScalarMul(c.theirEcdh, c.ourEcdh.Priv.K())

	if c.ratchetID%3 == 0 {
		// TODO: we shouldn't ignore this error
		c.ourDh, _ = generateDHKeypair(c)
		kDh := modExp(c.theirDh, c.ourDh.priv.k)
		c.braceKey = gotrx.Kdf(usageThirdBraceKey, 32, gotrx.AppendMPI([]byte{}, kDh))
		// TODO: here we can safely delete kDh
	} else {
		// TODO: safely delete the old brace key here
		c.braceKey = gotrx.Kdf(usageBraceKey, 32, c.braceKey)
	}

	k := gotrx.Kdf(usageSharedSecret, 64, append(gotrx.SerializePoint(kEcdh), c.braceKey...))
	// TODO: securely delete kEcdh

	c.rootKey, c.sendingChainKey = c.deriveRatchetKeys(c.rootKey, k)
	// TODO: securely delete previous root key and K
	c.ratchetID++
	// TODO: reveal and forget previous MAC keys

	c.shouldRatchet = false
}

func (c *conversation) ratchetReceiver() {
	kEcdh := ed448.PointScalarMul(c.theirEcdh, c.ourEcdh.Priv.K())
	// TODO: securely delete ourEcdh here

	if c.ratchetID%3 == 0 {
		// TODO: we shouldn't ignore this error
		//		c.ourDh, _ = generateDHKeypair(c)
		kDh := modExp(c.theirDh, c.ourDh.priv.k)
		c.braceKey = gotrx.Kdf(usageThirdBraceKey, 32, gotrx.AppendMPI([]byte{}, kDh))
		// TODO: here we can safely delete kDh
	} else {
		// TODO: safely delete the old brace key here
		c.braceKey = gotrx.Kdf(usageBraceKey, 32, c.braceKey)
	}

	c.ratchetPN = c.ratchetJ
	c.ratchetJ = 0
	c.ratchetK = 0

	k := gotrx.Kdf(usageSharedSecret, 64, append(gotrx.SerializePoint(kEcdh), c.braceKey...))
	// TODO: securely delete kEcdh

	c.rootKey, c.receivingChainKey = c.deriveRatchetKeys(c.rootKey, k)
	// TODO: securely delete previous receiving chain key and previous rootkey

	c.ratchetID++
	c.shouldRatchet = false
}

func (c *conversation) deriveRatchetKeys(previousRootKey []byte, k []byte) ([]byte, []byte) {
	dt := append(previousRootKey, k...)
	rk := gotrx.Kdf(usageRootKey, 64, dt)
	ck := gotrx.Kdf(usageChainKey, 64, dt)
	return rk, ck
}

func (c *conversation) deriveCurrentMK(ck []byte) ([]byte, []byte) {
	mkenc := gotrx.Kdf(usageMessageKey, 32, ck)
	mkmac := gotrx.Kdf(usageMACKey, 64, mkenc)
	return mkenc, mkmac
}
