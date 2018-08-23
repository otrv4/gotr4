package gotra

import (
	"math/big"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

// This method can only be called by Bob - the person receiving the Auth-R message
func (c *conversation) initializeRatchetR() error {
	c.their_ecdh = c.ar.x
	c.their_dh = c.ar.a.k

	c.our_ecdh = c.imp.y
	c.our_dh = c.imp.b

	k_ecdh := ed448.PointScalarMul(c.their_ecdh, c.our_ecdh.Priv.K())
	// TODO: Securely deletes our_ecdh.Priv.
	k_dh := modExp(c.their_dh, c.our_dh.priv.k)
	// TODO: Securely deletes our_dh.priv.

	c.brace_key = gotrax.Kdf(usageThirdBraceKey, 32, gotrax.AppendMPI([]byte{}, k_dh))
	// TODO: Securely deletes k_dh
	k := gotrax.Kdf(usageSharedSecret, 64, append(gotrax.SerializePoint(k_ecdh), c.brace_key...))
	// TODO: securely delete k_ecdh and c.brace_key
	c.ssid = gotrax.Kdf(usageSSID, 8, k)

	c.ratchetId = 0
	c.ratchetJ = 0
	c.ratchetK = 0
	c.ratchetPN = 0
	c.rootKey = k

	var r1 [57]byte
	gotrax.Kdfx(usageECDHFirstEphemeral, r1[:], k)
	c.our_ecdh = gotrax.DeriveKeypair(r1)
	// TODO: securely delete r1 and old our_ecdh

	r2 := gotrax.Kdf(usageDHFirstEphemeral, 80, k)
	r2x := new(big.Int).SetBytes(r2)
	c.our_dh = &dhKeypair{
		priv: &dhPrivateKey{k: r2x},
		pub:  &dhPublicKey{k: modExp(g3, r2x)},
	}
	// TODO: securely delete our_dh and r2

	// TODO: securely delete their_ecdh and their_dh
	c.their_ecdh = nil
	c.their_dh = nil

	return nil
}

// This method can only be called by Alice - the person receiving the Auth-I message
func (c *conversation) initializeRatchetI() error {
	// TODO: Theoretically, this can actually be done after creating the Auth-R message but before sending it

	// First part starts
	c.their_ecdh = c.im.y
	c.their_dh = c.im.b.k

	c.our_ecdh = c.arp.x
	c.our_dh = c.arp.a

	k_ecdh := ed448.PointScalarMul(c.their_ecdh, c.our_ecdh.Priv.K())
	// TODO: Securely deletes our_ecdh.Priv.
	k_dh := modExp(c.their_dh, c.our_dh.priv.k)
	// TODO: Securely deletes our_dh.priv.

	c.brace_key = gotrax.Kdf(usageThirdBraceKey, 32, gotrax.AppendMPI([]byte{}, k_dh))
	// TODO: Securely deletes k_dh
	k := gotrax.Kdf(usageSharedSecret, 64, append(gotrax.SerializePoint(k_ecdh), c.brace_key...))
	// TODO: securely delete k_ecdh and c.brace_key
	c.ssid = gotrax.Kdf(usageSSID, 8, k)
	// First part ends

	// Second part starts
	c.ratchetId = 0
	c.ratchetJ = 0
	c.ratchetK = 0
	c.ratchetPN = 0
	c.rootKey = k

	var r1 [57]byte
	gotrax.Kdfx(usageECDHFirstEphemeral, r1[:], k)
	their_ecdh2 := gotrax.DeriveKeypair(r1)
	c.their_ecdh = their_ecdh2.Pub.K()
	// TODO: securely delete r1 and secret in their_ecdh2

	r2 := gotrax.Kdf(usageDHFirstEphemeral, 80, k)
	r2x := new(big.Int).SetBytes(r2)

	c.their_dh = modExp(g3, r2x)
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

	// TODO: we should delete the old our_ecdh safely
	c.our_ecdh = gotrax.GenerateKeypair(c)
	k_ecdh := ed448.PointScalarMul(c.their_ecdh, c.our_ecdh.Priv.K())

	if c.ratchetId%3 == 0 {
		// TODO: we shouldn't ignore this error
		c.our_dh, _ = generateDHKeypair(c)
		k_dh := modExp(c.their_dh, c.our_dh.priv.k)
		c.brace_key = gotrax.Kdf(usageThirdBraceKey, 32, gotrax.AppendMPI([]byte{}, k_dh))
		// TODO: here we can safely delete k_dh
	} else {
		// TODO: safely delete the old brace key here
		c.brace_key = gotrax.Kdf(usageBraceKey, 32, c.brace_key)
	}

	k := gotrax.Kdf(usageSharedSecret, 64, append(gotrax.SerializePoint(k_ecdh), c.brace_key...))
	// TODO: securely delete k_ecdh

	c.rootKey, c.sendingChainKey = c.deriveRatchetKeys(c.rootKey, k)
	// TODO: securely delete previous root key and K
	c.ratchetId++
	// TODO: reveal and forget previous MAC keys

	c.shouldRatchet = false
}

func (c *conversation) ratchetReceiver() {
	k_ecdh := ed448.PointScalarMul(c.their_ecdh, c.our_ecdh.Priv.K())
	// TODO: securely delete our_ecdh here

	if c.ratchetId%3 == 0 {
		// TODO: we shouldn't ignore this error
		//		c.our_dh, _ = generateDHKeypair(c)
		k_dh := modExp(c.their_dh, c.our_dh.priv.k)
		c.brace_key = gotrax.Kdf(usageThirdBraceKey, 32, gotrax.AppendMPI([]byte{}, k_dh))
		// TODO: here we can safely delete k_dh
	} else {
		// TODO: safely delete the old brace key here
		c.brace_key = gotrax.Kdf(usageBraceKey, 32, c.brace_key)
	}

	c.ratchetPN = c.ratchetJ
	c.ratchetJ = 0
	c.ratchetK = 0

	k := gotrax.Kdf(usageSharedSecret, 64, append(gotrax.SerializePoint(k_ecdh), c.brace_key...))
	// TODO: securely delete k_ecdh

	c.rootKey, c.receivingChainKey = c.deriveRatchetKeys(c.rootKey, k)
	// TODO: securely delete previous receiving chain key and previous rootkey

	c.ratchetId++
	c.shouldRatchet = false
}

func (c *conversation) deriveRatchetKeys(previousRootKey []byte, k []byte) ([]byte, []byte) {
	dt := append(previousRootKey, k...)
	rk := gotrax.Kdf(usageRootKey, 64, dt)
	ck := gotrax.Kdf(usageChainKey, 64, dt)
	return rk, ck
}

func (c *conversation) deriveCurrentMK(ck []byte) ([]byte, []byte) {
	mkenc := gotrax.Kdf(usageMessageKey, 32, ck)
	mkmac := gotrax.Kdf(usageMACKey, 64, mkenc)
	return mkenc, mkmac
}
