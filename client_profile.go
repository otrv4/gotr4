package gotr4

import (
	"time"

	"github.com/otrv4/gotrx"
)

func (c *conversation) getKeypair() *gotrx.Keypair {
	// TODO: this should be implemented correctly later
	if c.longTerm == nil {
		c.longTerm = gotrx.GenerateKeypair(c)
	}
	return c.longTerm
}

func (c *conversation) getClientProfileExpiration() time.Time {
	// TODO: obviously implement this correctly
	return time.Now().Add(time.Duration(2 * 7 * 24 * time.Hour))
}

func (c *conversation) getValidClientProfile() *gotrx.ClientProfile {
	// TODO: implement correctly
	if c.currentClientProfile == nil {
		// TODO: this is missing the forging key
		kp := c.getKeypair()
		cp := &gotrx.ClientProfile{
			InstanceTag:           c.getInstanceTag(),
			PublicKey:             kp.Pub,
			Versions:              c.getVersions(),
			Expiration:            c.getClientProfileExpiration(),
			DsaKey:                nil,
			TransitionalSignature: nil,
		}
		cp.Sig = gotrx.CreateEddsaSignature(cp.GenerateSignature(kp))
		c.currentClientProfile = cp
	}
	return c.currentClientProfile
}
