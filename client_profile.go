package gotra

import (
	"time"

	"github.com/coyim/gotrax"
)

func (c *conversation) getKeypair() *gotrax.Keypair {
	// TODO: this should be implemented correctly later
	if c.longTerm == nil {
		c.longTerm = gotrax.GenerateKeypair(c)
	}
	return c.longTerm
}

func (c *conversation) getClientProfileExpiration() time.Time {
	// TODO: obviously implement this correctly
	return time.Now().Add(time.Duration(2 * 7 * 24 * time.Hour))
}

func (c *conversation) getValidClientProfile() *gotrax.ClientProfile {
	// TODO: implement correctly
	if c.currentClientProfile == nil {
		kp := c.getKeypair()
		cp := &gotrax.ClientProfile{
			InstanceTag:           c.getInstanceTag(),
			PublicKey:             kp.Pub,
			Versions:              c.getVersions(),
			Expiration:            c.getClientProfileExpiration(),
			DsaKey:                nil,
			TransitionalSignature: nil,
		}
		cp.Sig = gotrax.CreateEddsaSignature(cp.GenerateSignature(kp))
		c.currentClientProfile = cp
	}
	return c.currentClientProfile
}
