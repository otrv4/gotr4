package gotra

import (
	"math/big"

	"github.com/coyim/gotrax"
)

type dhKeypair struct {
	pub  *dhPublicKey
	priv *dhPrivateKey
}

type dhPublicKey struct {
	k *big.Int
}

type dhPrivateKey struct {
	k *big.Int
}

var (
	p  *big.Int // prime field, defined in RFC3526 as Diffie-Hellman Group 5
	g3 *big.Int // group generator
)

func init() {
	p, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"+
			"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"+
			"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"+
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"+
			"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)
	g3 = big.NewInt(2)
}

func modExp(g, x *big.Int) *big.Int {
	return new(big.Int).Exp(g, x, p)
}

func randMPI(r gotrax.WithRandom, b []byte) (*big.Int, error) {
	if err := gotrax.RandomInto(r, b); err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}

func randSizedMPI(r gotrax.WithRandom, size int) (*big.Int, error) {
	return randMPI(r, make([]byte, size))
}

func generateDHKeypair(r gotrax.WithRandom) (*dhKeypair, error) {
	k, e := randSizedMPI(r, 80)
	if e != nil {
		return nil, e
	}

	kp := modExp(g3, k)

	return &dhKeypair{
		priv: &dhPrivateKey{k: k},
		pub:  &dhPublicKey{k: kp},
	}, nil
}
