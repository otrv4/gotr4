package gotra

import "github.com/coyim/gotrax"

func (k *dhPublicKey) serialize() []byte {
	return gotrax.AppendMPI([]byte{}, k.k)
}
