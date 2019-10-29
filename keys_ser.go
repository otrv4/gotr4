package gotr4

import "github.com/otrv4/gotrx"

func (k *dhPublicKey) serialize() []byte {
	return gotrx.AppendMPI([]byte{}, k.k)
}
