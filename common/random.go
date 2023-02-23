package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ethereum/go-ethereum/crypto"
)

func GenRandom() []byte {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return crypto.FromECDSA(pk)
}
