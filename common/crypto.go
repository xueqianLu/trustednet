package common

import (
	"crypto/rand"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/log"
)

func HexToPrivkey(str string) (*ecies.PrivateKey, error) {
	pk, err := crypto.HexToECDSA(str)
	if err != nil {
		return nil, err
	}
	eck := ecies.ImportECDSA(pk)
	return eck, nil
}

// GenerateKey generate private key and public key
func GenerateKey() *ecies.PrivateKey {
	pk, _ := ecies.GenerateKey(rand.Reader, ecies.DefaultCurve, nil)
	return pk
}

// Encrypt public key encrypt
func Encrypt(pt []byte, pub *ecies.PublicKey) ([]byte, error) {
	return ecies.Encrypt(rand.Reader, pub, pt, nil, nil)
}

// Decrypt private key decrypt
func Decrypt(ct []byte, privk *ecies.PrivateKey) ([]byte, error) {
	return privk.Decrypt(ct, nil, nil)
}

// EnclaveEncrypt encrypt with sgx product key.
func EnclaveEncrypt(pt []byte) ([]byte, error) {
	k, _, err := enclave.GetProductSealKey()
	if err != nil {
		return nil, err
	}
	log.Debug("encrypt with key:", common.Bytes2Hex(k))
	return ecrypto.Encrypt(pt, k, nil)
}

// EnclaveDecrypt decrypt with sgx product key.
func EnclaveDecrypt(ct []byte) ([]byte, error) {
	k, _, err := enclave.GetProductSealKey()
	if err != nil {
		return nil, err
	}
	log.Debug("decrypt with key:", common.Bytes2Hex(k))
	return ecrypto.Decrypt(ct, k, nil)
}
