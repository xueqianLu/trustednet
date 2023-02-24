package main

import (
	"encoding/json"
	ethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	log "github.com/sirupsen/logrus"
	"github.com/xueqianLu/trustednet/common"

	"os"
)

type SecretDb struct {
	PK    string `json:"priv-key"`
	privk *ecies.PrivateKey
}

func (s SecretDb) PrivateKey() *ecies.PrivateKey {
	return s.privk
}

func (s SecretDb) PublicKey() *ecies.PublicKey {
	return &s.privk.PublicKey
}

func CreateWithHexkey(hexk string) (*SecretDb, error) {
	privk, err := common.HexToPrivkey(hexk)
	if err != nil {
		return nil, err
	}
	return &SecretDb{
		PK:    hexk,
		privk: privk,
	}, nil
}

func GenerateDB(path string) *SecretDb {
	pk := common.GenerateKey()
	hexk := ethcmn.Bytes2Hex(crypto.FromECDSA(pk.ExportECDSA()))
	db := &SecretDb{
		PK:    hexk,
		privk: pk,
	}
	err := SaveDb(db, path)
	if err != nil {
		log.Fatal("save db failed", "err", err)
		return nil
	}
	log.WithField("pk", hexk).Info("generate private key")
	return db
}

func LoadDb(path string) *SecretDb {
	// read file content
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		log.WithField("error", err).Error("loadDB read file failed")
		return nil
	}
	// decrypt
	pt, err := common.EnclaveDecrypt(data)
	if err != nil {
		log.WithField("error", err).Error("loadDB decrypt failed")
		return nil
	}

	var sdb = new(SecretDb)

	// json unmarshal
	if err = json.Unmarshal(pt, sdb); err != nil {
		log.WithField("error", err).Error("loadDB json unmarshal failed")
		return nil
	}
	sdb.privk, _ = common.HexToPrivkey(sdb.PK)
	log.WithField("pk", sdb.PK).Info("load private key")
	return sdb
}

func SaveDb(sdb *SecretDb, path string) error {
	// json marshal
	data, err := json.Marshal(sdb)
	if err != nil {
		return err
	}
	// encrypt
	ct, err := common.EnclaveEncrypt(data)
	if err != nil {
		return err
	}
	// write to file
	err = os.WriteFile(path, ct, os.FileMode(666))
	if err != nil {
		return err
	}
	return nil
}
