package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/edgelesssys/ego/enclave"
	"github.com/xueqianLu/trustednet/command"
	"github.com/xueqianLu/trustednet/common"
	"log"
	"net"
	"os"
	"time"
)

const (
	HOST = "localhost"
	PORT = "8080"
	TYPE = "tcp"
)

// generate remote report with random_a
func DoAuth(random_a []byte, conn net.Conn) {
	report, err := enclave.GetRemoteReport(random_a)
	if err != nil {
		log.Fatal("get remote report failed:", err)
	}
	d := command.NewAuthCommand(report)
	_, _ = conn.Write(d)
}

// check remote report and get random_b
func DoVerify(random_a []byte, payload []byte, conn net.Conn) ([]byte, error) {
	report, err := enclave.VerifyLocalReport(payload)
	if err != nil {
		log.Fatal("get remote report failed:", err)
	}
	if len(report.Data) != 64 {
		return nil, errors.New("invalid verify report data")
	}
	if bytes.Compare(report.Data[:32], random_a) != 0 {
		return nil, errors.New("invalid verify report data")
	}
	return report.Data[32:64], nil
}

// generate remote report with random_b and random_c
func DoGetKey(random_b []byte, random_c []byte, conn net.Conn) {
	data := append(random_b, random_c...)
	report, err := enclave.GetRemoteReport(data)
	if err != nil {
		log.Fatal("get remote report failed:", err)
	}
	d := command.NewGetKeyCommand(report)
	_, _ = conn.Write(d)
}

func DoParseKey(random_c []byte, payload []byte, conn net.Conn) ([]byte, error) {
	report, err := enclave.VerifyLocalReport(payload)
	if err != nil {
		log.Fatal("get remote report failed:", err)
	}
	if len(report.Data) != 64 {
		return nil, errors.New("invalid verify report data")
	}
	if bytes.Compare(report.Data[:32], random_c) != 0 {
		return nil, errors.New("invalid verify report data")
	}
	return report.Data[32:64], nil
}

func main() {
	tcpServer, err := net.ResolveTCPAddr(TYPE, HOST+":"+PORT)

	if err != nil {
		println("ResolveTCPAddr failed:", err.Error())
		os.Exit(1)
	}

	conn, err := net.DialTCP(TYPE, nil, tcpServer)
	if err != nil {
		println("Dial failed:", err.Error())
		os.Exit(1)
	}
	received := make([]byte, 65535)

	random_a := common.GenRandom()

	// step 1. auth
	DoAuth(random_a, conn)

	length, err := conn.Read(received)
	if err != nil {
		log.Fatal("read conn failed:", err)
	}
	// step 2. verify
	random_b, err := DoVerify(random_a, received[1:length], conn)
	if err != nil {
		log.Fatal("do verify failed:", err)
	}
	// step 3. GetKey
	random_c := common.GenRandom()
	DoGetKey(random_b, random_c, conn)

	length, err = conn.Read(received)
	if err != nil {
		log.Fatal("read data failed", err)
	}

	key, err := DoParseKey(random_c, received[1:length], conn)
	if err != nil {
		log.Fatal("do parse key failed:", err)
	}
	log.Println("succeed got secret key:", hex.EncodeToString(key))

	time.Sleep(time.Second)
	log.Println("goto disconnect")

	conn.Write(command.NewDisconnectCommand())
	time.Sleep(time.Second)
	conn.Close()
}
