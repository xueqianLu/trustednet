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
)

const (
	HOST = "0.0.0.0"
	PORT = "8080"
	TYPE = "tcp"
)

var (
	SecretKey, _ = hex.DecodeString("0448f96bb0a84fc80f5e184354ad13c027e3c544f42a68967471b0b78ef41e37")
)

func main() {
	listen, err := net.Listen(TYPE, HOST+":"+PORT)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	// close listener
	defer listen.Close()
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		go handleRequest(conn)
	}
}

func dealAuth(payload []byte, conn net.Conn) ([]byte, error) {
	report, err := enclave.VerifyRemoteReport(payload)
	if err != nil {
		return nil, err
	}
	if len(report.Data) < 32 {
		return nil, errors.New("invalid report data")
	}
	return report.Data[:32], nil
}

func sendVerify(random_a []byte, random_b []byte, conn net.Conn) error {
	data := append(random_a, random_b...)
	reportdata, err := enclave.GetRemoteReport(data)
	if err != nil {
		log.Fatal("get remote report failed", err)
	}

	cmd := command.NewVerifyCommand(reportdata)
	//log.Println("send report:", hex.EncodeToString(reportdata))
	conn.Write(cmd)
	return nil
}

func dealGetKey(random_b []byte, payload []byte, conn net.Conn) ([]byte, error) {
	report, err := enclave.VerifyRemoteReport(payload)
	if err != nil {
		return nil, err
	}
	if len(report.Data) != 64 {
		return nil, errors.New("invalid report data")
	}
	if bytes.Compare(report.Data[:32], random_b) != 0 {
		return nil, errors.New("verify random_b failed")
	}
	return report.Data[32:64], nil
}

func sendKey(random_c []byte, key []byte, conn net.Conn) {
	data := append(random_c, key...)
	reportdata, err := enclave.GetRemoteReport(data)
	if err != nil {
		log.Fatal("get remote report failed", err)
	}

	cmd := command.NewSendKeyCommand(reportdata)
	//log.Println("send report:", hex.EncodeToString(reportdata))
	conn.Write(cmd)
}

func handleRequest(conn net.Conn) {
	// incoming request
	buffer := make([]byte, 65535)
	continues := true
	random := make([]byte, 32)
	defer conn.Close()

	for continues {
		length, err := conn.Read(buffer)
		if err != nil {
			log.Fatal(err)
		}

		payload := common.CopyBytes(buffer[:length])
		switch payload[0] {
		case command.AUTH_COMMAND:
			if random_a, err := dealAuth(payload[1:length], conn); err != nil {
				log.Println("auth remote report failed")
				return
			} else {
				random_b := common.GenRandom()
				// save random_b to verify when getkey
				copy(random, random_b)

				sendVerify(random_a, random_b, conn)
			}
		case command.GETKEY_COMMAND:
			reportdata := payload[1:length]
			random_c, err := dealGetKey(random, reportdata, conn)
			if err != nil {
				log.Fatal("verify get key failed:", err)
			}
			sendKey(random_c, SecretKey, conn)
		case command.DISCONNECT_COMMAND:
			log.Println("client disconnect")
			continues = false
		}
	}
	log.Println("client handle exit")
}
