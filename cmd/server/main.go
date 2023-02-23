package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"github.com/edgelesssys/ego/enclave"
	"github.com/ethereum/go-ethereum/crypto"
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

func handleRequest(conn net.Conn) {
	// incoming request
	buffer := make([]byte, 1024)
	continues := true
	verifydata := make([]byte, 0)
	defer conn.Close()

	for continues {
		length, err := conn.Read(buffer)
		if err != nil {
			log.Fatal(err)
		}

		payload := common.CopyBytes(buffer[:length])
		switch payload[0] {
		case command.AUTH_COMMAND:
			pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			keydata := crypto.FromECDSA(pk)
			reportdata, err := enclave.GetRemoteReport(keydata)
			if err != nil {
				log.Fatal("get remote report failed", err)
			}
			log.Println("send report:", hex.EncodeToString(reportdata))
			conn.Write(reportdata)
			verifydata = common.CopyBytes(keydata)
		case command.VERIFY_COMMAND:
			reportdata := payload[1:]
			report, err := enclave.VerifyRemoteReport(reportdata)
			if err != nil {
				log.Fatal("verify remote report failed", err)
			}
			if bytes.Compare(report.Data, verifydata) != 0 {
				log.Println("verify failed")
				conn.Write([]byte("verify failed"))
			} else {
				conn.Write([]byte("verify passed"))
				log.Println("client verify passed")
			}
		//case command.GETKEY_COMMAND:
		//	data := payload[1:]
		//
		//	// write data to response
		//	time := time.Now().Format(time.ANSIC)
		//	responseStr := fmt.Sprintf("Your message is: %v. Received time: %v", string(buffer[:]), time)
		//	conn.Write([]byte(responseStr))

		//
		case command.DISCONNECT_COMMAND:
			log.Println("client disconnect")
			continues = false
		}
	}
	log.Println("client handle exit")
}
