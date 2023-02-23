package main

import (
	"encoding/hex"
	"github.com/edgelesssys/ego/enclave"
	"github.com/xueqianLu/trustednet/command"
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
	received := make([]byte, 1024)

	// step 1. auth verify
	d := command.NewAuthCommand([]byte{})
	_, err = conn.Write(d)
	if err != nil {
		log.Fatal("write data failed", err)
	}
	length, err := conn.Read(received)
	if err != nil {
		log.Fatal("read data failed", err)
	}
	log.Println("got auth data:", hex.EncodeToString(received[:length]))

	report, err := enclave.VerifyRemoteReport(received[:length])
	if err != nil {
		log.Fatal("verify remote report failed", err)
	}

	reportdata, err := enclave.GetRemoteReport(report.Data)
	if err != nil {
		log.Fatal("generate remote report failed", err)
	}

	verify := command.NewVerifyCommand(reportdata)
	_, err = conn.Write(verify)
	if err != nil {
		log.Fatal("write data failed", err)
	}
	length, err = conn.Read(received)
	if err != nil {
		log.Fatal("read data failed", err)
	}
	log.Println("got verify result:", string(received[:length]))
	time.Sleep(time.Second)
	log.Println("goto disconnect")

	conn.Write(command.NewDisconnectCommand())
	time.Sleep(time.Second)
	conn.Close()
}
