package main

import (
	"net"
)

type httpsock struct {
	IN  *net.TCPConn
	OUT *net.TCPConn
}

func newHttpSock(conn *net.TCPConn) *websock {
	sock := websock{
		Conn: conn,
	}
	return &sock
}

func (sock *httpsock) Read(p []byte) (int, error) {
	ReadLine(sock.IN) // skip until "\r\n"
	// // ReadLine(IN) // skip until "\r\n"
	// buf := make([]byte, 1)
	// // packet type
	// IN.Read(buf)
	// packettype := buf[0]
	// IN.Read(buf)
	// IN.Read(buf)
	// IN.Read(buf)
	// // packet length
	// IN.Read(buf)
	// length := int(buf[0])
	// IN.Read(buf)
	// length |= (int(buf[0]) << 8)
	// IN.Read(buf)
	// length |= (int(buf[0]) << 16)
	// IN.Read(buf)
	// length |= (int(buf[0]) << 24)
	// // fmt.Printf("=>Type: %d, len: %d\n", packettype, length)
	// body := make([]byte, 0)
	// for i := 8; i < length; i++ {
	// 	IN.Read(buf)
	// 	body = append(body, buf[0])
	// }
	// print(body)

	// IN.Read(buf)           // 0x0d
	// _, err := IN.Read(buf) // 0x0a
	// return packettype, body, err
	return 0, nil
}

func (sock *httpsock) Write(b []byte) (int, error) {
	return sock.OUT.Write(b)
}

func (sock *httpsock) Close() error {
	sock.IN.Close()
	return sock.OUT.Close()
}
