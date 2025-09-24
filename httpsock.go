package main

import (
	"errors"
	"net"
	"strconv"
)

type httpsock struct {
	IN     *net.TCPConn
	OUT    *net.TCPConn
	Buffer []byte
}

func newHttpSock(conn *net.TCPConn) *httpsock {
	sock := httpsock{
		IN: conn,
	}
	return &sock
}

func (sock *httpsock) Read(p []byte) (int, error) {
	data := sock.Buffer
	if data == nil {
		line, _ := ReadLine(sock.IN) // skip until "\r\n"
		println(line)
		length, _ := strconv.ParseInt(line, 16, 32)
		if length < 0 {
			return 0, errors.New("strange length")
		}
		buffer := make([]byte, length)
		for offset := int64(0); offset < length; {
			n, err := sock.IN.Read(buffer[offset:])
			if err != nil {
				return 0, err
			}
			offset += int64(n)
		}
		data = buffer[:length]

		line, err := ReadLine(sock.IN)
		if err != nil {
			return 0, err
		}
		println(line)
	}
	if len(data) <= len(p) {
		copy(p, data)
		sock.Buffer = nil
		return len(data), nil
	}
	for i := range p {
		p[i] = data[i]
	}
	sock.Buffer = data[len(p):]
	return len(p), nil
}

func (sock *httpsock) Write(b []byte) (int, error) {
	// cLength := fmt.Sprintf("%x", len(b))
	// fmt.Println(cLength)
	// sock.IN.Write([]byte(cLength + "\n"))
	// print(b)
	return sock.IN.Write(b)
}

func (sock *httpsock) Close() error {
	if sock.OUT != nil {
		sock.OUT.Close()
	}
	return sock.IN.Close()
}
