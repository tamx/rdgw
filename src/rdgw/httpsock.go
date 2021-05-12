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
		// fmt.Println(line)
		length, _ := strconv.ParseInt(line, 16, 32)
		if length < 0 {
			return 0, errors.New("it's strange.")
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

		buf := make([]byte, 1)
		sock.IN.Read(buf)           // 0x0d
		_, err := sock.IN.Read(buf) // 0x0a
		if err != nil {
			return 0, err
		}
	}
	if len(data) <= len(p) {
		for i := 0; i < len(data); i++ {
			p[i] = data[i]
		}
		sock.Buffer = nil
		return len(data), nil
	}
	for i := 0; i < len(p); i++ {
		p[i] = data[i]
	}
	sock.Buffer = data[len(p):]
	return len(p), nil
}

func (sock *httpsock) Write(b []byte) (int, error) {
	return sock.OUT.Write(b)
}

func (sock *httpsock) Close() error {
	if sock.OUT != nil {
		sock.OUT.Close()
	}
	return sock.IN.Close()
}
