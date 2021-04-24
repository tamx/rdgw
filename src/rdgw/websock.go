package main

import (
	"io"
	"io/ioutil"
	"log"
	"net"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type websock struct {
	Conn   io.ReadWriter
	Buffer []byte
}

type headerReader struct {
	Reader io.ReadWriter
	Header []byte
}

func newHeaderReader(reader io.ReadWriter,
	header string) *headerReader {
	// fmt.Println(header)
	r := headerReader{
		Reader: reader,
		Header: []byte(header),
	}
	return &r
}

func (r *headerReader) Read(p []byte) (int, error) {
	data := r.Header
	if data == nil {
		return r.Reader.Read(p)
	}
	if len(data) <= len(p) {
		for i := 0; i < len(data); i++ {
			p[i] = data[i]
		}
		r.Header = nil
		return len(data), nil
	}
	for i := 0; i < len(p); i++ {
		p[i] = data[i]
	}
	r.Header = data[len(p):]
	return len(p), nil
}

func (r *headerReader) Write(b []byte) (int, error) {
	return r.Reader.Write(b)
}

func newWebSock(conn *net.TCPConn, header string) *websock {
	hr := newHeaderReader(conn, header)
	_, err := ws.Upgrade(hr)
	if err != nil {
		log.Println("upgrade error")
		log.Println(err)
		return nil
	}
	log.Println("Upgraded.")
	sock := websock{
		Conn: hr,
	}
	return &sock
}

func (sock *websock) Read(p []byte) (int, error) {
	data := sock.Buffer
	if data == nil {
		reader := wsutil.NewReader(sock.Conn, ws.StateServerSide)
		_, err := reader.NextFrame()
		if err != nil {
			return 0, err
		}
		data, err = ioutil.ReadAll(reader)
		if err != nil {
			return 0, err
		}
		// fmt.Println("Read:")
		// print(data)
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

func (sock *websock) Write(b []byte) (int, error) {
	// fmt.Println("Write:")
	// print(b)
	if err := wsutil.WriteServerBinary(sock.Conn, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (sock *websock) Close() error {
	return nil
}
