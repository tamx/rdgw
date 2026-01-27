package main

import (
	"errors"
	"io"
	"net/http"
	"strconv"
)

type httpsock struct {
	IN     io.ReadCloser
	OUT    io.Writer
	Ch     chan error
	Buffer []byte
}

func newHttpSock(out io.Writer, ch chan error) httpsock {
	sock := httpsock{
		OUT: out,
		Ch:  ch,
	}
	return sock
}

// not used
func (sock httpsock) ReadChunked(p []byte) (int, error) {
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

func (sock httpsock) Write(b []byte) (int, error) {
	// cLength := fmt.Sprintf("%x", len(b))
	// fmt.Println(cLength)
	// sock.IN.Write([]byte(cLength + "\n"))
	// print(b)
	size, err := sock.OUT.Write(b)
	if flusher, ok := sock.OUT.(http.Flusher); ok {
		flusher.Flush()
	}
	return size, err
}

func (sock httpsock) Close() error {
	if sock.IN != nil {
		err := sock.IN.Close()
		sock.Ch <- err
		return err
	}
	sock.Ch <- nil
	return nil
}
