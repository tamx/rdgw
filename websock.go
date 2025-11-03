package main

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type websock struct {
	// Conn   io.ReadWriteCloser
	Conn         *websocket.Conn
	Buffer       []byte
	lastResponse time.Time
}

func (sock *websock) keepAlive(timeout time.Duration) {
	sock.lastResponse = time.Now()
	sock.Conn.SetPongHandler(func(msg string) error {
		sock.lastResponse = time.Now()
		return nil
	})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				// fmt.Printf("%v", r)
				// err = status.Error(codes.Internal, "unexpected error")
				println("catch panic.")
				sock.Conn.Close()
			}
		}()
		for {
			err := sock.Conn.WriteMessage(websocket.PingMessage, []byte("keepalive"))
			if err != nil {
				return
			}
			time.Sleep(timeout / 3)
			if time.Since(sock.lastResponse) > timeout {
				println("time out.")
				sock.Conn.Close()
				return
			}
		}
	}()
}

func newWebSock(w http.ResponseWriter, r *http.Request) *websock {
	var upgrader = websocket.Upgrader{} // use default options
	r.Method = "GET"
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		println("upgrade error")
		println(err.Error())
		return nil
	}
	println("Upgraded.")
	sock := websock{
		Conn:         c,
		lastResponse: time.Now(),
	}
	sock.keepAlive(time.Duration(60) * time.Second)
	return &sock
}

func (sock *websock) Read(p []byte) (int, error) {
	data := sock.Buffer
	if data == nil {
		_, message, err := sock.Conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		// log.Printf("recv: %s", message)
		// println("Read:")
		sock.lastResponse = time.Now()
		data = message
		// print(data)
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

func (sock *websock) Write(b []byte) (int, error) {
	// println("Write:")
	// print(b)
	err := sock.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (sock *websock) Close() error {
	return sock.Conn.Close()
}
