package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type websock struct {
	// Conn   io.ReadWriteCloser
	Conn   *websocket.Conn
	Buffer []byte
}

func keepAlive(c *websocket.Conn, timeout time.Duration) {
	lastResponse := time.Now()
	c.SetPongHandler(func(msg string) error {
		lastResponse = time.Now()
		return nil
	})

	go func() {
		for {
			err := c.WriteMessage(websocket.PingMessage, []byte("keepalive"))
			if err != nil {
				return
			}
			time.Sleep(timeout / 2)
			if time.Since(lastResponse) > timeout {
				c.Close()
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
		log.Println("upgrade error")
		log.Println(err)
		return nil
	}
	log.Println("Upgraded.")
	keepAlive(c, time.Duration(10)*time.Second)
	sock := websock{
		Conn: c,
	}
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
