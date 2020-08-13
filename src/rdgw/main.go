package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	// "github.com/ssgelm/golang-github-thomsonreuterseikon-go-ntlm/ntlm"
	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
	digest "github.com/tamx/golang-digest"
)

func checkHandler(username string) string {
	if username != USERNAME {
		return ""
	}
	return PASSWORD
}

func print(bs []byte) {
	count := 0
	strs := ""
	for _, n := range bs {
		fmt.Printf("%02x ", n) // prints 1111111111111101
		if n >= 0x20 && n < 0x7f {
			strs += string(n)
		} else {
			strs += "."
		}
		count++
		if count%16 == 0 {
			fmt.Printf("%s\n", strs)
			strs = ""
		} else if count%8 == 0 {
			fmt.Printf(" ")
			strs += " "
		}
	}
	for count := len(bs); count%16 != 0; count++ {
		fmt.Print("   ")
		if count%8 == 0 {
			fmt.Printf(" ")
		}
	}
	fmt.Printf("%s\n", strs)
}

func createRandom(size int) []byte {
	rand.Seed(time.Now().UnixNano())
	buf := make([]byte, 0)
	for i := 0; i < size; i++ {
		buf = append(buf, byte(rand.Int()%256))
	}
	return buf
}

// ReadLine ...
func ReadLine(conn *net.TCPConn) (string, error) {
	buf := make([]byte, 1)
	line := make([]byte, 0)
	var old byte
	for {
		size, err := conn.Read(buf)
		if err != nil {
			return "", err
		}
		if size == 0 {
			continue
		}
		// fmt.Printf("%c", buf[0])
		if old == 0x0d && buf[0] == 0x0a {
			return string(line), nil
		}
		if old != 0x00 {
			line = append(line, old)
		}
		old = buf[0]
	}
}

func responseUnauth(conn *net.TCPConn, chaMsg string) {
	conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n"))
	conn.Write([]byte("Server: Microsoft-HTTPAPI/2.0\r\n"))
	if chaMsg != "" {
		conn.Write([]byte("WWW-Authenticate: " + chaMsg + "\r\n"))
	}
	conn.Write([]byte("WWW-Authenticate: " +
		"Digest realm=\"secret\", nonce=\"12345678901234567890123456789012\", algorithm=MD5, qop=auth\r\n"))
	conn.Write([]byte("WWW-Authenticate: Basic realm=\"SECRET AREA\"\r\n"))
	conn.Write([]byte("Content-Length: 0\r\n"))
	conn.Write([]byte("\r\n"))
}

func authNtlm2(conn *net.TCPConn, session2 ntlm.ServerSession, auth, ntlmHeader string) bool {
	auth = auth[strings.Index(auth, ntlmHeader)+len(ntlmHeader)+1:]
	// fmt.Println("Auth: " + auth)
	data, _ := base64.StdEncoding.DecodeString(auth)
	am, err := ntlm.ParseAuthenticateMessage(data, 2)
	if err != nil {
		log.Println(err)
		session2.ProcessNegotiateMessage(nil)
		challenge, _ := session2.GenerateChallengeMessage()
		chaMsg := base64.StdEncoding.EncodeToString(challenge.Bytes())
		// fmt.Println("Challenge: " + chaMsg)
		responseUnauth(conn, ntlmHeader+" "+chaMsg)
		return false
	}
	username := am.UserName.String()
	fmt.Println("User: " + username)
	password := checkHandler(username)
	session2.SetUserInfo(username, password, "")
	err = session2.ProcessAuthenticateMessage(am)
	if err != nil {
		log.Println(err)
		responseUnauth(conn, "")
		conn.Close()
		return false
	}
	return true
}

func authNtlm(conn *net.TCPConn, rdgOut bool) bool {
	websocket := false
	session2, _ := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
	auth := ""
	head, _ := ReadLine(conn)
	for {
		// fmt.Println("=>" + strconv.Itoa(phase))
		line, err := ReadLine(conn)
		if err != nil {
			log.Println(err)
			return false
		}
		fmt.Printf("%s\n", line)
		if strings.HasPrefix(strings.ToLower(line), "authorization:") {
			auth = line
		} else if strings.HasPrefix(strings.ToLower(line), "upgrade:") {
			websocket = true
		} else if line == "" {
			if auth == "" {
			} else if strings.Index(auth, "NTLM") >= 0 {
				if authNtlm2(conn, session2, auth, "NTLM") {
					break
				}
			} else if strings.Index(auth, "Negotiate") >= 0 {
				if authNtlm2(conn, session2, auth, "Negotiate") {
					break
				}
			} else if strings.Index(auth, "Digest") >= 0 {
				index := strings.Index(auth, "Digest ")
				auth = auth[index:]
				index = strings.Index(head, " ")
				method := head[:index]
				if digest.CheckAuth(auth, method, checkHandler) {
					break
				}
			} else if strings.Index(auth, "Basic") >= 0 {
				index := strings.Index(auth, "Basic ")
				auth = auth[index:]
				auth = auth[6:]
				checkStr := USERNAME + ":" + checkHandler(USERNAME)
				checkByte := []byte(checkStr)
				digest := base64.StdEncoding.EncodeToString(checkByte)
				if auth == digest {
					break
				}
			}
			responseUnauth(conn, "")
		}
	}

	conn.Write([]byte("HTTP/1.1 200 OK\r\n"))
	conn.Write([]byte("Server: Microsoft-HTTPAPI/2.0\r\n"))
	if websocket {
		conn.Write([]byte("\r\n"))
	} else {
		conn.Write([]byte("Content-Length: 0\r\n"))
		conn.Write([]byte("\r\n"))
	}
	if rdgOut {
		conn.Write([]byte{0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd})
	}

	for {
		line, err := ReadLine(conn)
		if err != nil {
			log.Println(err)
			return false
		}
		// fmt.Printf("%s\n", line)
		if line == "" {
			break
		}
	}
	return true
}

// ReadHTTPPacket ...
func ReadHTTPPacket(IN *net.TCPConn) (byte, []byte, error) {
	ReadLine(IN) // skip until "\r\n"
	buf := make([]byte, 1)
	// packet type
	IN.Read(buf)
	packettype := buf[0]
	IN.Read(buf)
	IN.Read(buf)
	IN.Read(buf)
	// packet length
	IN.Read(buf)
	length := int(buf[0])
	IN.Read(buf)
	length |= (int(buf[0]) << 8)
	IN.Read(buf)
	length |= (int(buf[0]) << 16)
	IN.Read(buf)
	length |= (int(buf[0]) << 24)
	// fmt.Printf("=>Type: %d, len: %d\n", packettype, length)
	body := make([]byte, 0)
	for i := 8; i < length; i++ {
		IN.Read(buf)
		body = append(body, buf[0])
	}
	// print(body)
	IN.Read(buf)           // 0x0d
	_, err := IN.Read(buf) // 0x0a
	return packettype, body, err
}

// WriteHTTPPacket ...
func WriteHTTPPacket(OUT *net.TCPConn, packettype int, body []byte) error {
	packet := make([]byte, 0)
	packet = append(packet, byte(packettype))
	packet = append(packet, 0)
	packet = append(packet, 0)
	packet = append(packet, 0)
	length := len(body) + 8
	packet = append(packet, byte(0xff&length))
	packet = append(packet, byte(0xff&(length>>8)))
	packet = append(packet, byte(0xff&(length>>16)))
	packet = append(packet, byte(0xff&(length>>24)))
	packet = append(packet, body...)
	// fmt.Printf("<=Type: %d, len: %d\n", packettype, len(packet))
	// print(packet)
	_, err := OUT.Write(packet)
	return err
}

func handle(IN, OUT *net.TCPConn) error {
	defer IN.Close()
	defer OUT.Close()

	ptype, body, err := ReadHTTPPacket(IN)
	if err != nil {
		return err
	}
	response := make([]byte, 0)
	response = append(response, 0)
	response = append(response, 0)
	response = append(response, 0)
	response = append(response, 0)
	response = append(response, 1)
	response = append(response, 0)
	response = append(response, 0)
	response = append(response, 0)
	response = append(response, 0)
	response = append(response, 0)
	err = WriteHTTPPacket(OUT, 0x2, response)
	if err != nil {
		return err
	}
	ptype, body, err = ReadHTTPPacket(IN)
	if err != nil {
		return err
	}

	// TUNNEL RESPONSE
	response = make([]byte, 0)
	// server version
	response = append(response, []byte{0, 0}...)
	// status code
	response = append(response, []byte{0, 0, 0, 0}...)
	// fields present
	// 1: tunnel id, 2: caps, 4: nonce & server cert
	response = append(response, []byte{3, 0}...)
	// reserved
	response = append(response, []byte{0, 0}...)
	// tunnel ID
	response = append(response, []byte{0x0a, 0, 0, 0}...)
	// caps flag
	response = append(response, []byte{0x3f, 0, 0, 0}...)
	// // nonce (20bytes)
	// response = append(response, createRandom(16)...)
	// // server cert
	// cert := readCert()
	// response = append(response, byte(0xff&len(cert)))
	// response = append(response, byte(0xff&(len(cert)>>8)))
	// response = append(response, cert...)
	err = WriteHTTPPacket(OUT, 0x5, response)
	if err != nil {
		return err
	}
	ptype, body, err = ReadHTTPPacket(IN)
	if err != nil {
		return err
	}

	// TUNNEL AUTH RESPONSE
	response = make([]byte, 0)
	// error code (4byte)
	response = append(response, []byte{0, 0, 0, 0}...)
	// flag (2byte)
	response = append(response, []byte{3, 0}...)
	// reserved (2byte)
	response = append(response, []byte{0, 0}...)
	// redir flag (2byte)
	response = append(response, []byte{0, 0, 0, 0x80}...)
	// idle timeout (4byte)
	response = append(response, []byte{0, 0, 0, 0}...)
	// // HTTP blob len
	// response = append(response, 0)
	// response = append(response, 0)
	err = WriteHTTPPacket(OUT, 0x7, response)
	if err != nil {
		return err
	}

	for {
		ptype, body, err = ReadHTTPPacket(IN)
		if err != nil {
			return err
		}
		if ptype != 0x8 {
			return nil
		}
		server := make([]byte, 0)
		for i := 8; i < len(body)-2; i += 2 {
			server = append(server, body[i])
		}
		port := (0xff & int(body[2]))
		port |= (0xff & int(body[3])) << 8
		fmt.Println(string(server) + ":" + strconv.Itoa(port))
		if port != 3389 {
			return nil
		}
		err = exec.Command("kick.sh", string(server)).Start()
		if err != nil {
			fmt.Println(err.Error())
		}

		// HTTP CHANNEL RESPONSE
		response = make([]byte, 0)
		// error code (4byte)
		response = append(response, []byte{0, 0, 0, 0}...)
		// fields present (2byte)
		// 1: channel id, 4: udp, 2: udp cookie
		response = append(response, []byte{7, 0}...)
		// reserved (2byte)
		response = append(response, []byte{0, 0}...)
		// channel id (4byte)
		response = append(response, []byte{1, 0, 0, 0}...)
		// UDP port (2byte)
		response = append(response, byte(0xff&(udpport>>0)))
		response = append(response, byte(0xff&(udpport>>8)))
		// HTTP blob len (2byte)
		response = append(response, []byte{20, 0}...)
		response = append(response, createRandom(20)...)
		err = WriteHTTPPacket(OUT, 0x9, response)
		if err != nil {
			return err
		}

		rdp, err := net.Dial("tcp4", string(server)+":"+strconv.Itoa(port))
		if err != nil {
			return err
		}
		defer rdp.Close()

		go func() {
			stuck := make([]byte, 0)
			buf := make([]byte, 0xffff)
			for {
				size, err := rdp.Read(buf)
				if err != nil {
					log.Println(err)
					return
				}
				stuck = append(stuck, buf[:size]...)
				// fmt.Printf("Len: %d\n", size)
				for {
					if len(stuck) < 5 {
						break
					}
					// print(stuck[:5])
					realSize := (0xff & int(stuck[3])) | (0xff & int(stuck[2]) << 8)
					realSize &= 0x3fff
					if 0x80&stuck[1] != 0 {
						realSize = (0xff & int(stuck[2])) | (0x7f & int(stuck[1]) << 8)
					}
					if stuck[1] == 0x03 && stuck[2] == 0x03 {
						realSize = (0xff & int(stuck[4])) | (0xff & int(stuck[3]) << 8)
						realSize += 5
					}
					// fmt.Printf("Size: %04x %d %d %04x\n", realSize, realSize, len(stuck), len(stuck))
					if len(stuck) < realSize {
						break
					}
					// fmt.Printf("Size: %04x\n", realSize)
					packet := make([]byte, 0)
					packet = append(packet, 0xff&byte(realSize))
					packet = append(packet, 0xff&byte(realSize>>8))
					packet = append(packet, stuck[:realSize]...)
					err = WriteHTTPPacket(OUT, 0x0a, packet)
					if err != nil {
						log.Println(err)
						return
					}
					stuck = stuck[realSize:]
				}
			}
		}()

		for {
			ptype, body, err := ReadHTTPPacket(IN)
			if err != nil {
				return err
			}
			if ptype == 10 {
				size := (0xff & int(body[0])) | (0xff & int(body[1]) << 8)
				_, err = rdp.Write(body[2:(size + 2)])
				if err != nil {
					return err
				}
			} else if ptype == 16 {
				rdp.Close()
				err = WriteHTTPPacket(OUT, 0x11, []byte{0, 0, 0, 0})
				if err != nil {
					return err
				}
				break
			}
		}
	}
}

func pipe(conn *net.TCPConn) {
	fmt.Println("Accepted.")
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", "winsvr2012-1:80")
	rdg, err := net.DialTCP("tcp4", nil, tcpAddr)
	if err != nil {
		log.Println(err)
		return
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			size, err := rdg.Read(buf)
			if err != nil {
				log.Println(err)
				return
			}
			if size > 0 {
				print(buf[:size])
				conn.Write(buf[:size])
			}
		}
	}()
	buf := make([]byte, 2048)
	for {
		size, err := conn.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		if size > 0 {
			print(buf[:size])
			rdg.Write(buf[:size])
		}
	}
}

func readCert() []byte {
	f, err := os.Open("cert")
	if err != nil {
		fmt.Println("error")
		return nil
	}
	defer f.Close()

	// 一気に全部読み取り
	b, err := ioutil.ReadAll(f)
	// fmt.Print(string(b))

	buf := make([]byte, 0)
	for _, v := range b {
		buf = append(buf, v)
		buf = append(buf, 0)
	}
	buf = append(buf, 0)
	buf = append(buf, 0)
	// print(buf)
	return buf
}

// UDPHandler ...
func UDPHandler() {
	fmt.Println("Server is Running at 0.0.0.0:" + strconv.Itoa(udpport))
	udp, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(udpport))
	if err != nil {
		log.Println(err)
		return
	}
	defer udp.Close()

	buffer := make([]byte, 1600)
	for {
		// 通信読込 + 接続相手アドレス情報が受取
		length, remoteAddr, _ := udp.ReadFrom(buffer)
		fmt.Printf("Received from %v:\n", remoteAddr)
		print(buffer[:length])
		if false {
			// conn, _ := net.Dial("udp4", "winsvr2016-3:3389")
			// defer conn.Close()
			// fmt.Println("サーバへメッセージを送信.")
			// conn.Write(buffer[:length])

			// fmt.Println("サーバからメッセージを受信。")
			// buffer := make([]byte, 1600)
			// length, _ := conn.Read(buffer)
			// fmt.Printf("Receive: %s \n", string(buffer[:length]))
		}
		// conn.WriteTo([]byte("Hello, World !"), remoteAddr)
	}
}

// RDG_IN_DATA ...
func RDG_IN_DATA(conn *net.TCPConn) bool {
	fmt.Println("Accepted IN.")
	if !authNtlm(conn, false) {
		return false
	}
	fmt.Println("Start IN.")
	return true
}

// RDG_OUT_DATA ...
func RDG_OUT_DATA(conn *net.TCPConn) bool {
	fmt.Println("Accepted OUT.")
	if !authNtlm(conn, true) {
		return false
	}
	fmt.Println("Start OUT.")
	return true
}

func handleListener(l *net.TCPListener) error {
	defer l.Close()

	// go UDPHandler()

	var out *net.TCPConn
	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			return err
		}
		line, _ := ReadLine(conn) // line is empty when error occured
		fmt.Printf("%s\n", line)
		if strings.HasPrefix(line, "RDG_OUT_DATA ") {
			out = conn
			go RDG_OUT_DATA(out)
			continue
		}
		if strings.HasPrefix(line, "RDG_IN_DATA ") && out != nil {
			in := conn
			go func() {
				defer in.Close()
				defer out.Close()

				success := RDG_IN_DATA(in)
				if success {
					handle(in, out)
				}
			}()
		}
	}
}

var USERNAME string = ""
var PASSWORD string = ""
var udpport int = 3391

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: rdgw [user] [pass]")
		return
	}
	USERNAME = os.Args[1]
	PASSWORD = os.Args[2]

	tcpAddr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:13389")
	if err != nil {
		log.Println("ResolveTCPAddr", err)
		return
	}

	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Println("ListenTCP", err)
		return
	}

	err = handleListener(l)
	if err != nil {
		log.Println("handleListener", err)
	}
}
