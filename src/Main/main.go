package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"unicode"

	"golang.org/x/crypto/md4"
)

func print(bs []byte) {
	count := 0
	for _, n := range bs {
		fmt.Printf("%02x ", n) // prints 1111111111111101
		count++
		if count%16 == 0 {
			fmt.Printf("\n")
		} else if count%8 == 0 {
			fmt.Printf(" ")
		}
	}
	fmt.Printf("\n")
}

func print21(bs [21]byte) {
	for _, n := range bs {
		fmt.Printf("%02x ", n) // prints 1111111111111101
	}
	fmt.Printf("\n")
}

func print24(bs [24]byte) {
	for _, n := range bs {
		fmt.Printf("%02x ", n) // prints 1111111111111101
	}
	fmt.Printf("\n")
}

/* setup LanManager password */
func setup_lmpasswd(passw []byte) [14]byte {
	var lm_pw [14]byte
	len := len(passw)
	if len > 14 {
		len = 14
	}

	idx := 0
	for ; idx < len; idx++ {
		lm_pw[idx] = byte(unicode.ToUpper(rune(passw[idx])))
	}
	for ; idx < 14; idx++ {
		lm_pw[idx] = 0
	}
	return lm_pw
}

/* create LanManager hashed password */
func create_lm_hashed_passwd(passw []byte) [21]byte {
	var magic []byte = []byte{0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25}
	// lm_hpw := make([]byte, 21)
	var lm_hpw [21]byte
	// var ks des_key_schedule
	lm_pw := setup_lmpasswd(passw)

	// setup_des_key(lm_pw, ks)
	ks := setup_des_key(lm_pw[:7])
	// des_ecb_encrypt(magic, lm_hpw, ks)
	ks.Encrypt(lm_hpw[:8], magic)

	// setup_des_key(lm_pw+7, ks)
	ks = setup_des_key(lm_pw[7:14])
	// des_ecb_encrypt(magic, lm_hpw+8, ks)
	ks.Encrypt(lm_hpw[8:], magic)

	// memset(lm_hpw+16, 0, 5)
	return lm_hpw
}

/* create NT hashed password */
func create_nt_hashed_passwd(passw []byte) [21]byte {
	len := len(passw)
	nt_pw := make([]byte, 2*len)
	for idx := 0; idx < len; idx++ {
		nt_pw[2*idx] = passw[idx]
		nt_pw[2*idx+1] = 0
	}

	var nt_hpw [21]byte
	// MD4_CTX context;
	// MD4Init(&context);
	// MD4Update(&context, nt_pw, 2*len);
	// MD4Final(nt_hpw, &context);
	context := md4.New()
	io.WriteString(context, string(nt_pw))
	hashed := context.Sum(nil)

	for idx := 0; idx < 16; idx++ {
		nt_hpw[idx] = hashed[idx]
	}

	// memset(nt_hpw+16, 0, 5)
	return nt_hpw
}

/* create responses */
func create_response(passw []byte) {
	// var lm_resp [24]byte
	// var nt_resp [24]byte
	nonce := make_nonce()

	lm_hpw := create_lm_hashed_passwd(passw)
	print21(lm_hpw)
	lm_resp := calc_resp(lm_hpw, nonce)
	print24(lm_resp)
	nt_hpw := create_nt_hashed_passwd(passw)
	print21(nt_hpw)
	nt_resp := calc_resp(nt_hpw, nonce)
	print24(nt_resp)
}

/*
 * takes a 21 byte array and treats it as 3 56-bit DES keys. The
 * 8 byte plaintext is encrypted with each key and the resulting 24
 * bytes are stored in the results array.
 */
func calc_resp(keys [21]byte, plaintext []byte) [24]byte {
	var result [24]byte
	var cipher cipher.Block

	cipher = setup_des_key(keys[:7])
	//  des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) results, ks, DES_ENCRYPT);
	cipher.Encrypt(result[:8], plaintext)

	//  setup_des_key(keys+7, ks);
	cipher = setup_des_key(keys[7:14])
	//  des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) (results+8), ks, DES_ENCRYPT);
	cipher.Encrypt(result[8:16], plaintext)

	//  setup_des_key(keys+14, ks);
	cipher = setup_des_key(keys[14:21])
	//  des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) (results+16), ks, DES_ENCRYPT);
	cipher.Encrypt(result[16:24], plaintext)

	return result
}

/*
 * turns a 56 bit key into the 64 bit, odd parity key and sets the key.
 * The key schedule ks is also set.
 */
func setup_des_key(key_56 []byte) cipher.Block {
	key := make([]byte, 8)
	key[0] = key_56[0]
	key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1)
	key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2)
	key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3)
	key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4)
	key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5)
	key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6)
	key[7] = (key_56[6] << 1) & 0xFF

	//  des_set_odd_parity(&key);
	//  des_set_key(&key, ks);
	block, _ := des.NewCipher(key)
	return block
}

func make_nonce() []byte {
	nonce := make([]byte, 16)
	nonce[0] = 'S'
	nonce[1] = 'r'
	nonce[2] = 'v'
	nonce[3] = 'N'
	nonce[4] = 'o'
	nonce[5] = 'n'
	nonce[6] = 'c'
	nonce[7] = 'e'

	return nonce
}

func handleConnection(conn *net.TCPConn) {
	defer conn.Close()

	// buf := make([]byte, 4*1024)

	// n, err := conn.Read(buf)
	// if err != nil {
	// 	if ne, ok := err.(net.Error); ok {
	// 		switch {
	// 		case ne.Temporary():
	// 			continue
	// 		}
	// 	}
	// 	log.Println("Read", err)
	// 	return
	// }

	phase := 0
	// fmt.Printf("%s", buf[:n])
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("%s\n", line)
		if strings.HasPrefix(line, "Authorization:") {
			index := strings.Index(line, "NTLM") + 5
			type1msg := make([]byte, 4*1024)
			size, _ := base64.StdEncoding.Decode(type1msg, []byte(line[index:]))
			type1msg = type1msg[:size]
			switch phase {
			case 0:
				type2msg := make([]byte, 40)
				type2msg[0] = 'N'
				type2msg[1] = 'T'
				type2msg[2] = 'L'
				type2msg[3] = 'M'
				type2msg[4] = 'S'
				type2msg[5] = 'S'
				type2msg[6] = 'P'
				type2msg[7] = 0
				type2msg[8] = 2
				type2msg[16] = 40
				type2msg[17] = 0
				type2msg[20] = 0x01
				type2msg[21] = 0x82
				nonce := make_nonce()
				for idx := 0; idx < 8; idx++ {
					type2msg[idx+24] = nonce[idx]
				}
				type2msg_base64 := base64.StdEncoding.EncodeToString(type2msg)

				conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n"))
				conn.Write([]byte("WWW-Authenticate: NTLM " + type2msg_base64 + "\r\n"))
				conn.Write([]byte("\r\n"))

				phase = 1
				break

			case 1:
				print(type1msg)
				var lm_resp_offset int = 0
				lm_resp_offset = int(type1msg[16])
				lm_resp_offset |= int(type1msg[17]) << 8
				fmt.Printf("Host Offset: %d\n", lm_resp_offset)
				print(type1msg[lm_resp_offset : lm_resp_offset+24])
				break
			}
		}
	}
	// n, err = conn.Write(buf[:n])
	// if err != nil {
	//     log.Println("Write", err)
	//     return
	// }
}

func handleListener(l *net.TCPListener) error {
	defer l.Close()
	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Temporary() {
					log.Println("AcceptTCP", err)
					continue
				}
			}
			return err
		}

		go handleConnection(conn)
	}
}

func main() {
	create_response([]byte("Beeblebrox"))
	tcpAddr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:10080")
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
