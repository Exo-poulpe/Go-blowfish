package main

import (
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/blowfish"
)

var (
	strData  string
	strKey   string
	fVerbose bool
)

func init() {
	flag.StringVar(&strData, "d", "", "Data to encrypt")
	flag.StringVar(&strKey, "k", "", "Key for encryption")
	flag.BoolVar(&fVerbose, "v", false, "For activate verbose mode")
}

func main() {

	flag.Parse()

	if strData == "" || strData == "" {
		println("Please " + os.Args[0] + " -h")
		os.Exit(0)
	}

	fmt.Println("Start blowfish encryption")
	start := time.Now()
	key := []byte(strKey)
	data := []byte(strData)
	var encryptedVal []byte
	var decryptedVal []byte

	encryptedVal, err := encrypt(data, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(ByteToHex(encryptedVal))

	decryptedVal, err = decrypt(encryptedVal, key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Time elapsed : %s", time.Since(start))
	if fVerbose == true {
		fmt.Printf("Data \t : %s \nKey \t : %s \nResult encrypt : %s\nResult decrypt : %s\nEnd\n",
			string(data), string(key), ByteToHex(encryptedVal), decryptedVal)
	}

}

// Convert byte array to string hex
func ByteToHex(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Check if size padding is ok
func checksizeAndPad(plaintext []byte) []byte {

	modulus := len(plaintext) % blowfish.BlockSize
	if modulus != 0 {
		padlen := blowfish.BlockSize - modulus

		// add required padding
		for i := 0; i < padlen; i++ {
			plaintext = append(plaintext, 0)
		}
	}

	return plaintext
}

// encrypt data to blowfish algo
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	var iv = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	plaintext = checksizeAndPad(plaintext)

	cip, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, blowfish.BlockSize+len(plaintext))

	ecbc := cipher.NewCBCEncrypter(cip, iv)
	ecbc.CryptBlocks(ciphertext[blowfish.BlockSize:], plaintext)

	return ciphertext, nil
}

// Decrypt data to blowfish algo
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	var iv = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	dcipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err)
	}

	decrypted := ciphertext[blowfish.BlockSize:]
	if len(decrypted)%blowfish.BlockSize != 0 {
		panic("is not valid for decrypt (not multipl of blowfish.BlockSize)")
	}

	dcbc := cipher.NewCBCDecrypter(dcipher, iv)
	dcbc.CryptBlocks(decrypted, decrypted)

	return decrypted, nil
}
