package main

import (
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/crypto/blowfish"
)

var (
	strData     string
	strKey      string
	fFile       string
	fOutPutFile string
	fCrypt      int
	fVerbose    bool
	fHelp       bool
	fDevices    bool

	encryptedVal []byte
	decryptedVal []byte
	err          error
)

func init() {
	flag.StringVar(&strData, "d", "", "Data to encrypt")
	flag.StringVar(&strKey, "k", "", "Key for encryption")
	flag.StringVar(&fFile, "f", "", "file to encrypt")
	flag.StringVar(&fOutPutFile, "o", "", "file to write data encrypted")
	flag.BoolVar(&fVerbose, "v", false, "For activate verbose mode")
	flag.IntVar(&fCrypt, "m", -1, "1 for encryption 2 for decryption")
	flag.BoolVar(&fDevices, "list-devices", false, "list all devices on system")
	flag.BoolVar(&fHelp, "h", false, "Show this help")
}

func main() {

	flag.Parse()

	if fDevices == true {
		fmt.Println(Getdrives())
		os.Exit(0)
	}
	if (strData == "" && fFile == "") || strKey == "" || fHelp == true || fCrypt == -1 {
		flag.Usage()
		os.Exit(0)
	}

	fmt.Println("Start blowfish encryption")
	start := time.Now()
	key := []byte(strKey)
	data := []byte(strData)

	if fCrypt == 1 {
		if fFile != "" {
			encryptedVal, err = encryptFile(fFile, key)
			if err != nil {
				panic(err)
			}
		} else {
			encryptedVal, err = encryptText(data, key)
			if err != nil {
				panic(err)
			}
		}

	} else if fCrypt == 2 {
		if fFile != "" {
			decryptedVal, err = decryptFile(fFile, key)
			if err != nil {
				panic(err)
			}
		} else {
			data, err := base64.StdEncoding.DecodeString(strData)
			decryptedVal, err = decryptText(data, key)
			if err != nil {
				panic(err)
			}
		}

	}

	if fVerbose == true {
		if fCrypt == 1 {
			fmt.Printf("Data \t : %s \nKey \t : %s \nResult encrypt : %s\n",
				string(data), string(key), ByteToHex(encryptedVal))
		} else if fCrypt == 2 {
			fmt.Printf("Data \t : %s \nKey \t : %s \nResult decrypt : %s\n",
				string(data), string(key), decryptedVal)
		}

	}
	if fOutPutFile != "" {
		if fCrypt == 1 {
			err = ioutil.WriteFile(fOutPutFile, encryptedVal, 7777)
			if err != nil {
				panic(err)
			}
		} else if fCrypt == 2 {
			err = ioutil.WriteFile(fOutPutFile, decryptedVal, 7777)
			if err != nil {
				panic(err)
			}
		}

	}
	fmt.Printf("Time elapsed \t : %s\n", time.Since(start))

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
func encryptText(plaintext []byte, key []byte) ([]byte, error) {
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
func decryptText(ciphertext []byte, key []byte) ([]byte, error) {
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

// Read file and encrypt then
func encryptFile(filePath string, key []byte) ([]byte, error) {
	var iv = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	plaintext, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
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

// Read file and decrypt then
func decryptFile(filePath string, key []byte) ([]byte, error) {
	var iv = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	dcipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext, err := ioutil.ReadFile(filePath)
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

// Test all drives possibilites
func Getdrives() (r []string) {
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		_, err := os.Open(string(drive) + ":\\")
		if err == nil {
			r = append(r, " ["+string(drive)+":\\\\] ")
		}
	}
	return
}

func EncryptDevice(label string) {

	// for i, item := range files {
	//
	// }
}
