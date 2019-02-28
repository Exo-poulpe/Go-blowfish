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
	strData  string
	strKey   string
	fFlag    string
	fCrypt   int
	fVerbose bool
	fHelp    bool

	encryptedVal []byte
	decryptedVal []byte
	err          error
)

func init() {
	flag.StringVar(&strData, "d", "", "Data to encrypt")
	flag.StringVar(&strKey, "k", "", "Key for encryption")
	flag.StringVar(&fFlag, "f", "", "file to encrypt")
	flag.BoolVar(&fVerbose, "v", false, "For activate verbose mode")
	flag.IntVar(&fCrypt, "m", -1, "1 for encryption 2 for decryption")
	flag.BoolVar(&fHelp, "h", false, "Show this help")
}

func main() {

	flag.Parse()

	if (strData == "" && fFlag == "") || strKey == "" || fHelp == true || fCrypt == -1 {
		flag.Usage()
		os.Exit(0)
	}

	fmt.Println("Start blowfish encryption")
	start := time.Now()
	key := []byte(strKey)
	data := []byte(strData)

	//fmt.Println(base64.StdEncoding.DecodeString(strData))

	if fCrypt == 1 {
		encryptedVal, err = encryptText(data, key)
		if err != nil {
			panic(err)
		}
	} else if fCrypt == 2 {
		data, err := base64.StdEncoding.DecodeString(strData)
		decryptedVal, err = decryptText(data, key)
		if err != nil {
			panic(err)
		}
	}

	// else if fFlag != "" {
	// 	encryptedVal, err := encryptFile(fFlag, key)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Println("Encrypted file : " + ByteToHex(encryptedVal))
	// 	decryptedVal, err := ioutil.ReadFile(fFlag)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	decryptedVal = decryptedVal

	// }

	if fVerbose == true {
		if fCrypt == 1 {
			fmt.Printf("Data \t : %s \nKey \t : %s \nResult encrypt : %s\n",
				string(data), string(key), ByteToHex(encryptedVal))
		} else if fCrypt == 2 {
			fmt.Printf("Data \t : %s \nKey \t : %s \nResult decrypt : %s\n",
				string(data), string(key), decryptedVal)
		}

	} else {
		fmt.Printf("Result : %s\n", ByteToHex(encryptedVal))
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
