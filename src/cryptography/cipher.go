package cryptography

import (
	"bytes"
	"credentials"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"loggerUtil"
	"strings"
)

func addBase64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)
	}

	return value
}

func removeBase64Padding(value string) string {
	return strings.Replace(value, "=", "", -1)
}

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		loggerUtil.Debugln("unpad error. This could happen when incorrect encryption key is used")
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

func encryptBackend(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		loggerUtil.Log.Println("New Cipher Error: " + err.Error())
		return "", err
	}

	msg := Pad([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		loggerUtil.Log.Println("Rand Reader Error: " + err.Error())
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
	finalMsg := removeBase64Padding(base64.URLEncoding.EncodeToString(ciphertext))
	return finalMsg, nil
}

func decryptBackend(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedMsg, err := base64.URLEncoding.DecodeString(addBase64Padding(text))
	if err != nil {
		loggerUtil.Log.Println("Error: in url encoding and decode: " + err.Error())
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		loggerUtil.Log.Println("blocksize must be multipe of decoded message length")
		return "", errors.New("blocksize must be multipe of decoded message length")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unpadMsg, err := Unpad(msg)
	if err != nil {
		loggerUtil.Log.Println("Unpad Error: " + err.Error())
		return "", err
	}

	return string(unpadMsg), nil
}

func Encrypt(email string) (string, error) {
	loggerUtil.Debugln("Entering Encrypt: " + email)
	var ciphertext string
	cred, err := credentials.GetCredentials()
	if err != nil {
		loggerUtil.Log.Println("Error: in obtaining credentials " + err.Error())
		return ciphertext, err
	}
	keyString := cred.TokenAuthKey
	key := []byte(keyString)
	ciphertext, err = encryptBackend(key, email)
	if err != nil {
		loggerUtil.Log.Println("encrypt: Error encrypting Email " + email + " " + err.Error())
		return ciphertext, err
	}
	loggerUtil.Debugln("Returning Cipher " + ciphertext)
	return ciphertext, nil

}

func Decrypt(ciphertext string) (string, error) {
	loggerUtil.Debugln("Entering Decrypt " + ciphertext)
	var email string
	cred, err := credentials.GetCredentials()
	if err != nil {
		loggerUtil.Log.Println("decrypt: Error: in obtaining credentials " + err.Error())
		return email, err
	}
	keyString := cred.TokenAuthKey
	key := []byte(keyString)
	email, err = decryptBackend(key, ciphertext)
	if err != nil {
		loggerUtil.Log.Println("decrypt: Error decrypting ciphertext " + ciphertext + " " + err.Error())
		return email, err
	}
	loggerUtil.Debugln("Entering Decrypt  email " + email)
	return email, nil

}
