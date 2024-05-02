package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

func Encrypt(key *rsa.PublicKey, mensagem string) (string, error) {
	mensagemBytes := []byte(mensagem)
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, key, mensagemBytes, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(key *rsa.PrivateKey, mensagem string) (string, error) {
	decodedCiphertext, err := base64.StdEncoding.DecodeString(mensagem)
	if err != nil {
		return "", err
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, key, decodedCiphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func main() {

	bitSize := 4096
	msg := ("Distopia, ThSheen, Ubirajara, John Wesley")

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		fmt.Println(err)
	}

	mensagemCripto, err := Encrypt(&key.PublicKey, msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return
	}

	fmt.Println("Mensagem criptografada: ", mensagemCripto, "\n")

	mensagemDescripto, err := Decrypt(key, mensagemCripto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return
	}

	fmt.Println("Mensagem Descriptografada: ", mensagemDescripto, "\n")
}
