package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
)

// GenerateECDSAKeyPair generates a new ECDSA key pair.
func GenerateECDSAKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func GenerateECDSAKeyAndSave() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, publicKey, err := GenerateECDSAKeyPair()
	if err != nil {
		return nil, nil, err
	}
	privateKeyFile, err := os.Create("private.pem")
	if err != nil {
		return nil, nil, err
	}
	publicKeyFile, err := os.Create("public.pem")
	if err != nil {
		return nil, nil, err
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
	privateKeyFile.Write(privateKeyPEM)
	publicKeyFile.Write(publicKeyPEM)
	return privateKey, publicKey, nil
}

func LoadECDSAKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKeyFile, err := os.Open("private.pem")
	if err != nil {
		return nil, nil, err
	}
	publicKeyFile, err := os.Open("public.pem")
	if err != nil {
		return nil, nil, err
	}
	privateKeyBytes, err := io.ReadAll(privateKeyFile)
	if err != nil {
		return nil, nil, err
	}
	publicKeyBytes, err := io.ReadAll(publicKeyFile)
	if err != nil {
		return nil, nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	privateKey, err := x509.ParseECPrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey.(*ecdsa.PublicKey), nil
}

// SignECDSA signs a message with an ECDSA private key.
func SignECDSA(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, privateKey, message)
}

// VerifyECDSA verifies a signature with an ECDSA public key.
func VerifyECDSA(publicKey *ecdsa.PublicKey, message, signature []byte) bool {
	return ecdsa.VerifyASN1(publicKey, message, signature)
}
