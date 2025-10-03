package sbom

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type signer interface {
	Sign(data []byte) ([]byte, error)
}

type ed25519Signer struct {
	key ed25519.PrivateKey
}

func newEd25519Signer(path string) (signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data in %s", path)
	}

	switch block.Type {
	case "ED25519 PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			if pk, ok := key.(ed25519.PrivateKey); ok {
				return &ed25519Signer{key: pk}, nil
			}
		}
		keyBytes := block.Bytes
		if len(keyBytes) == ed25519.PrivateKeySize {
			return &ed25519Signer{key: ed25519.PrivateKey(keyBytes)}, nil
		}
		return nil, fmt.Errorf("unsupported ed25519 key format")
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		pk, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not ed25519")
		}
		return &ed25519Signer{key: pk}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

func (s *ed25519Signer) Sign(data []byte) ([]byte, error) {
	if len(s.key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key length")
	}
	sig := ed25519.Sign(s.key, data)
	return sig, nil
}
