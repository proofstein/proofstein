// Package seal provides authenticated encryption for device payloads.
//
// Transports register themselves in a constructor table rather than calling the
// cipher constructors directly, so that the relay can add a transport without
// touching the call sites in cmd/.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// ErrUnknownTransport is returned when the config names a transport that was
// never registered.
var ErrUnknownTransport = errors.New("seal: unknown transport")

type aeadFactory func(key []byte) (cipher.AEAD, error)

// registry maps a transport name to the AEAD it uses on the wire. Names are the
// ones that appear in configs/relay.yaml.
var registry = map[string]aeadFactory{
	"device-uplink": newPayloadAEAD,
	"peer-mirror":   newPayloadAEAD,
}

// newPayloadAEAD builds the AEAD used for every relay payload.
func newPayloadAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("seal: need a 32 byte key, got %d", len(key))
	}
	block, err := aes.NewCipher(key) //@PS go-l1-aes-block|AES-256|1|algorithm|block cipher construction
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block) //@PS go-l1-aes-gcm|AES-256-GCM|1|algorithm|AEAD construction
}

// Sealer encrypts payloads for one named transport.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer resolves a transport name through the registry. The algorithm is
// never named at this call site; it is reached only through the table above.
func NewSealer(transport string, key []byte) (*Sealer, error) {
	factory, ok := registry[transport]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownTransport, transport)
	}
	aead, err := factory(key) //@PS go-l3-wrapper|AES-256-GCM|3|algorithm|AEAD reached only via the constructor table
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext and prefixes the nonce.
func (s *Sealer) Seal(plaintext, additional []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("seal: nonce: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, additional), nil
}

// Open reverses Seal.
func (s *Sealer) Open(sealed, additional []byte) ([]byte, error) {
	size := s.aead.NonceSize()
	if len(sealed) < size {
		return nil, errors.New("seal: ciphertext too short")
	}
	return s.aead.Open(nil, sealed[:size], sealed[size:], additional)
}
