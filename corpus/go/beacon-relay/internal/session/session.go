// Package session negotiates the per-connection key for peer relay mirroring.
//
// Peer links are long-lived and carry fleet telemetry that must stay
// confidential well past the lifetime of the hardware, so the key exchange is
// post-quantum rather than classical ECDH.
package session

import (
	"crypto/mlkem"
	"fmt"
)

// Responder holds the decapsulation key for one relay.
type Responder struct {
	key *mlkem.DecapsulationKey768
}

// NewResponder generates a fresh ML-KEM decapsulation key.
func NewResponder() (*Responder, error) {
	key, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("session: generate: %w", err)
	}
	return &Responder{key: key}, nil
}

// EncapsulationKey is the public half, published in the relay directory.
func (r *Responder) EncapsulationKey() []byte {
	return r.key.EncapsulationKey().Bytes()
}

// Accept derives the shared secret from an initiator's ciphertext.
func (r *Responder) Accept(ciphertext []byte) ([]byte, error) {
	shared, err := r.key.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("session: decapsulate: %w", err)
	}
	return shared, nil
}

// Initiate encapsulates a fresh shared secret against a peer's published key.
func Initiate(peerKey []byte) (shared, ciphertext []byte, err error) {
	encapsulation, err := mlkem.NewEncapsulationKey768(peerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("session: peer key: %w", err)
	}
	shared, ciphertext = encapsulation.Encapsulate()
	return shared, ciphertext, nil
}
