// Package identity holds the relay's long-lived signing material.
//
// A relay carries three identities: an RSA key for the legacy fleet management
// API, an ECDSA key for mutual TLS to peer relays, and an Ed25519 key used to
// sign the beacon envelopes themselves.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// Bundle is the full set of keys a relay needs at startup.
type Bundle struct {
	FleetAPI  *rsa.PrivateKey
	PeerMTLS  *ecdsa.PrivateKey
	Envelopes ed25519.PrivateKey
}

// Generate creates a fresh identity bundle. Production relays load these from
// the keystore instead; see loadFleetKey.
func Generate() (*Bundle, error) {
	fleet, err := rsa.GenerateKey(rand.Reader, 2048) //@PS go-l1-rsa|RSA-2048|1|algorithm|legacy fleet management API key
	if err != nil {
		return nil, fmt.Errorf("identity: fleet key: %w", err)
	}

	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //@PS go-l1-ecdsa|ECDSA-P256|1|algorithm|peer mutual TLS key
	if err != nil {
		return nil, fmt.Errorf("identity: peer key: %w", err)
	}

	_, envelopes, err := ed25519.GenerateKey(rand.Reader) //@PS go-l1-ed25519|Ed25519|1|algorithm|beacon envelope signing key
	if err != nil {
		return nil, fmt.Errorf("identity: envelope key: %w", err)
	}

	return &Bundle{FleetAPI: fleet, PeerMTLS: peer, Envelopes: envelopes}, nil
}

// SignEnvelope signs a serialised beacon envelope.
func (b *Bundle) SignEnvelope(envelope []byte) []byte {
	return ed25519.Sign(b.Envelopes, envelope)
}

// SignFleetRequest signs a fleet API request body over its digest.
func (b *Bundle) SignFleetRequest(digest []byte) ([]byte, error) {
	return b.FleetAPI.Sign(rand.Reader, digest, crypto.SHA256) //@PS go-l1-sha256|SHA-256|1|algorithm|digest algorithm for fleet request signatures
}
