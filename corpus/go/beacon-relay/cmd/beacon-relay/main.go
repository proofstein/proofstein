// Command beacon-relay accepts telemetry beacons from field devices, seals
// them, and mirrors them to peer relays.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/proofstein/beacon-relay/internal/config"
	"github.com/proofstein/beacon-relay/internal/digest"
	"github.com/proofstein/beacon-relay/internal/identity"
	"github.com/proofstein/beacon-relay/internal/seal"
	"github.com/proofstein/beacon-relay/internal/session"
)

func main() {
	configPath := flag.String("config", "configs/relay.yaml", "path to the relay config")
	flag.Parse()

	if err := run(*configPath); err != nil {
		log.Printf("beacon-relay: %v", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	ids, err := identity.Generate()
	if err != nil {
		return err
	}

	responder, err := session.NewResponder()
	if err != nil {
		return err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("session key: %w", err)
	}

	sealer, err := seal.NewSealer(cfg.Transport, key)
	if err != nil {
		return err
	}

	body := []byte("beacon: device=field-0417 rssi=-71 battery=0.62")
	address := digest.Of(body)

	sealed, err := sealer.Seal(body, []byte(address))
	if err != nil {
		return err
	}

	envelope := append([]byte(address), sealed...)
	signature := ids.SignEnvelope(envelope)

	log.Printf("relay ready: transport=%s suite=%s address=%s sealed=%dB sig=%dB peer_key=%dB",
		cfg.Transport, cfg.Suite, address[:16], len(sealed), len(signature), len(responder.EncapsulationKey()))
	return nil
}
