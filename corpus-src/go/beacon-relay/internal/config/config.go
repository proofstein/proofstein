// Package config loads the relay's runtime settings.
//
// The relay reads a deliberately small subset of YAML: flat scalars and one
// level of nesting. Pulling in a full YAML parser for eight keys was not worth
// the dependency.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config is the parsed contents of configs/relay.yaml.
type Config struct {
	Transport string
	Suite     string
	Signature string
	KeyFile   string
	CertFile  string
}

// Load reads a relay config from disk.
func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer file.Close()

	values := map[string]string{}
	var section string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" {
			section = key
			continue
		}
		if !strings.HasPrefix(line, " ") {
			section = ""
		}
		if section != "" {
			key = section + "." + key
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	return &Config{
		Transport: values["relay.transport"],
		Suite:     values["crypto.suite"],
		Signature: values["crypto.signature"],
		KeyFile:   values["crypto.key_file"],
		CertFile:  values["crypto.cert_file"],
	}, nil
}
