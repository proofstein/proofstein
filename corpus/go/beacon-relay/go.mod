module github.com/proofstein/beacon-relay

go 1.24

// The relay ships an optional SSH transport for field devices. The transport is
// gated behind a build tag that is off by default, so nothing in the default
// build reaches this module -- but it is still part of our dependency surface.
require golang.org/x/crypto v0.36.0
