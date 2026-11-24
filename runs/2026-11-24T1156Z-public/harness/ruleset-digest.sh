#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
#
# The rule-set digest the manifest records:  ruleset-digest.sh <rule directory>
# sha256 over sha256sum's own lines ("<sha256>  <path>") for every file in the
# directory, paths relative to it and sorted bytewise; the first 16 hex digits.
set -euo pipefail
cd "$1"
find . -type f -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum | sha256sum | cut -c1-16
