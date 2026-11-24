# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Deciding whether a reported asset is the planted one.

A detection is agreement on file, algorithm and layer. An algorithm name
alone is never a detection.

* **Algorithm names** are compared as token sets, and a less specific report
  matches a more specific plant (``AES`` matches a planted ``AES-256-GCM``).
  The reverse does not hold, and a different family never matches.
* **File paths** are resolved by longest matching suffix against the real file
  list of the project.

Both are applied to every tool identically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Lines may differ by this much and still count as located.
DEFAULT_LINE_TOLERANCE = 2

# Token aliases folded together before comparison. Purely notational: each entry
# maps spellings of the same thing onto one token.
_TOKEN_ALIASES: dict[str, str] = {
    "AESGCM": "AES",
    "AES256GCM": "AES",
    "GCM": "GCM",
    "EDDSA": "ED25519",
    "ED25519PH": "ED25519",
    "CURVE25519": "X25519",
    "SECP256R1": "P256",
    "PRIME256V1": "P256",
    "NISTP256": "P256",
    "SECP256K1": "P256K1",
    "SECP384R1": "P384",
    "SECP521R1": "P521",
    "CURVE448": "X448",
    "FFDHE": "DH",
    "MLKEM": "MLKEM",
    "KYBER": "MLKEM",
    "MLDSA": "MLDSA",
    "DILITHIUM": "MLDSA",
    "SHA2": "SHA256",
    "RSASSA": "RSA",
    "RSAPSS": "RSA",
    "PSS": "RSA",
    "PKCS1": "RSA",
    "OAEP": "RSA",
    "EC": "EC",
    "ECDH": "ECDH",
    "ECDHE": "ECDH",
    "TLSV1": "TLS",
    "TLS1": "TLS",
    "XSALSA20": "SALSA20",
    "CHACHA20POLY1305": "CHACHA20",
    "POLY1305": "CHACHA20",
    "ARC4": "RC4",
}

# Tokens that carry no discriminating power on their own.
_STOPWORDS = frozenset(
    {
        "",
        "WITH",
        "AND",
        "KEY",
        "ALGORITHM",
        "CIPHER",
        "MODE",
        "NOPADDING",
        "PADDING",
        "PRIVATE",
        "PUBLIC",
        "SECRET",
        "OTHER",
        "UNKNOWN",
        "GENERIC",
        "UNSPECIFIED",
        # Descriptive words: "AES block cipher in use" reads as "AES".
        "IN",
        "USE",
        "BLOCK",
    }
)

#: Mode and construction qualifiers that may accompany a cipher name without
#: making the name mean something else. Used only to decide whether a token from
#: :data:`_WHOLE_TOKEN_ONLY` is being used as an algorithm name.
_CIPHER_QUALIFIERS = frozenset(
    {"CBC", "ECB", "CFB", "OFB", "CTR", "GCM", "CCM", "XTS", "EDE", "EDE2", "EDE3", "PKCS5", "PKCS7"}
)

#: Algorithm family tokens. Two names sharing no family never match.
_FAMILIES = (
    "AES",
    "RSA",
    "ECDSA",
    # Elliptic-curve key agreement, a family distinct from ECDSA.
    "ECDH",
    # An elliptic-curve key whose use is not stated: a bare curve name or "EC".
    # It credits an ECDSA or an ECDH plant on that curve; see _settle_ec.
    "EC",
    "ED25519",
    "ED448",
    "X25519",
    "X448",
    "MLKEM",
    "MLDSA",
    # Post-quantum signature schemes, each a family distinct from the others
    # and from DSA.
    "SLHDSA",
    "FALCON",
    "LMS",
    "XMSS",
    "SHA1",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3",
    "MD5",
    "TLS",
    # A family distinct from TLS.
    "SSL",
    "CHACHA20",
    "SALSA20",
    "DES",
    "3DES",
    "BLOWFISH",
    "HMAC",
    "PBKDF2",
    "SCRYPT",
    "ARGON2",
    "BCRYPT",
    "DSA",
    "DH",
    "MGF1",
    # Matched as whole tokens only; see _WHOLE_TOKEN_ONLY below.
    "RC2",
    "RC4",
    "SEED",
    "IDEA",
    "CAST5",
    "CAMELLIA",
)

#: Families matched only as a complete token, never inside one, and only when
#: every other token of the name is a size, a mode qualifier or a descriptive
#: word. None of them appears in _FAMILY_MARKERS. ``SEED``, ``SEED-CBC`` and
#: ``SEED-128-CBC`` claim the family; ``seedRandom``, ``seed_material`` and
#: ``random seed`` do not. ``BCRYPT`` alone claims the password hash;
#: ``BCryptOpenAlgorithmProvider`` and ``BCRYPT_ECDH_P256_ALGORITHM`` do not.
_WHOLE_TOKEN_ONLY = frozenset({"DES", "RC2", "RC4", "SEED", "IDEA", "CAST5", "CAMELLIA", "BCRYPT"})

#: Token a curve name contributes in place of a family. A name that gives only
#: a curve, or only "EC", says which curve and not what the key does, so it
#: claims the EC family, which credits an ECDSA or an ECDH plant on that curve.
#: A name that says ECDSA or ECDH (``ECDH-P256``, ``BCRYPT_ECDH_P256_ALGORITHM``)
#: claims only that family.
_CURVE = "ECCURVE"
_EC_USES = frozenset({"ECDSA", "ECDH"})

#: JOSE algorithm names (RFC 7518) -> what they are. The number in a JOSE name
#: is a digest length, never a key size: RS256 is RSA with SHA-256 at whatever
#: modulus the key has, so it must neither contradict RSA-2048 nor be read as
#: 256-bit RSA. ES256, ES384 and ES512 do fix their curve. A hyphen in a key
#: matches any one separator or none.
_JOSE_NAMES: dict[str, str] = {
    "RS256": "RSA",
    "RS384": "RSA",
    "RS512": "RSA",
    "PS256": "RSA-PSS",
    "PS384": "RSA-PSS",
    "PS512": "RSA-PSS",
    "ES256": "ECDSA-P256",
    "ES384": "ECDSA-P384",
    "ES512": "ECDSA-P521",
    "RSA-OAEP-256": "RSA-OAEP",
}

#: Hybrid key-exchange groups -> (classical half, post-quantum half). A hybrid
#: is credited by a report naming the hybrid, or naming both halves in the
#: plant's file; a report of either half alone does not credit it. The classical
#: half of a SecP hybrid is ECDH on that curve. A hyphen in a key matches any
#: one separator or none; ``+`` and a space may join the halves, a list
#: separator may not, since ``X25519:MLKEM768`` lists two groups.
_HYBRID_GROUPS: dict[str, tuple[str, str]] = {
    "X25519-ML-KEM-768": ("X25519", "ML-KEM-768"),
    "X448-ML-KEM-1024": ("X448", "ML-KEM-1024"),
    "SECP256R1-ML-KEM-768": ("ECDH-P256", "ML-KEM-768"),
    "SECP384R1-ML-KEM-1024": ("ECDH-P384", "ML-KEM-1024"),
}


def _spelling_pattern(key: str, joiner: str = r"[-_ ]?") -> str:
    return joiner.join(re.escape(part) for part in key.split("-"))


_JOSE_PATTERN = re.compile(
    r"(?<![A-Z0-9])("
    + "|".join(_spelling_pattern(key) for key in sorted(_JOSE_NAMES, key=len, reverse=True))
    + r")(?![A-Z0-9])"
)
_JOSE_LOOKUP = {re.sub(r"[^A-Z0-9]", "", key): value for key, value in _JOSE_NAMES.items()}

_HYBRID_PATTERN = re.compile(
    r"(?<![A-Z0-9])("
    + "|".join(_spelling_pattern(key, r"[-_ +]*") for key in _HYBRID_GROUPS)
    + r")(?![0-9])"
)
_HYBRID_LOOKUP = {re.sub(r"[^A-Z0-9]", "", key): halves for key, halves in _HYBRID_GROUPS.items()}

#: ``P-384`` is the curve ``secp384r1`` names; written with a separator it would
#: otherwise split into a bare letter and a number.
_NIST_CURVE = re.compile(r"(?<![A-Z0-9])P[-_ ]?(192|224|256|384|521)(?![0-9])")


def hybrid_halves(name: str) -> tuple[str, str] | None:
    """The (classical, post-quantum) halves of a hybrid group the name states."""
    if not name:
        return None
    match = _HYBRID_PATTERN.search(name.upper().strip().split("@", 1)[0])
    if not match:
        return None
    return _HYBRID_LOOKUP[re.sub(r"[^A-Z0-9]", "", match.group(1))]


#: A combined signature name: a digest, "with", a signature scheme, as the JCA
#: and X.509 spell them (SHA256withECDSA, SHA384withRSA, sha256WithRSAEncryption,
#: SHA256withRSA/PSS, SHA256withRSAandMGF1). It names both algorithms, so it is
#: rewritten to the two names before tokens are read.
_COMBINED_SIGNATURE = re.compile(
    r"(?<![A-Z0-9])(SHA-?(?:1|224|256|384|512)|SHA3-(?:224|256|384|512)|MD5|MD2|SM3)WITH"
    r"(RSAANDMGF1|RSAENCRYPTION|RSA|PLAIN-ECDSA|CVC-ECDSA|ECDSA|DSA|ED25519|ED448|SM2)(?![A-Z0-9])"
)
_COMBINED_SCHEME = {"RSAANDMGF1": "RSA-PSS", "RSAENCRYPTION": "RSA", "PLAIN-ECDSA": "ECDSA", "CVC-ECDSA": "ECDSA"}

_SPLIT = re.compile(r"[^A-Z0-9]+")
_TRAILING_DIGITS = re.compile(r"^([A-Z]+)(\d+)$")
_DIGITS = re.compile(r"\d+")
_NON_ALNUM = re.compile(r"[^A-Z0-9]")

#: Markers that identify a family inside a separator-stripped name, anchored to
#: a token boundary by :func:`_marker_positions`. Longest first, so ML-KEM is
#: found before any shorter accidental match.
_FAMILY_MARKERS: tuple[tuple[str, str], ...] = tuple(
    sorted(
        (
            ("MLKEM", "MLKEM"),
            ("KYBER", "MLKEM"),
            ("MLDSA", "MLDSA"),
            ("DILITHIUM", "MLDSA"),
            ("SLHDSA", "SLHDSA"),
            ("SPHINCS", "SLHDSA"),
            ("FNDSA", "FALCON"),
            ("FALCON", "FALCON"),
            ("XMSS", "XMSS"),
            ("LMS", "LMS"),
            ("ED25519", "ED25519"),
            ("EDDSA", "ED25519"),
            ("ED448", "ED448"),
            ("X25519", "X25519"),
            ("CURVE25519", "X25519"),
            ("X448", "X448"),
            ("CURVE448", "X448"),
            ("FFDHE", "DH"),
            ("CHACHA20", "CHACHA20"),
            ("POLY1305", "CHACHA20"),
            ("XSALSA20", "SALSA20"),
            ("SALSA20", "SALSA20"),
            ("BLOWFISH", "BLOWFISH"),
            ("PBKDF2", "PBKDF2"),
            ("SCRYPT", "SCRYPT"),
            ("ARGON2", "ARGON2"),
            ("HMAC", "HMAC"),
            ("SHA3", "SHA3"),
            ("SHA1", "SHA1"),
            ("SHA256", "SHA256"),
            ("SHA384", "SHA384"),
            ("SHA512", "SHA512"),
            ("MD5", "MD5"),
            ("MGF1", "MGF1"),
            ("3DES", "3DES"),
            ("TRIPLEDES", "3DES"),
            ("ECDSA", "ECDSA"),
            ("ECDH", "ECDH"),
            # A curve name says which curve, not what the key does. It implies
            # ECDSA unless the name also says ECDH; see _CURVE.
            ("SECP", _CURVE),
            ("PRIME256V1", _CURVE),
            ("NISTP", _CURVE),
            ("RSASSA", "RSA"),
            ("RSA", "RSA"),
            ("AES", "AES"),
            ("TLS", "TLS"),
            # Anchored: "OpenSSL" does not claim SSL.
            ("SSL", "SSL"),
            ("DSA", "DSA"),
        ),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )
)

#: Prefixes that make a DSA match part of a longer family name: ML-DSA, SLH-DSA
#: and FN-DSA end in DSA but are not DSA. The DSA family is claimed only by DSA
#: itself.
_DSA_PREFIXES = ("ML", "SLH", "FN")

#: Curve names imply the ECDSA/EC family even when it is never spelled out.
_CURVE_TOKENS = frozenset({"P256", "P384", "P521", "P256K1", "SECP256R1", "PRIME256V1"})


def _marker_matches(squashed: str, token_starts: frozenset[int], marker: str) -> bool:
    """Report whether ``marker`` occurs in ``squashed`` at a token boundary.

    ``squashed`` has its separators removed, so ``ML-KEM-768``, ``MLKEM768`` and
    ``ml_kem_768`` all find MLKEM; the token boundaries are passed in
    ``token_starts``. Two conditions apply:

    * The match begins at a token start, or immediately after a digit
      (``x25519mlkem768``). "universal-hash" does not contain RSA, "Caesar"
      does not contain AES, and ECDSA does not contain DSA.
    * A marker ending in a digit is not followed by another digit, so SHA3 is
      not found inside SHA-384. MLKEM may be followed by 768.
    """
    index = squashed.find(marker)
    while index != -1:
        at_boundary = index in token_starts or squashed[index - 1].isdigit()
        if marker == "DSA" and any(squashed[:index].endswith(prefix) for prefix in _DSA_PREFIXES):
            at_boundary = False
        if at_boundary and marker[-1].isdigit():
            after = index + len(marker)
            if after < len(squashed) and squashed[after].isdigit():
                at_boundary = False
        if at_boundary:
            return True
        index = squashed.find(marker, index + 1)
    return False


def _clean(name: str) -> str:
    # Text after "@" ("key@50ece37a-...", "foo.gpg@sha256:...") is dropped.
    # "/" is an ordinary separator ("AES/GCM/NoPadding").
    #
    # Four spellings are then rewritten before any token is read: a combined
    # signature name becomes its digest and its scheme, a JOSE name becomes its
    # algorithm, a hybrid group becomes its two halves, and "P-384" becomes the
    # curve token "P384".
    cleaned = name.upper().strip().split("@", 1)[0]
    cleaned = _COMBINED_SIGNATURE.sub(
        lambda m: f"{m.group(1)} {_COMBINED_SCHEME.get(m.group(2), m.group(2))}", cleaned
    )
    cleaned = _JOSE_PATTERN.sub(lambda m: _JOSE_LOOKUP[re.sub(r"[^A-Z0-9]", "", m.group(1))], cleaned)
    cleaned = _HYBRID_PATTERN.sub(
        lambda m: " {} + {} ".format(*_HYBRID_LOOKUP[re.sub(r"[^A-Z0-9]", "", m.group(1))]).upper(),
        cleaned,
    )
    return _NIST_CURVE.sub(lambda m: "P" + m.group(1), cleaned)


def normalize_tokens(name: str) -> frozenset[str]:
    """Reduce an algorithm name to a comparable token set.

    Separators carry no meaning: ``SHA-256``, ``SHA256`` and ``sha_256`` all
    reduce to the same set, and so do ``ML-KEM-768`` and ``MLKEM768``.
    """
    if not name:
        return frozenset()

    upper = _clean(name)
    parts = [part for part in _SPLIT.split(upper) if part]
    squashed = "".join(parts)
    if not squashed:
        return frozenset()

    # Where each token begins in the separator-stripped name.
    token_starts: set[int] = set()
    offset = 0
    for part in parts:
        token_starts.add(offset)
        offset += len(part)
    frozen_starts = frozenset(token_starts)

    tokens: set[str] = set()

    for marker, family in _FAMILY_MARKERS:
        if _marker_matches(squashed, frozen_starts, marker):
            tokens.add(family)

    # Every token but stopwords and bare numbers. Used below for the
    # _WHOLE_TOKEN_ONLY families.
    significant = {
        _TOKEN_ALIASES.get(part, part)
        for part in parts
        if part not in _STOPWORDS and not part.isdigit()
    }

    for position, part in enumerate(parts):
        if part in _STOPWORDS:
            continue
        if part == "DSA" and position and parts[position - 1] in _DSA_PREFIXES:
            # The tail of ML-DSA, SLH-DSA or FN-DSA, not the DSA family.
            continue
        part = _TOKEN_ALIASES.get(part, part)
        if part in _STOPWORDS:
            continue
        if part in _WHOLE_TOKEN_ONLY:
            remainder = significant - {part}
            if not remainder <= _CIPHER_QUALIFIERS:
                # "seed_material", "random seed": not an algorithm name.
                continue
        tokens.add(part)
        match = _TRAILING_DIGITS.match(part)
        if match:
            stem, digits = match.groups()
            stem = _TOKEN_ALIASES.get(stem, stem)
            if stem not in _STOPWORDS:
                tokens.add(stem)
            tokens.add(digits)

    names_a_curve = bool(tokens & _CURVE_TOKENS) or _CURVE in tokens
    tokens.discard(_CURVE)
    if tokens & _EC_USES:
        tokens.discard("EC")
    elif names_a_curve:
        tokens.add("EC")

    return frozenset(tokens)


def families(tokens: frozenset[str]) -> frozenset[str]:
    """Return the family tokens present in a token set."""
    return frozenset(token for token in tokens if token in _FAMILIES)


#: Numbers treated as key, curve or digest sizes. Only these are parameters
#: that can contradict one another; the 8 in ``PKCS#8`` and the 12 in
#: ``PKCS#12`` are not.
CRYPTO_SIZES = frozenset(
    {
        "112", "128", "160", "192", "224", "233", "256", "283", "320", "384",
        "409", "448", "512", "521", "571", "768", "1024", "1536", "2048",
        "3072", "4096", "6144", "7680", "8192", "15360",
        # ML-KEM / ML-DSA parameter set identifiers.
        "44", "65", "87",
    }
)


def parameters(name: str) -> frozenset[str]:
    """Return the size-like numeric parameters in a name.

    Digits outside ``CRYPTO_SIZES`` are ignored.
    """
    found = _DIGITS.findall(_NON_ALNUM.sub("", _clean(name)))
    return frozenset(digit for digit in found if digit in CRYPTO_SIZES)


def algorithms_compatible(planted: str, reported: str) -> bool:
    """Report whether a reported algorithm name is credible for a planted one.

    Compatible when the two share a family and do not contradict each other on
    a parameter. A less specific report is accepted (``AES`` against a planted
    ``AES-256-GCM``). A different family is never accepted, and neither is the
    same family carrying a conflicting size.

    A hybrid key-exchange plant is credited only by a report naming a hybrid
    whose halves are each compatible with the plant's; one name stating a single
    half is not a report of the hybrid (``score_cbom`` credits two halves
    named in the plant's file). A hybrid report credits a plain plant matching
    either of its halves.
    """
    planted_halves = hybrid_halves(planted)
    reported_halves = hybrid_halves(reported)
    if planted_halves:
        if not reported_halves:
            return False
        return all(
            _single_compatible(left, right)
            for left, right in zip(planted_halves, reported_halves, strict=True)
        )
    if reported_halves:
        return any(_single_compatible(planted, half) for half in reported_halves)
    return _single_compatible(planted, reported)


def _settle_ec(own: frozenset[str], other: frozenset[str]) -> frozenset[str]:
    """Read an unstated elliptic-curve use as the use the other name states.

    A bare curve or "EC" takes the other side's use, so the parameter check
    still compares curves. A name that states a use keeps it.
    """
    if "EC" not in own:
        return own
    return (own - {"EC"}) | (other & _EC_USES or {"EC"})


def _single_compatible(planted: str, reported: str) -> bool:
    planted_tokens = normalize_tokens(planted)
    reported_tokens = normalize_tokens(reported)
    if not planted_tokens or not reported_tokens:
        return False

    planted_families = families(planted_tokens)
    reported_families = families(reported_tokens)
    planted_families, reported_families = (
        _settle_ec(planted_families, reported_families),
        _settle_ec(reported_families, planted_families),
    )

    # Where either name states a family, a bare number belongs to that family and
    # identifies nothing on its own: a familyless name is not credited by another
    # family sharing its number, nor credits one. Between two familyless names a
    # shared number may be all there is (``PKCS#12`` and ``node.p12``).
    shared = planted_tokens & reported_tokens
    if planted_families or reported_families:
        shared = {token for token in shared if not token.isdigit()}

    if planted_families and reported_families:
        if not (planted_families & reported_families):
            return False
    elif not shared:
        return False
    elif planted_families and not shared - _CIPHER_QUALIFIERS:
        # A report naming no family that shares only a mode with the plant
        # (GCM against AES-256-GCM) is not compatible.
        return False

    # Same family with different sizes is a contradiction: AES-128-GCM does
    # not match a planted AES-256-GCM. Applied only when the family sets agree,
    # so SHA256withRSA does not contradict a planted RSA-2048.
    if planted_families and planted_families == reported_families:
        planted_parameters = parameters(planted)
        reported_parameters = parameters(reported)
        if planted_parameters and reported_parameters and not (planted_parameters & reported_parameters):
            return False

    return True


def normalize_path(path: str) -> str:
    """Normalise a reported path to forward slashes with no leading './'."""
    cleaned = path.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


@dataclass
class PathResolver:
    """Maps reported paths onto the project's real files.

    A reported path may be absolute, relative to the project root, or relative
    to a subdirectory. The longest matching suffix that names exactly one file
    wins; an unresolvable path resolves to ``None``.
    """

    project_files: frozenset[str]
    _by_suffix: dict[str, list[str]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        for path in self.project_files:
            parts = path.split("/")
            for index in range(len(parts)):
                suffix = "/".join(parts[index:])
                self._by_suffix.setdefault(suffix, []).append(path)

    def resolve(self, reported: str) -> str | None:
        """Return the project file a reported path refers to, if any."""
        cleaned = normalize_path(reported)
        if not cleaned:
            return None
        if cleaned in self.project_files:
            return cleaned

        parts = cleaned.split("/")
        # Longest suffix first, so a/b/c.go beats c.go when both would match.
        for index in range(len(parts)):
            suffix = "/".join(parts[index:])
            candidates = self._by_suffix.get(suffix)
            if candidates and len(candidates) == 1:
                return candidates[0]
            if candidates:
                # Ambiguous suffix (same basename in several directories) is not
                # a resolution; keep widening.
                continue
        return None


def location_matches(
    planted_file: str,
    planted_line: int,
    reported_file: str | None,
    reported_line: int | None,
    *,
    line_tolerance: int,
) -> bool:
    """Same file, and lines within ``line_tolerance``. Reported, not scored."""
    if reported_file is None or reported_line is None:
        return False
    if reported_file != planted_file:
        return False
    return abs(reported_line - planted_line) <= line_tolerance
