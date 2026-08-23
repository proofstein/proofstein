# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
"""Deciding whether a reported asset is the planted one.

The rule the benchmark is built around: **a detection requires agreement on
file and line. An algorithm name alone is never a detection.** A generator that
emits ``{"name": "AES-256-GCM"}`` with no evidence has said nothing that can be
checked, and a corpus that rewarded it would reward guessing -- every project
here contains AES-GCM, so "AES-GCM is present" is free.

Two normalisations are deliberately generous, because the alternative is
measuring a generator's naming and path conventions rather than its detection:

* **Algorithm names** are compared as token sets, and a less specific report
  matches a more specific plant (``AES`` matches a planted ``AES-256-GCM``).
  The reverse does not hold, and a different family never matches.
* **File paths** are resolved by longest matching suffix against the real file
  list of the project, so a generator that reports absolute paths from a
  temporary clone directory is not punished for it.

Both are applied to every tool identically and both are recorded in the output
so a reader can see how much work they are doing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Lines may differ by this much and still match. Generators disagree about
#: whether a multi-line statement is reported at its first or last line.
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
    "MLKEM": "MLKEM",
    "KYBER": "MLKEM",
    "MLDSA": "MLDSA",
    "DILITHIUM": "MLDSA",
    "SHA2": "SHA256",
    "SHA256WITHRSA": "RSA",
    "RSASSA": "RSA",
    "RSAPSS": "RSA",
    "PSS": "RSA",
    "PKCS1": "RSA",
    "OAEP": "RSA",
    "RS256": "RSA",
    "ES256": "ECDSA",
    "EC": "ECDSA",
    "ECDH": "ECDSA",
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
        # Narration. Generators describe a finding as well as naming it, and
        # "AES block cipher in use" is the same claim as "AES".
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

#: Family token -> the tokens that may only ever match inside that family. Two
#: names sharing no family never match, which is what stops "RSA" from being
#: credited against a planted "AES-256-GCM".
_FAMILIES = (
    "AES",
    "RSA",
    "ECDSA",
    "ED25519",
    "X25519",
    "MLKEM",
    "MLDSA",
    "SHA1",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3",
    "MD5",
    "TLS",
    # A distinct family from TLS, not an older spelling of it. Without it a
    # report of SSLv3 carries no family at all, which has two consequences:
    # claiming SSLv3 in a project that has none cannot be charged, and the
    # compatibility check falls through to bare token overlap, where SSLv3 and
    # a planted TLSv1.3 match on the shared "3".
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
    "DSA",
    "DH",
    "MGF1",
    # Recognised as families so that reporting one where none exists can be
    # charged. Every name here is absent from _FAMILY_MARKERS on purpose: see
    # _WHOLE_TOKEN_ONLY below.
    "RC2",
    "RC4",
    "SEED",
    "IDEA",
    "CAST5",
    "CAMELLIA",
)

#: Families whose names are ordinary English words, or fall inside them.
#:
#: A family is normally found by looking for its marker inside the
#: separator-stripped name, which is what makes ``ML-KEM-768`` and ``MLKEM768``
#: the same thing. That search cannot be allowed anywhere near these: "seed"
#: appears in every CSPRNG identifier in the corpus, "idea" and "des" fall inside
#: ordinary prose, and a scorer that read them as algorithm claims would invent
#: findings no generator made.
#:
#: They are therefore matched only as a complete token, never inside one, which
#: is why none of them appears in _FAMILY_MARKERS. A whole token is still not
#: enough on its own -- ``seed_material`` splits into two tokens, one of which is
#: ``SEED`` -- so the rest of the name must read as an algorithm name too: every
#: other token must be a size, a mode qualifier, or narration. ``SEED``,
#: ``SEED-CBC`` and ``SEED-128-CBC`` claim the family; ``seedRandom``,
#: ``seed_material`` and ``random seed`` do not.
#:
#: The cost is that an unusual descriptive spelling would be missed, which is the
#: right way round: missing a weak-cipher report understates a tool, inventing
#: one accuses it.
_WHOLE_TOKEN_ONLY = frozenset({"DES", "RC2", "RC4", "SEED", "IDEA", "CAST5", "CAMELLIA"})

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
            ("ED25519", "ED25519"),
            ("EDDSA", "ED25519"),
            ("X25519", "X25519"),
            ("CURVE25519", "X25519"),
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
            ("ECDH", "ECDSA"),
            ("SECP", "ECDSA"),
            ("PRIME256V1", "ECDSA"),
            ("NISTP", "ECDSA"),
            ("RSASSA", "RSA"),
            ("RSA", "RSA"),
            ("AES", "AES"),
            ("TLS", "TLS"),
            # Anchoring is what makes this safe: "OpenSSL" is a library name
            # that generators report routinely, and SSL sits in the middle of it.
            ("SSL", "SSL"),
            ("DSA", "DSA"),
        ),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )
)

#: Curve names imply the ECDSA/EC family even when it is never spelled out.
_CURVE_TOKENS = frozenset({"P256", "P384", "P521", "P256K1", "SECP256R1", "PRIME256V1"})


def _marker_matches(squashed: str, token_starts: frozenset[int], marker: str) -> bool:
    """Report whether ``marker`` occurs in ``squashed`` at a token boundary.

    Separators are stripped before this runs, because hyphenation is a spelling
    choice: ``ML-KEM-768``, ``MLKEM768`` and ``ml_kem_768`` must all find MLKEM.
    Stripping them also removes the boundaries that tell an algorithm name from
    an English word, so the boundaries are carried alongside in ``token_starts``
    and re-imposed here.

    Two conditions, each pinned by a case that was live on real generator output:

    * The match must begin at a token start, or immediately after a digit.
      Without it "universal-hash" contains RSA, "Caesar" contains AES and every
      ECDSA report also claimed DSA. The digit exception is what keeps hybrid
      names working: ``x25519mlkem768`` juxtaposes two complete algorithm names
      with no separator between them.
    * A marker ending in a digit may not be followed by another digit, so SHA3
      is not found inside SHA-384. Markers not ending in a digit are exempt,
      because a trailing parameter is normal: MLKEM is followed by 768.
    """
    index = squashed.find(marker)
    while index != -1:
        at_boundary = index in token_starts or squashed[index - 1].isdigit()
        if at_boundary and marker[-1].isdigit():
            after = index + len(marker)
            if after < len(squashed) and squashed[after].isdigit():
                at_boundary = False
        if at_boundary:
            return True
        index = squashed.find(marker, index + 1)
    return False


def _clean(name: str) -> str:
    # "key@50ece37a-..." and "crypto/certificate/foo.gpg@sha256:..." carry an
    # opaque generator identifier after the "@"; drop it so a hex digest cannot
    # supply stray tokens.
    #
    # "/" is deliberately left alone and treated as an ordinary separator:
    # "AES/GCM/NoPadding" is the exact string Java's Cipher.getInstance takes,
    # and splitting on the last slash would reduce it to "NoPadding".
    return name.upper().strip().split("@", 1)[0]


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

    # Where each token began once the separators were removed. Family markers
    # are matched against the separator-stripped form so that hyphenation is
    # irrelevant; these offsets are what keeps that from matching mid-word.
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

    # The tokens a reader would have to account for to call this an algorithm
    # name: everything but stopwords and bare numbers. Used below to decide
    # whether a dictionary-word family name is being used as an algorithm.
    significant = {
        _TOKEN_ALIASES.get(part, part)
        for part in parts
        if part not in _STOPWORDS and not part.isdigit()
    }

    for part in parts:
        if part in _STOPWORDS:
            continue
        part = _TOKEN_ALIASES.get(part, part)
        if part in _STOPWORDS:
            continue
        if part in _WHOLE_TOKEN_ONLY:
            remainder = significant - {part}
            if not remainder <= _CIPHER_QUALIFIERS:
                # "seed_material", "random seed": the token is there, the name
                # is not an algorithm name.
                continue
        tokens.add(part)
        match = _TRAILING_DIGITS.match(part)
        if match:
            stem, digits = match.groups()
            stem = _TOKEN_ALIASES.get(stem, stem)
            if stem not in _STOPWORDS:
                tokens.add(stem)
            tokens.add(digits)

    if tokens & _CURVE_TOKENS:
        tokens.add("ECDSA")

    return frozenset(tokens)


def families(tokens: frozenset[str]) -> frozenset[str]:
    """Return the family tokens present in a token set."""
    return frozenset(token for token in tokens if token in _FAMILIES)


#: Numbers that plausibly denote a key, curve or digest size. Only these are
#: treated as parameters that can contradict one another.
#:
#: Without this restriction any digit in a name becomes a size claim, and
#: standard encoding names collide with real key sizes: the 8 in ``PKCS#8`` and
#: the 12 in ``PKCS#12`` are structure versions, not moduli. In scoring the 2026-07-28 run
#: that read "RSA private key (PKCS#8)" as contradicting a planted RSA-2048,
#: which both denied the generator a correct detection and charged it a false
#: positive for the same component.
CRYPTO_SIZES = frozenset(
    {
        "112", "128", "160", "192", "224", "233", "256", "283", "320", "384",
        "409", "448", "512", "521", "571", "768", "1024", "1536", "2048",
        "3072", "4096", "7680", "8192", "15360",
        # ML-KEM / ML-DSA parameter set identifiers.
        "44", "65", "87",
    }
)


def parameters(name: str) -> frozenset[str]:
    """Return the size-like numeric parameters in a name.

    Digits that are not plausible cryptographic sizes are ignored, because they
    are far more often part of a standard's name (PKCS#8, SEC1, X.509, SHA-3)
    than a statement about key length.
    """
    found = _DIGITS.findall(_NON_ALNUM.sub("", _clean(name)))
    return frozenset(digit for digit in found if digit in CRYPTO_SIZES)


def algorithms_compatible(planted: str, reported: str) -> bool:
    """Report whether a reported algorithm name is credible for a planted one.

    Compatible when the two share a family and do not contradict each other on
    a parameter. A less specific report is accepted -- ``AES`` is credited
    against a planted ``AES-256-GCM``, because the generator did find the right
    primitive. A different family is never accepted, and neither is the same
    family carrying a conflicting size.
    """
    planted_tokens = normalize_tokens(planted)
    reported_tokens = normalize_tokens(reported)
    if not planted_tokens or not reported_tokens:
        return False

    planted_families = families(planted_tokens)
    reported_families = families(reported_tokens)

    if planted_families and reported_families:
        if not (planted_families & reported_families):
            return False
    elif not (planted_tokens & reported_tokens):
        return False

    # Same family with different sizes is a contradiction, not a vaguer report:
    # a planted AES-256-GCM is not found by a report of AES-128-GCM. Only
    # applied when the family sets agree, so that a signature name such as
    # SHA256withRSA is not read as contradicting a planted RSA-2048.
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

    Generators run against a clone in a temporary directory and may report an
    absolute path, a path relative to the clone root, or a path relative to some
    subdirectory. The longest matching suffix wins; unresolvable paths stay as
    they are and are what the phantom-file check keys on.
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
    """File and line agreement, the primary detection rule."""
    if reported_file is None or reported_line is None:
        return False
    if reported_file != planted_file:
        return False
    return abs(reported_line - planted_line) <= line_tolerance
