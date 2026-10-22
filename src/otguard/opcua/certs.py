"""Self-signed certificates for the OPC UA experiment.

Two of the three security modes under test need certificates on both ends, and
a third certificate for the guard, which is a client in its own right. These
are generated on first use into a cache directory and reused after that, so a
repeat run does not spend seconds on RSA key generation.

Everything here is a test fixture. The certificates are self-signed, nobody
validates anybody's chain, and the guard's own certificate is generated beside
the ones it is inspecting. A deployment would have a real PKI and the guard
would hold a key issued by it; the point of this module is only to get a
SignAndEncrypt channel on the wire so the guard can be measured against one.

OPC UA is fussy about certificate contents in a way TLS is not: the
``ApplicationUri`` in an application's description has to appear as a URI entry
in the certificate's subject alternative name, or the handshake is rejected.
``setup_self_signed_certificate`` handles that, which is why this uses it rather
than driving ``cryptography`` directly.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

from cryptography.x509.oid import ExtendedKeyUsageOID

DEVICE_URI = "urn:otguard:opcua:device"
MASTER_URI = "urn:otguard:opcua:master"
GUARD_URI = "urn:otguard:opcua:guard"

_SUBJECT = {
    "countryName": "US",
    "stateOrProvinceName": "Georgia",
    "localityName": "Atlanta",
    "organizationName": "OTGuard",
}


@dataclass(frozen=True)
class CertPair:
    key: Path
    cert: Path

    @property
    def key_str(self) -> str:
        return str(self.key)

    @property
    def cert_str(self) -> str:
        return str(self.cert)


@dataclass(frozen=True)
class CertSet:
    device: CertPair
    master: CertPair
    guard: CertPair


_LOCK = asyncio.Lock()


async def ensure_certs(cache_dir: Path, host: str = "127.0.0.1") -> CertSet:
    """Generate the three certificate pairs if they are not already on disk."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    specs = (
        ("device", DEVICE_URI, [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
        ("master", MASTER_URI, [ExtendedKeyUsageOID.CLIENT_AUTH]),
        ("guard", GUARD_URI, [ExtendedKeyUsageOID.CLIENT_AUTH]),
    )
    pairs: dict[str, CertPair] = {}
    async with _LOCK:
        for name, uri, usage in specs:
            pair = CertPair(cache_dir / f"{name}-key.pem", cache_dir / f"{name}-cert.der")
            if not (pair.key.exists() and pair.cert.exists()):
                # Imported here so that importing this module does not pull in
                # asyncua, which is an optional dependency of the project.
                from asyncua.crypto.cert_gen import setup_self_signed_certificate

                await setup_self_signed_certificate(
                    pair.key, pair.cert, uri, host, usage, dict(_SUBJECT)
                )
            pairs[name] = pair
    return CertSet(device=pairs["device"], master=pairs["master"], guard=pairs["guard"])
