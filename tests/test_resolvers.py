"""Unit tests for the MX2 DNS & DID Resolver Engines."""

import unittest

from src.did_resolver import DIDCache, MX2DIDResolver
from src.dns_resolver import MX2DNSResolver


class TestMX2Resolvers(unittest.TestCase):
    """Test suite for MX2DNSResolver and MX2DIDResolver classes."""

    def setUp(self) -> None:
        """Sets up resolver instances."""
        self.dns_resolver = MX2DNSResolver(dnssec_strict=False)
        self.did_resolver = MX2DIDResolver(ttl_seconds=300)

    def test_dns_domain_key_resolution(self) -> None:
        """Tests TXT key resolution for reputable domains."""
        res = self.dns_resolver.resolve_domain_key("trusted.nl")
        self.assertIsNotNone(res)
        self.assertEqual(res["algorithm"], "Ed25519")
        self.assertEqual(res["publicKey"], "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327")

        # Unknown domain returns None in sandbox fallback
        res_unknown = self.dns_resolver.resolve_domain_key("unknown-nonexistent-domain.xyz")
        self.assertIsNone(res_unknown)

    def test_dns_gateway_srv_resolution(self) -> None:
        """Tests SRV gateway endpoint discovery."""
        srv = self.dns_resolver.resolve_gateway_srv("example.com")
        self.assertIsNotNone(srv)
        self.assertEqual(srv["target"], "mx2.example.com")
        self.assertEqual(srv["port"], 443)

    def test_did_mx2_resolution(self) -> None:
        """Tests resolving did:mx2 identifiers into W3C DID Documents."""
        did = "did:mx2:MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"
        doc = self.did_resolver.resolve(did)

        self.assertIsNotNone(doc)
        self.assertEqual(doc["id"], did)
        self.assertEqual(len(doc["verificationMethod"]), 1)
        self.assertEqual(
            doc["verificationMethod"][0]["publicKeyBase64"], "MCowBQYDK2VwAyEAdS+7fGZ8A1839gBbcD81hS9bV2g327"
        )

    def test_did_cache(self) -> None:
        """Tests in-memory TTL caching for DID resolution."""
        cache = DIDCache(ttl_seconds=10)
        did = "did:mx2:test_key_123"
        doc = {"id": did}

        cache.set(did, doc)
        self.assertEqual(cache.get(did), doc)

        cache.clear()
        self.assertIsNone(cache.get(did))


if __name__ == "__main__":
    unittest.main()
