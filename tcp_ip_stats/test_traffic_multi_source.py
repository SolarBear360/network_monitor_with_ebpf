#!/usr/bin/env python3

import unittest

from traffic_test.allocate_normal_source_ips import allocate_addresses
from traffic_test.normal_http_keepalive import parse_source_ips as parse_keepalive_ips
from traffic_test.normal_tcp_connections import parse_source_ips as parse_connection_ips


class MultiSourceTrafficTests(unittest.TestCase):
    def test_allocator_uses_free_high_addresses(self):
        self.assertEqual(
            allocate_addresses(
                "172.30.0.0/24",
                5,
                ["172.30.0.1", "172.30.0.253"],
            ),
            [
                "172.30.0.249",
                "172.30.0.250",
                "172.30.0.251",
                "172.30.0.252",
                "172.30.0.254",
            ],
        )

    def test_allocator_rejects_public_network(self):
        with self.assertRaises(ValueError):
            allocate_addresses("8.8.8.0/24", 5)

    def test_connection_source_ips_are_normalized(self):
        self.assertEqual(
            parse_connection_ips("172.30.0.100, 172.30.0.101"),
            ["172.30.0.100", "172.30.0.101"],
        )

    def test_keepalive_rejects_duplicate_source_ip(self):
        with self.assertRaises(ValueError):
            parse_keepalive_ips("172.30.0.100,172.30.0.100")


if __name__ == "__main__":
    unittest.main()
