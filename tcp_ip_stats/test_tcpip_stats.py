#!/usr/bin/env python3

import ctypes
import csv
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import tcpip_stats


def make_key(src_ip, src_port):
    key = tcpip_stats.FlowKey()
    key.src_ip = src_ip
    key.dst_ip = 0x0200000A
    key.src_port = src_port
    key.dst_port = 80
    key.protocol = 6
    return key


def make_percpu_values(packets, byte_count=0, syn=0, ack=0):
    values = tcpip_stats.StatsArray()
    values[0].packets = packets
    values[0].bytes = byte_count
    values[0].syn = syn
    values[0].ack = ack
    return values


class TcpIpStatsSnapshotTests(unittest.TestCase):
    def collect(
        self,
        keys,
        values_by_key,
        previous=None,
        previous_syn_ips=None,
    ):
        previous = previous or {}
        previous_syn_ips = previous_syn_ips or set()

        def lookup(_map_fd, key):
            return values_by_key[bytes(key)]

        with patch.object(tcpip_stats, "iterate_keys", return_value=keys), patch.object(
            tcpip_stats, "lookup_percpu", side_effect=lookup
        ):
            return tcpip_stats.collect_snapshot(
                1,
                previous,
                previous_syn_ips,
                set(),
            )

    def test_active_source_ip_is_deduplicated_within_interval(self):
        first = make_key(0x0100000A, 10001)
        second = make_key(0x0100000A, 10002)
        values = {
            bytes(first): make_percpu_values(2),
            bytes(second): make_percpu_values(3),
        }

        interval, _, _, _ = self.collect([first, second], values)

        self.assertEqual(interval["tcp_packets"], 5)
        self.assertEqual(interval["active_source_ips"], 1)

    def test_only_sources_with_new_packets_are_active(self):
        active = make_key(0x0100000A, 10001)
        inactive = make_key(0x0200000A, 10002)
        previous = {
            bytes(active): (4, 100, 0, 0),
            bytes(inactive): (7, 200, 0, 0),
        }
        values = {
            bytes(active): make_percpu_values(5, 120),
            bytes(inactive): make_percpu_values(7, 200),
        }

        interval, _, _, _ = self.collect([active, inactive], values, previous)

        self.assertEqual(interval["tcp_packets"], 1)
        self.assertEqual(interval["active_source_ips"], 1)

    def test_same_source_is_counted_again_in_next_interval(self):
        key = make_key(0x0100000A, 10001)
        first_values = {bytes(key): make_percpu_values(1)}
        first_interval, first_snapshot, _, _ = self.collect([key], first_values)

        second_values = {bytes(key): make_percpu_values(2)}
        second_interval, _, _, _ = self.collect(
            [key], second_values, first_snapshot
        )

        self.assertEqual(first_interval["active_source_ips"], 1)
        self.assertEqual(second_interval["active_source_ips"], 1)

    def test_distinct_pure_syn_tuples_from_same_source_are_counted(self):
        first = make_key(0x0100000A, 10001)
        second = make_key(0x0100000A, 10002)
        values = {
            bytes(first): make_percpu_values(1, syn=1),
            bytes(second): make_percpu_values(1, syn=1),
        }

        interval, _, _, _ = self.collect([first, second], values)

        self.assertEqual(interval["syn_only_packets"], 2)
        self.assertEqual(interval["syn_source_ips"], 1)
        self.assertEqual(interval["syn_flows"], 2)

    def test_pure_syn_retransmissions_share_one_tuple(self):
        key = make_key(0x0100000A, 10001)
        values = {bytes(key): make_percpu_values(3, syn=3)}

        interval, _, _, _ = self.collect([key], values)

        self.assertEqual(interval["syn_only_packets"], 3)
        self.assertEqual(interval["syn_source_ips"], 1)
        self.assertEqual(interval["syn_flows"], 1)

    def test_old_syn_without_a_new_syn_is_not_counted_as_a_tuple(self):
        key = make_key(0x0100000A, 10001)
        previous = {bytes(key): (1, 60, 1, 0)}
        values = {bytes(key): make_percpu_values(2, 120, syn=1)}

        interval, _, _, _ = self.collect([key], values, previous)

        self.assertEqual(interval["tcp_packets"], 1)
        self.assertEqual(interval["syn_only_packets"], 0)
        self.assertEqual(interval["syn_source_ips"], 0)
        self.assertEqual(interval["syn_flows"], 0)

    def test_same_tuple_is_counted_again_when_syn_increases_next_interval(self):
        key = make_key(0x0100000A, 10001)
        first_values = {bytes(key): make_percpu_values(1, syn=1)}
        first_interval, first_snapshot, _, _ = self.collect([key], first_values)

        second_values = {bytes(key): make_percpu_values(2, syn=2)}
        second_interval, _, _, _ = self.collect(
            [key],
            second_values,
            first_snapshot,
            previous_syn_ips={key.src_ip},
        )

        self.assertEqual(first_interval["syn_flows"], 1)
        self.assertEqual(second_interval["syn_flows"], 1)
        self.assertEqual(first_interval["syn_source_ips"], 1)
        self.assertEqual(second_interval["syn_source_ips"], 1)

    def test_new_tuple_from_a_previously_seen_source_is_counted(self):
        old_key = make_key(0x0100000A, 10001)
        new_key = make_key(0x0100000A, 10002)
        previous = {bytes(old_key): (1, 60, 1, 0)}
        values = {
            bytes(old_key): make_percpu_values(1, 60, syn=1),
            bytes(new_key): make_percpu_values(1, 60, syn=1),
        }

        interval, _, _, _ = self.collect(
            [old_key, new_key],
            values,
            previous,
            previous_syn_ips={old_key.src_ip},
        )

        self.assertEqual(interval["syn_flows"], 1)
        self.assertEqual(interval["syn_source_ips"], 1)

    def test_distinct_pure_syn_sources_are_counted_in_current_interval(self):
        first = make_key(0x0100000A, 10001)
        second = make_key(0x0200000A, 10002)
        values = {
            bytes(first): make_percpu_values(1, syn=1),
            bytes(second): make_percpu_values(1, syn=1),
        }

        interval, _, _, _ = self.collect([first, second], values)

        self.assertEqual(interval["syn_source_ips"], 2)
        self.assertEqual(interval["syn_flows"], 2)

    def test_syn_ack_is_not_counted_as_a_pure_syn_source_or_tuple(self):
        key = make_key(0x0100000A, 10001)
        values = {bytes(key): make_percpu_values(1, syn=1, ack=1)}

        interval, _, _, _ = self.collect([key], values)

        self.assertEqual(interval["syn_only_packets"], 0)
        self.assertEqual(interval["syn_ack_packets"], 1)
        self.assertEqual(interval["syn_source_ips"], 0)
        self.assertEqual(interval["syn_flows"], 0)

    def test_csv_writer_rejects_an_old_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stats.csv"
            with path.open("w", newline="", encoding="utf-8") as output:
                csv.writer(output).writerow(["timestamp", "tcp_packets"])

            with ExitStack() as stack:
                with self.assertRaisesRegex(ValueError, "CSV 欄位格式已更新"):
                    tcpip_stats.open_csv_writer(
                        stack, path, tcpip_stats.STATS_CSV_FIELDS
                    )


if __name__ == "__main__":
    unittest.main()
