import ipaddress
import json
import subprocess
import unittest
from unittest.mock import patch

import netscan


class NetscanTests(unittest.TestCase):
    def test_ipv4_forms(self):
        for value in ["192.0.2", "192.0.2.45", "192.0.2.45/24"]:
            self.assertEqual(str(netscan.parse_network(value)), "192.0.2.0/24")

    def test_ipv6_rejected(self):
        with self.assertRaises(ValueError):
            netscan.parse_network("::1/128")

    def test_noncontiguous_mask_rejected(self):
        with self.assertRaises(ValueError):
            netscan.mask_to_cidr("255.0.255.0")

    def test_large_scan_rejected_before_any_ping(self):
        with patch.object(netscan, "ping") as ping, patch(
            "concurrent.futures.ThreadPoolExecutor", side_effect=AssertionError("must reject before allocation")
        ):
            with self.assertRaises(ValueError):
                netscan.scan_network(ipaddress.ip_network("10.0.0.0/8"))
            ping.assert_not_called()

    def test_failed_ping_with_ttl_text_is_not_online(self):
        result = subprocess.CompletedProcess([], 1, "TTL expired in transit", "")
        with patch("subprocess.run", return_value=result):
            self.assertIsNone(netscan.ping("192.0.2.1"))

    def test_successful_ping_and_timeout(self):
        result = subprocess.CompletedProcess([], 0, "64 bytes ttl=64", "")
        with patch("subprocess.run", return_value=result):
            self.assertEqual(netscan.ping("192.0.2.1"), "192.0.2.1")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ping", 2)):
            self.assertIsNone(netscan.ping("192.0.2.1"))

    def test_small_scan_returns_only_live_hosts(self):
        with patch.object(netscan, "ping", side_effect=lambda ip: str(ip) if str(ip).endswith("1") else None):
            self.assertEqual(netscan.scan_network(ipaddress.ip_network("192.0.2.0/30")), ["192.0.2.1"])

    def test_linux_discovery_uses_real_prefix_and_skips_loopback(self):
        config = [{"addr_info": [{"family": "inet", "scope": "host", "local": "127.0.0.1", "prefixlen": 8}]},
                  {"addr_info": [{"family": "inet", "scope": "global", "local": "192.0.2.5", "prefixlen": 28}]}]
        with patch("platform.system", return_value="Linux"), patch("subprocess.check_output", return_value=json.dumps(config)):
            self.assertEqual(netscan.get_local_ip_and_mask(), ("192.0.2.5", "255.255.255.240"))

    def test_windows_discovery_keeps_address_and_mask_in_same_adapter(self):
        config = "Ethernet adapter Disabled:\n   IPv4 Address. . . . . . : 192.0.2.1\nWireless LAN adapter Wi-Fi:\n   IPv4 Address. . . . . . : 198.51.100.5\n   Subnet Mask . . . . . . : 255.255.255.240\n"
        with patch("platform.system", return_value="Windows"), patch("subprocess.check_output", return_value=config):
            self.assertEqual(netscan.get_local_ip_and_mask(), ("198.51.100.5", "255.255.255.240"))

    def test_missing_interface_commands_require_explicit_subnet(self):
        with patch("platform.system", return_value="Linux"), patch("subprocess.check_output", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(ValueError, "Supply it explicitly"):
                netscan.get_local_ip_and_mask()

    def test_macos_uses_milliseconds_for_ping_timeout(self):
        result = subprocess.CompletedProcess([], 0, "ttl=64", "")
        with patch("platform.system", return_value="Darwin"), patch("subprocess.run", return_value=result) as run:
            netscan.ping("192.0.2.1")
            self.assertEqual(run.call_args.args[0], ["ping", "-c", "1", "-W", "1000", "192.0.2.1"])

    def test_interrupt_cancels_queued_pings(self):
        with patch("concurrent.futures.ThreadPoolExecutor") as pool, patch("concurrent.futures.as_completed", side_effect=KeyboardInterrupt):
            netscan.scan_network(ipaddress.ip_network("192.0.2.0/30"))
            pool.return_value.shutdown.assert_called_once_with(wait=True, cancel_futures=True)

    def test_cli_errors_have_nonzero_exit_status(self):
        self.assertEqual(netscan.main(["invalid"]), 1)
        self.assertEqual(netscan.main(["10.0.0.0/8"]), 1)


if __name__ == "__main__":
    unittest.main()
