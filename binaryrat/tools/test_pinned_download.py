"""Retries, hash pinning and partial-file handling of pinned downloads.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""
import hashlib
import http.client
import io
from pathlib import Path
import tempfile
import unittest
import urllib.error

import pinned_download


PAYLOAD = b"pinned payload\n" * 1000
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class Opener:
    """Replays one outcome per call: bytes to serve, or an exception to raise."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(self, url, timeout):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return io.BytesIO(outcome)


class Truncated(io.BytesIO):
    def read(self, size=-1):
        data = super().read(size)
        if not data:
            raise http.client.IncompleteRead(b"")
        return data


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.target = Path(self.directory.name) / "nested" / "file.bin"
        self.waits = []

    def fetch(self, opener, **options):
        return pinned_download.fetch("https://example.invalid/file.bin", self.target, DIGEST,
                                     opener=opener, sleep=self.waits.append, **options)

    def test_reset_connection_is_retried_with_growing_waits(self):
        opener = Opener(ConnectionResetError("reset"), TimeoutError("slow"), PAYLOAD)
        self.assertEqual(self.fetch(opener), self.target)
        self.assertEqual(self.target.read_bytes(), PAYLOAD)
        self.assertEqual(opener.calls, 3)
        self.assertEqual(self.waits, [5.0, 15.0])

    def test_truncated_transfer_is_retried_and_never_kept(self):
        calls = []

        def replay(url, timeout):
            calls.append(url)
            return Truncated(PAYLOAD[:100]) if len(calls) == 1 else io.BytesIO(PAYLOAD)

        self.fetch(replay)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.target.read_bytes(), PAYLOAD)
        self.assertFalse(self.target.with_name("file.bin.part").exists())

    def test_short_body_without_an_error_fails_the_hash_and_is_retried(self):
        opener = Opener(PAYLOAD[:-1], PAYLOAD)
        self.fetch(opener)
        self.assertEqual(opener.calls, 2)
        self.assertEqual(self.target.read_bytes(), PAYLOAD)

    def test_wrong_content_fails_after_every_attempt_and_leaves_nothing(self):
        opener = Opener(b"tampered", b"tampered", b"tampered")
        with self.assertRaisesRegex(pinned_download.DownloadError, "SHA-256 mismatch"):
            self.fetch(opener, attempts=3)
        self.assertEqual(opener.calls, 3)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.target.with_name("file.bin.part").exists())

    def test_missing_file_is_not_retried(self):
        missing = urllib.error.HTTPError("https://example.invalid", 404, "Not Found", {}, None)
        opener = Opener(missing, PAYLOAD)
        with self.assertRaisesRegex(pinned_download.DownloadError, "404"):
            self.fetch(opener)
        self.assertEqual(opener.calls, 1)
        self.assertEqual(self.waits, [])

    def test_rate_limit_and_server_errors_are_retried(self):
        limited = urllib.error.HTTPError("https://example.invalid", 429, "Too Many", {}, None)
        broken = urllib.error.HTTPError("https://example.invalid", 503, "Unavailable", {}, None)
        opener = Opener(limited, broken, PAYLOAD)
        self.fetch(opener)
        self.assertEqual(opener.calls, 3)

    def test_matching_file_is_reused_without_a_request(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(PAYLOAD)
        opener = Opener()
        self.fetch(opener)
        self.assertEqual(opener.calls, 0)

    def test_stale_file_is_replaced(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"older release")
        self.fetch(Opener(PAYLOAD))
        self.assertEqual(self.target.read_bytes(), PAYLOAD)

    def test_malformed_pin_is_rejected_before_any_request(self):
        opener = Opener(PAYLOAD)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            pinned_download.fetch("https://example.invalid", self.target, "abc", opener=opener)
        self.assertEqual(opener.calls, 0)


if __name__ == "__main__":
    unittest.main()
