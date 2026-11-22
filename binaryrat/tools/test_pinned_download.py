"""Retries, hash pinning and partial-file handling of pinned downloads.

SPDX-License-Identifier: Apache-2.0
Copyright 2026 YurilLAB. New BinaryRat tests.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import io
from pathlib import Path
import tempfile
from threading import Event, current_thread
import unittest
from unittest.mock import patch
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
        self.assertEqual(set(self.target.parent.iterdir()), {self.target})

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
        self.assertEqual(list(self.target.parent.iterdir()), [])

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

    def test_concurrent_interrupted_request_cannot_replace_verified_bytes(self):
        payload = PAYLOAD * 80
        digest = hashlib.sha256(payload).hexdigest()
        verified = Event()
        started_second_transfer = Event()
        first_returned = Event()
        first_thread = None
        replace = Path.replace

        class InterruptedTransfer(io.BytesIO):
            def read(self, size=-1):
                data = super().read(size)
                if data:
                    return data
                started_second_transfer.set()
                if not first_returned.wait(5):
                    raise AssertionError("first transfer did not return")
                raise ConnectionResetError("simulated interrupted transfer")

        def fetch(opener):
            return pinned_download.fetch("https://example.invalid/file.bin", self.target, digest,
                                         opener=opener, attempts=1)

        def first():
            nonlocal first_thread
            first_thread = current_thread()
            try:
                return fetch(Opener(payload)).read_bytes()
            finally:
                first_returned.set()

        def publish(source, destination):
            if current_thread() is first_thread:
                verified.set()
                if not started_second_transfer.wait(5):
                    raise AssertionError("second transfer did not start")
            return replace(source, destination)

        with patch.object(Path, "replace", publish), ThreadPoolExecutor(max_workers=2) as threads:
            completed = threads.submit(first)
            self.assertTrue(verified.wait(5))
            interrupted = threads.submit(fetch, lambda *_args, **_options:
                                         InterruptedTransfer(payload[:640 * 1024]))
            with self.assertRaisesRegex(pinned_download.DownloadError, "interrupted transfer"):
                interrupted.result(timeout=10)
            self.assertEqual(completed.result(timeout=10), payload)

        self.assertEqual(self.target.read_bytes(), payload)
        self.assertEqual(set(self.target.parent.iterdir()), {self.target})

    def test_malformed_pin_is_rejected_before_any_request(self):
        opener = Opener(PAYLOAD)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            pinned_download.fetch("https://example.invalid", self.target, "abc", opener=opener)
        self.assertEqual(opener.calls, 0)


if __name__ == "__main__":
    unittest.main()
