# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Bounded reads for benchmark files and subprocess pipes."""

from io import BytesIO
from typing import BinaryIO


def read_limited(stream: BinaryIO, limit: int) -> bytes:
    """Read through EOF or limit without reserving the full limit upfront."""
    output = BytesIO()
    while output.tell() < limit:
        chunk = stream.read(min(64 * 1024, limit - output.tell()))
        if not chunk:
            break
        output.write(chunk)
    return output.getvalue()
