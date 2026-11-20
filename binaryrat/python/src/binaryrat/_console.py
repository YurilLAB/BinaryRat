"""Console output that cannot fail on a character the stream cannot encode.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import sys


def tolerant_output() -> None:
    """Escape text the console or a redirected file cannot encode instead of raising.

    A redirected stream on Windows uses the ANSI code page, while decompiled C and symbol
    names can hold any character; an encoding error would end the output halfway.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
