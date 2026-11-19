#!/usr/bin/env python3
# Copyright 2026 YurilLAB
# SPDX-License-Identifier: Apache-2.0
"""Render BinaryRat's application icons and splash image from the README logo.

The committed images are this script's output. Run it again after the logo changes:

    python binaryrat/tools/make_branding.py

`--check` renders into memory and fails if a committed image differs in size, mode or
pixels by more than a rounding tolerance, so a stale image is caught without Pillow
producing byte-identical PNG files on every platform.
"""
from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path
import sys

try:
    from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont
except ImportError:  # test_make_branding.py reads the paths and sizes without Pillow.
    Image = ImageChops = ImageDraw = ImageFilter = ImageFont = None

ROOT = Path(__file__).resolve().parents[2]
LOGO = ROOT / "binaryrat/docs/assets/logo.png"
# Ears, eyes and headband: the parts that stay recognisable at 16 and 24 pixels.
HEAD_BOX = (150, 40, 1150, 880)
SMALL_ICON = 24
GUI_IMAGES = ROOT / "Ghidra/Framework/Gui/src/main/resources/images"
EXTENSION_IMAGES = ROOT / "binaryrat/bridge/src/main/resources/images/binaryrat"
HELP_LOGO = ROOT / "binaryrat/distribution/help/logo.png"
HELP_LOGO_SIZE = 128
APPLICATION_SIZES = (16, 24, 32, 40, 48, 64, 128, 256)
EXTENSION_SIZES = (16, 24, 32, 64)
SPLASH_SIZE = 500
# Colours sampled from the logo: the ear and eye red, and light fur grey.
RED = (225, 8, 35)
FUR = (222, 222, 226)
MUTED = (140, 140, 148)
FONTS = (
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    Path(sys.prefix) / "Lib/site-packages/matplotlib/mpl-data/fonts/ttf/DejaVuSans-Bold.ttf",
)


def visible_logo(box: tuple[int, int, int, int] | None = None) -> Image.Image:
    """The logo (or a part of it) cropped to visible pixels, centred on a transparent square."""
    logo = Image.open(LOGO).convert("RGBA")
    if box is None:
        box = logo.getchannel("A").point(lambda value: 255 if value > 64 else 0).getbbox()
    if box is None:
        raise ValueError("the logo has no visible pixels")
    cropped = logo.crop(box)
    side = max(cropped.size)
    square = Image.new("RGBA", (side, side))
    square.paste(cropped, ((side - cropped.width) // 2, (side - cropped.height) // 2))
    return square


def scaled(image: Image.Image, size: int) -> Image.Image:
    # Resample premultiplied colour so transparent edges do not pick up dark fringes.
    return image.convert("RGBa").resize((size, size), Image.Resampling.LANCZOS).convert("RGBA")


def icon(logo: Image.Image, head: Image.Image, size: int) -> Image.Image:
    # Small icons keep a one-pixel margin so the ears are not clipped by window chrome.
    margin = 1 if size <= SMALL_ICON else max(2, size // 32)
    canvas = Image.new("RGBA", (size, size))
    inner = scaled(head if size <= SMALL_ICON else logo, size - 2 * margin)
    if size <= SMALL_ICON:
        inner = inner.filter(ImageFilter.UnsharpMask(radius=0.6, percent=60, threshold=1))
    canvas.alpha_composite(inner, (margin, margin))
    return canvas


def font(path: Path | None, size: int) -> ImageFont.FreeTypeFont:
    candidates = [path] if path else [candidate for candidate in FONTS if candidate.is_file()]
    if not candidates:
        raise FileNotFoundError("DejaVu Sans Bold not found; pass --font")
    return ImageFont.truetype(str(candidates[0]), size)


def splash(logo: Image.Image, font_path: Path | None) -> Image.Image:
    canvas = Image.new("RGBA", (SPLASH_SIZE, SPLASH_SIZE), (0, 0, 0, 255))
    mark = scaled(logo, 330)
    canvas.alpha_composite(mark, ((SPLASH_SIZE - mark.width) // 2, 28))
    draw = ImageDraw.Draw(canvas)
    title = font(font_path, 54)
    first, second = "Binary", "Rat"
    widths = [draw.textlength(part, font=title) for part in (first, second)]
    left = (SPLASH_SIZE - sum(widths)) / 2
    baseline = 418
    draw.text((left, baseline), first, font=title, fill=FUR, anchor="ls")
    draw.text((left + widths[0], baseline), second, font=title, fill=RED, anchor="ls")
    tagline = font(font_path, 17)
    draw.text((SPLASH_SIZE / 2, 452), "Reverse engineering, built on Ghidra", font=tagline,
              fill=MUTED, anchor="ms")
    return canvas


def outputs(font_path: Path | None) -> dict[Path, Image.Image]:
    logo, head = visible_logo(), visible_logo(HEAD_BOX)
    images = {GUI_IMAGES / f"BinaryRatIcon{size}.png": icon(logo, head, size) for size in APPLICATION_SIZES}
    images[GUI_IMAGES / "BinaryRatSplash.png"] = splash(logo, font_path)
    images.update({EXTENSION_IMAGES / f"logo{size}.png": icon(logo, head, size) for size in EXTENSION_SIZES})
    images[HELP_LOGO] = icon(logo, head, HELP_LOGO_SIZE)
    return images


def differs(expected: Image.Image, path: Path) -> str | None:
    if not path.is_file():
        return "missing"
    actual = Image.open(path)
    if actual.size != expected.size or actual.mode != expected.mode:
        return f"{actual.size} {actual.mode}, expected {expected.size} {expected.mode}"
    # Allow small resampling differences between Pillow builds.
    worst = max(high for _, high in ImageChops.difference(actual, expected).getextrema())
    return f"pixel difference {worst}" if worst > 3 else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--font", type=Path, help="path to DejaVuSans-Bold.ttf")
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args()
    if Image is None:
        raise SystemExit("make_branding.py needs Pillow: python -m pip install pillow")
    stale = []
    for path, image in outputs(args.font).items():
        if args.check:
            problem = differs(image, path)
            if problem:
                stale.append(f"{path.relative_to(ROOT).as_posix()}: {problem}")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        buffer = BytesIO()
        image.save(buffer, "PNG", optimize=True)
        path.write_bytes(buffer.getvalue())
        print(path.relative_to(ROOT).as_posix())
    if stale:
        raise SystemExit("Stale BinaryRat images; run make_branding.py:\n" + "\n".join(stale))


if __name__ == "__main__":
    main()
