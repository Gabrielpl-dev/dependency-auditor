#!/usr/bin/env python3
"""Render ``docs/demo.gif`` without requiring `vhs` to be installed.

The canonical recording is ``docs/demo.tape``; run it with ``vhs`` when the tool
is available. This fallback runs the very same commands through the real CLI,
captures their output and paints it into an animated GIF, so the demo shown in
the README is always genuine output.

Usage (from the repository root):

    python3 docs/render_demo.py
"""

import os
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
FIXTURE = "examples/osv-fixture.json"
OUTPUT = os.path.join(ROOT, "docs", "demo.gif")

WIDTH = 1060
PAD = 24
FONT_SIZE = 15
LINE_HEIGHT = 21
# Height is derived from the transcript so nothing is ever clipped; keep it in
# sync with `Set Height` in docs/demo.tape.
HEIGHT = 1160
BG = (30, 30, 46)
FG = (205, 214, 244)
PROMPT = (166, 227, 161)
FAIL = (243, 139, 168)
OK = (166, 227, 161)
MUTED = (127, 132, 156)
HEAD = (137, 180, 250)

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"


def run(cmd):
    env = dict(os.environ)
    env["AUDITOR_OSV_FIXTURE"] = FIXTURE
    env["NO_COLOR"] = "1"
    proc = subprocess.run(
        cmd, cwd=ROOT, env=env, capture_output=True, text=True
    )
    return proc.stdout.rstrip("\n"), proc.returncode


def build_transcript():
    """Return the list of (kind, text) lines that the demo shows."""
    lines = []
    lines.append(("cmd", "export AUDITOR_OSV_FIXTURE=" + FIXTURE))
    lines.append(("out", ""))

    lines.append(("cmd", "./app examples"))
    out, code = run([APP, "examples"])
    for line in out.split("\n"):
        lines.append(("out", line))
    lines.append(("cmd", 'echo "exit code: $?"'))
    lines.append(("exit", "exit code: %d" % code))
    lines.append(("out", ""))

    lines.append(("cmd", "./app --fail-on critical examples/package.json"))
    out, code = run([APP, "--fail-on", "critical", "examples/package.json"])
    for line in out.split("\n"):
        lines.append(("out", line))
    lines.append(("cmd", 'echo "exit code: $?"'))
    lines.append(("exit", "exit code: %d" % code))
    return lines


def color_for(kind, text):
    if kind == "exit":
        return OK if text.endswith("0") else FAIL
    stripped = text.strip()
    if stripped.startswith("FAIL"):
        return FAIL
    if stripped.startswith("OK"):
        return OK
    if stripped.startswith("Result:"):
        return OK if "exit 0" in stripped else FAIL
    if stripped.startswith("warnings:") or stripped.endswith("(npm)") or stripped.endswith("(PyPI)"):
        return HEAD
    if stripped.startswith("Summary:") or stripped.startswith("critical "):
        return MUTED
    return FG


def frame(lines, cursor, font, bold):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    y = PAD
    for index, (kind, text) in enumerate(lines):
        if y > HEIGHT - PAD - LINE_HEIGHT:
            break
        if kind == "cmd":
            draw.text((PAD, y), "$", font=bold, fill=PROMPT)
            draw.text((PAD + 18, y), text, font=font, fill=FG)
        else:
            draw.text((PAD, y), text, font=font, fill=color_for(kind, text))
        y += LINE_HEIGHT

    if cursor is not None and y <= HEIGHT - PAD - LINE_HEIGHT:
        draw.rectangle(
            [PAD, y + 2, PAD + 9, y + FONT_SIZE + 3], fill=(108, 112, 134)
        )
    return img


def main():
    if not shutil.which("python3"):
        sys.exit("python3 is required")

    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    bold = ImageFont.truetype(FONT_BOLD, FONT_SIZE)

    transcript = build_transcript()

    frames = []
    durations = []

    # Progressive reveal: one new line every few tenths of a second.
    for i in range(0, len(transcript) + 1):
        cursor = i < len(transcript)
        frames.append(frame(transcript[:i], cursor, font, bold))
        durations.append(120 if cursor else 2500)

    frames[0].save(
        OUTPUT,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print("wrote %s (%d frames)" % (os.path.relpath(OUTPUT, ROOT), len(frames)))


if __name__ == "__main__":
    main()
