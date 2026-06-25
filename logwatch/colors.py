"""Tiny ANSI colour helper - no third party ``colorama`` dependency.

The terminal report is easier to scan when severities and headings are
coloured, but we never want colour codes to leak into a file or a pipe (for
example ``logwatch ... > report.txt`` or ``| grep``). This module therefore:

* auto-detects whether stdout is an interactive TTY,
* lets the user force colour on/off via the CLI (``--color`` / ``--no-color``),
* honours the de-facto ``NO_COLOR`` environment variable convention
  (https://no-color.org/),
* and best-effort enables ANSI processing on modern Windows consoles.

All public colour functions degrade gracefully to plain text when colour is
disabled, so the rest of the code base can call them unconditionally.
"""

from __future__ import annotations

import os
import sys

# Raw ANSI SGR escape codes. Kept private; callers use the wrapper functions.
_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_cyan": "\033[96m",
}

# Module level switch. Resolved once by ``configure`` and read by ``paint``.
_ENABLED = False


def _windows_enable_ansi() -> None:
    """Best-effort enable of ANSI escape handling on legacy Windows consoles.

    Modern Windows Terminal / PowerShell already understand ANSI, but the
    classic ``cmd.exe`` console needs the ``ENABLE_VIRTUAL_TERMINAL_PROCESSING``
    flag set. We do this via ctypes so we add no dependency. Any failure is
    swallowed: worst case we simply fall back to monochrome output.
    """
    if os.name != "nt":
        return
    try:  # pragma: no cover - platform specific, exercised only on Windows.
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # -11 == STD_OUTPUT_HANDLE. 0x0004 == ENABLE_VIRTUAL_TERMINAL_PROCESSING.
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def configure(mode: str = "auto", stream=None) -> bool:
    """Decide whether colour output is enabled and remember the decision.

    :param mode: one of ``"auto"``, ``"always"`` or ``"never"``.
    :param stream: the output stream to probe (defaults to ``sys.stdout``).
    :returns: ``True`` if colour is enabled.

    Precedence: an explicit ``"always"``/``"never"`` always wins. In ``"auto"``
    mode we enable colour only for a real interactive TTY and only when the
    ``NO_COLOR`` environment variable is absent.
    """
    global _ENABLED
    stream = stream if stream is not None else sys.stdout

    if mode == "never":
        _ENABLED = False
    elif mode == "always":
        _ENABLED = True
    else:  # auto
        is_tty = bool(getattr(stream, "isatty", lambda: False)())
        no_color = "NO_COLOR" in os.environ
        _ENABLED = is_tty and not no_color

    if _ENABLED:
        _windows_enable_ansi()
    return _ENABLED


def enabled() -> bool:
    """Return the current colour state (mostly handy for tests)."""
    return _ENABLED


def paint(text: str, *styles: str) -> str:
    """Wrap ``text`` in the given style codes, or return it untouched.

    Unknown style names are ignored so a typo can never crash the report.
    """
    if not _ENABLED or not styles:
        return text
    prefix = "".join(_CODES.get(s, "") for s in styles)
    if not prefix:
        return text
    return f"{prefix}{text}{_CODES['reset']}"


# Convenience wrappers - read better at call sites than paint(x, "red").
def red(text: str) -> str:
    return paint(text, "bright_red")


def green(text: str) -> str:
    return paint(text, "bright_green")


def yellow(text: str) -> str:
    return paint(text, "bright_yellow")


def cyan(text: str) -> str:
    return paint(text, "bright_cyan")


def bold(text: str) -> str:
    return paint(text, "bold")


def dim(text: str) -> str:
    return paint(text, "dim")
