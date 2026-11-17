"""Terminal-safe printing: hostile files can contain escape sequences."""

import re

CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def clean(s: object) -> str:
    return CTRL.sub("?", str(s))


def log(msg: object) -> None:
    print(clean(msg), flush=True)
