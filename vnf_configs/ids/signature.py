"""The intentionally narrow, repeatable IDS demo signature."""


def is_attack(payload):
    if not isinstance(payload, bytes):
        return False
    first_line = payload.split(b"\r\n", 1)[0]
    return (first_line.startswith(b"GET /attack ") or
            b"\r\nx-sfc-attack: 1\r\n" in payload.lower())
