"""Device-independent reference for WSI v1 bytes and commitments."""

from hashlib import sha256
from struct import pack, unpack


MAGIC = b"WSI\x01"
MAX_CONTAINER = 16_777_216
MAX_DEPTH = 64
MAX_UINT = 0xFFFFFFFF


class EncodingError(ValueError):
    """A payload or frame violates the WSI byte format."""


def _head(major, value):
    if not 0 <= value <= MAX_UINT:
        raise EncodingError("value outside the WSI uint32 encoding domain")
    if value < 24:
        return bytes((major << 5 | value,))
    if value < 256:
        return bytes((major << 5 | 24, value))
    if value < 65_536:
        return bytes((major << 5 | 25,)) + pack(">H", value)
    return bytes((major << 5 | 26,)) + pack(">I", value)


def encode(value, depth=1):
    """Encode one WSI CBOR item, without applying method-level schemas."""
    if depth > MAX_DEPTH:
        raise EncodingError("CBOR nesting limit exceeded")
    if value is None:
        return b"\xf6"
    if type(value) is bool:
        return b"\xf5" if value else b"\xf4"
    if type(value) is int:
        return _head(0, value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        payload = value.encode("utf-8")
        return _head(3, len(payload)) + payload
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(encode(item, depth + 1) for item in value)
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        entries = [(encode(key, depth + 1), val) for key, val in value.items()]
        return _head(5, len(entries)) + b"".join(
            key + encode(val, depth + 1) for key, val in sorted(entries)
        )
    raise EncodingError("unsupported WSI CBOR type")


class _Decoder:
    def __init__(self, payload):
        self.payload = payload
        self.position = 0

    def take(self, size):
        end = self.position + size
        if end > len(self.payload):
            raise EncodingError("truncated CBOR")
        value = self.payload[self.position:end]
        self.position = end
        return value

    def count(self, additional):
        if additional < 24:
            return additional
        widths = {24: (1, 24), 25: (2, 256), 26: (4, 65_536)}
        if additional not in widths:
            raise EncodingError("unsupported CBOR length or integer width")
        width, minimum = widths[additional]
        number = int.from_bytes(self.take(width), "big")
        if number < minimum:
            raise EncodingError("nonshort CBOR argument")
        return number

    def item(self, depth):
        if depth > MAX_DEPTH:
            raise EncodingError("CBOR nesting limit exceeded")
        first = self.take(1)[0]
        major, additional = first >> 5, first & 31
        if major == 7 and additional in (20, 21, 22):
            return {20: False, 21: True, 22: None}[additional]
        if major not in (0, 2, 3, 4, 5):
            raise EncodingError("unsupported WSI CBOR type")
        count = self.count(additional)
        if major == 0:
            return count
        if major == 2:
            return self.take(count)
        if major == 3:
            try:
                return self.take(count).decode("utf-8")
            except UnicodeDecodeError as error:
                raise EncodingError("invalid CBOR UTF-8") from error
        minimum_bytes = count if major == 4 else 2 * count
        if minimum_bytes > len(self.payload) - self.position:
            raise EncodingError("CBOR container count exceeds available bytes")
        if major == 4:
            return [self.item(depth + 1) for _ in range(count)]
        result = {}
        previous = b""
        for _ in range(count):
            start = self.position
            key = self.item(depth + 1)
            raw_key = self.payload[start:self.position]
            if not isinstance(key, str) or raw_key <= previous:
                raise EncodingError("invalid, duplicate, or unsorted CBOR map key")
            previous = raw_key
            result[key] = self.item(depth + 1)
        return result


def decode(payload):
    if len(payload) > MAX_CONTAINER - len(MAGIC):
        raise EncodingError("CBOR payload exceeds the WSI container limit")
    decoder = _Decoder(payload)
    result = decoder.item(1)
    if decoder.position != len(payload):
        raise EncodingError("trailing bytes")
    return result


def frame(payload, carrier):
    container = MAGIC + payload
    if not 5 <= len(container) <= MAX_CONTAINER:
        raise EncodingError("WSI container length outside bounds")
    if carrier == "file":
        return container
    if carrier == "stream":
        return pack(">I", len(container)) + container
    raise EncodingError("unknown carrier")


def unframe(data, carrier, limit=MAX_CONTAINER):
    if carrier == "stream":
        if len(data) < 4:
            raise EncodingError("truncated frame header")
        length = unpack(">I", data[:4])[0]
        if not 5 <= length <= min(limit, MAX_CONTAINER) or length != len(data) - 4:
            raise EncodingError("invalid frame length")
        data = data[4:]
    elif carrier != "file":
        raise EncodingError("unknown carrier")
    if not 5 <= len(data) <= min(limit, MAX_CONTAINER) or not data.startswith(MAGIC):
        raise EncodingError("invalid WSI container")
    return data[len(MAGIC):]


def commitment(domain, encoded):
    return sha256(domain.encode("ascii") + b"\x00" + encoded).digest()


def request(method, params, name, required_features=()):
    identifier = sha256(f"WSI/CTS/request/{name}".encode()).digest()[:16]
    return {
        "v": 1,
        "type": "request",
        "id": identifier,
        "method": method,
        "required_features": list(required_features),
        "params": params,
    }


def response(operation, **outcome):
    if list(outcome) not in (["result"], ["error"]):
        raise ValueError("exactly one of result or error is required")
    return {
        "v": 1,
        "type": "response",
        "id": operation["id"],
        "request_hash": commitment("WSI/request/v1", encode(operation)),
        **outcome,
    }
