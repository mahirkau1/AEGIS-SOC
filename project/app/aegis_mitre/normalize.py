"""Command-line normalisation and bounded deobfuscation for AEGIS SOC."""
from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Tuple

MAX_DECODED_BYTES = 262_144   # zip-bomb guard per layer
MAX_LAYERS = 8
MAX_DEPTH = 3

_DASHES = str.maketrans({"\u2013": "-", "\u2014": "-", "\u2015": "-", "\u2212": "-"})
_INVISIBLE = re.compile(r"[\u200b-\u200f\u2060\ufeff\x00]")
_CONCAT = re.compile(r"[\"']\s*\+\s*[\"']")
_WS = re.compile(r"\s+")


def light_clean(text: str) -> str:
    """NFKC, unify dashes, drop invisible chars. Keeps case and quoting."""
    t = unicodedata.normalize("NFKC", text).translate(_DASHES)
    return _INVISIBLE.sub("", t)


def normalize(text: str) -> str:
    """Aggressive form used for rule matching (lowercase, escapes/quotes removed)."""
    t = light_clean(text)
    t = _CONCAT.sub("", t)                       # 'pow'+'ershell'
    t = t.replace("^", "").replace("`", "")      # cmd / PowerShell escapes
    t = t.replace('"', "").replace("'", "")
    return _WS.sub(" ", t).strip().lower()


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


# ---------------------------------------------------------------- deobfuscation
def prefixes(word: str, minimum: int) -> str:
    """Regex alternation of all abbreviations PowerShell accepts for a switch."""
    return "|".join(sorted({word[:i] for i in range(minimum, len(word) + 1)},
                           key=len, reverse=True))


ENC_FLAG = prefixes("encodedcommand", 1) + "|ec"
_ENC_RE = re.compile(
    rf"(?i)(?:^|\s)[-/](?:{ENC_FLAG})(?:\s+|:)([\"']?)([A-Za-z0-9+/=]{{8,}})\1(?=\s|$)"
)
_ENC_PRESENT = re.compile(rf"(?i)(?:^|\s)[-/](?:{ENC_FLAG})(?=[\s:]|$)")
_LITERAL_B64 = re.compile(
    r"(?i)frombase64string\(\s*[\"']([A-Za-z0-9+/=]{16,})[\"']\s*\)"
)


@dataclass
class Layer:
    kind: str          # encodedcommand | frombase64 | gzip | deflate
    text: str
    depth: int
    embedded_pe: bool = False


@dataclass
class Deobfuscation:
    layers: List[Layer] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)


def _b64(data: str) -> bytes:
    data = data.strip()
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data, validate=True)


def _printable_ratio(s: str) -> float:
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in s) / len(s) if s else 0.0


def _to_text(raw: bytes) -> str | None:
    # UTF-16-LE text has NULs in the high byte of most code units; ASCII/UTF-8 does not.
    looks_utf16 = len(raw) >= 2 and len(raw) % 2 == 0 and \
        sum(b == 0 for b in raw[1::2]) >= 0.3 * (len(raw) // 2)
    order = ("utf-16-le", "utf-8", "latin-1") if looks_utf16 else ("utf-8", "utf-16-le", "latin-1")
    for enc in order:
        if enc == "utf-16-le" and len(raw) % 2:
            continue
        try:
            txt = raw.decode(enc).lstrip("\ufeff")
        except UnicodeError:
            continue
        if _printable_ratio(txt) >= 0.9:
            return txt
    return None


def _inflate(raw: bytes) -> Tuple[bytes, str] | None:
    attempts = ((31, "gzip") if raw[:2] == b"\x1f\x8b" else (-15, "deflate"),
                (15, "zlib"))
    for wbits, kind in attempts:
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(raw, MAX_DECODED_BYTES)
            if d.unconsumed_tail:
                return None                     # exceeds cap: treat as bomb
            if out:
                return out, kind
        except zlib.error:
            continue
    return None


def deobfuscate(command: str) -> Deobfuscation:
    result = Deobfuscation()
    queue: List[Tuple[str, int]] = [(light_clean(command).replace("^", ""), 0)]

    while queue and len(result.layers) < MAX_LAYERS:
        text, depth = queue.pop(0)
        if depth >= MAX_DEPTH:
            continue

        matches = [("encodedcommand", m.group(2)) for m in _ENC_RE.finditer(text)]
        matches += [("frombase64", m.group(1)) for m in _LITERAL_B64.finditer(text)]

        if not matches and _ENC_PRESENT.search(text) and depth == 0:
            result.failed.append("encoded flag present but payload not decodable")

        for kind, blob in matches:
            try:
                raw = _b64(blob)
            except (ValueError, binascii.Error):
                result.failed.append(f"{kind}: invalid base64")
                continue
            if len(raw) > MAX_DECODED_BYTES:
                result.failed.append(f"{kind}: payload too large")
                continue

            pe = raw[:2] == b"MZ"
            inflated = _inflate(raw) if not pe else None
            if inflated:
                raw, ckind = inflated
                pe = raw[:2] == b"MZ"
                kind = f"{kind}+{ckind}"

            txt = None if pe else _to_text(raw)
            if txt is None and not pe:
                result.failed.append(f"{kind}: binary or unreadable payload")
                continue

            layer = Layer(kind, txt or "", depth + 1, embedded_pe=pe)
            result.layers.append(layer)
            if txt:
                queue.append((txt, depth + 1))
    return result


# ---------------------------------------------------------------- IOC extraction
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"<>)\]]{4,}")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_iocs(*texts: str) -> dict:
    urls, ips = [], []
    for t in texts:
        urls += _URL.findall(t)
        ips += [ip for ip in _IPV4.findall(t)
                if all(0 <= int(o) <= 255 for o in ip.split("."))]
    dedupe = lambda xs: list(dict.fromkeys(xs))[:25]
    return {"urls": dedupe(urls), "ips": dedupe(ips)}
