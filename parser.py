"""
parser.py - Email parsing layer for the AI-Assisted Phishing Email & Header Analyzer.

Responsibilities
----------------
* Parse a raw RFC 5322 message (.eml bytes, or pasted raw text / headers only).
* Extract what a SOC L1 analyst checks first: identity headers, SPF/DKIM/DMARC
  results, sender IPs, embedded URLs, attachments and body text.
* Run a small set of deterministic, explainable heuristics. These give the AI a
  head start AND act as an offline fallback when the Gemini API is unavailable.

This module is 100% offline: it never opens URLs, resolves DNS or calls any API.
Everything returned is a plain, JSON-serialisable dict.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

__all__ = ["EmailParseError", "parse_email", "compute_heuristics", "defang"]


class EmailParseError(Exception):
    """Raised when the supplied input cannot be interpreted as an email."""


# --------------------------------------------------------------------------- #
# Tunables and reference data
# --------------------------------------------------------------------------- #
MAX_BODY_CHARS = 4000       # body excerpt size handed to the AI
MAX_URLS = 50               # hard cap so a link-farm email cannot blow up the prompt
MAX_RECEIVED_HOPS = 12
MAX_RECEIVED_CHARS = 400

# Address space we consider "internal / not attributable". NOTE: the RFC 5737
# documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are
# deliberately NOT listed, so the bundled sample_phish.eml behaves like real
# internet-sourced mail.
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
        "::1/128", "fc00::/7", "fe80::/10",
    )
)

_URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
})

_SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "click", "work", "country", "gq", "tk", "ml",
    "cf", "ga", "icu", "cyou", "rest", "buzz", "monster", "loan", "cam",
})

_RISKY_EXTENSIONS = frozenset({
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf",
    "ps1", "hta", "jar", "lnk", "iso", "img", "msi", "dll", "html", "htm",
    "xhtml", "svg", "docm", "xlsm", "pptm", "xlam", "one", "chm", "zip", "rar",
    "7z", "ace", "cab",
})

# Brand -> legitimate registrable domains. Used for impersonation / look-alike checks.
_BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com",
                  "microsoftonline.com", "office365.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "amazonses.com"),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com", "dropboxmail.com"),
    "facebook": ("facebook.com", "facebookmail.com"),
    "hdfc": ("hdfcbank.com", "hdfcbank.net"),
    "icici": ("icicibank.com",),
}

# Common phishing / social-engineering language.
_KEYWORDS = (
    "urgent", "immediately", "verify your", "confirm your", "account suspended",
    "account will be", "suspended", "limited", "unusual activity", "unauthorized",
    "security alert", "password", "login", "log in", "sign in", "click here",
    "within 24 hours", "act now", "final notice", "invoice", "payment",
    "wire transfer", "gift card", "refund", "update your", "expire", "locked",
)

_LOOKALIKE_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})

_URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'`]+""")
_TRAILING_PUNCT = ".,;:!?)]}'\""
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{3,45})\]")
_DOMAINISH_RE = re.compile(r"(?i)^(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#]|$)")
_DOUBLE_EXT_RE = re.compile(r"(?i)\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif)\.[a-z0-9]{2,5}$")
_AUTH_PATTERNS = {
    "spf": re.compile(r"(?i)\bspf\s*=\s*([a-z]+)"),
    "dkim": re.compile(r"(?i)\bdkim\s*=\s*([a-z]+)"),
    "dmarc": re.compile(r"(?i)\bdmarc\s*=\s*([a-z]+)"),
}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _clean(value: Any) -> str:
    """Collapse folded/multi-line header values into one tidy line."""
    return " ".join(str(value).split())


def _header(msg: Message, name: str) -> str:
    """Safely fetch a single header as clean text ('' if absent or malformed)."""
    try:
        value = msg.get(name)
    except Exception:  # a malformed header must never crash triage
        return ""
    return _clean(value) if value is not None else ""


def _all_headers(msg: Message, name: str) -> list[str]:
    """Safely fetch every occurrence of a header (top-most first)."""
    try:
        values = msg.get_all(name) or []
    except Exception:
        return []
    return [_clean(v) for v in values]


def _domain_of(address: str) -> str:
    """'User@Example.COM' -> 'example.com' ('' if no '@')."""
    address = (address or "").strip().lower()
    return address.rpartition("@")[2].strip("<> ") if "@" in address else ""


def _related_domains(a: str, b: str) -> bool:
    """True when the domains are identical or one is a sub-domain of the other."""
    if not a or not b:
        return True  # nothing to compare -> do not raise a mismatch
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_multicast or addr.is_unspecified or any(addr in net for net in _INTERNAL_NETS)


def _find_ips(text: str) -> list[str]:
    """Return every syntactically valid IPv4/IPv6 address found in `text`."""
    candidates = [m.group(0) for m in _IPV4_RE.finditer(text)]
    candidates += [m.group(1) for m in _IPV6_RE.finditer(text)]
    valid = []
    for candidate in candidates:
        try:
            valid.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return valid


def defang(value: str) -> str:
    """Make a URL/domain non-clickable: http://a.com -> hxxp://a[.]com"""
    return re.sub(r"(?i)^http", "hxxp", value).replace(".", "[.]")


def _normalize_lookalike(text: str) -> str:
    """Undo common character swaps so 'paypa1' / 'rnicrosoft' still match the brand."""
    return text.lower().translate(_LOOKALIKE_MAP).replace("rn", "m").replace("vv", "w")


def _is_legit_for(domain: str, legit_domains: tuple[str, ...]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in legit_domains)


def _brand_in_domain(domain: str) -> str | None:
    """Return the brand a domain imitates (without being the real one), else None."""
    if not domain:
        return None
    normalized = _normalize_lookalike(domain)
    for brand, legit in _BRANDS.items():
        if brand in normalized and not _is_legit_for(domain, legit):
            return brand
    return None


def _brand_in_display_name(display: str, from_domain: str) -> str | None:
    """Return the brand claimed in a display name when the sending domain is not the brand's."""
    if not display:
        return None
    normalized = _normalize_lookalike(display)
    for brand, legit in _BRANDS.items():
        if brand in normalized and not _is_legit_for(from_domain, legit):
            return brand
    return None


# --------------------------------------------------------------------------- #
# HTML scanning (links + visible text) using only the standard library
# --------------------------------------------------------------------------- #
class _HTMLScanner(HTMLParser):
    """Collects visible text plus (href, anchor_text, kind) triples from HTML."""

    _BLOCK_TAGS = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str, str]] = []
        self._text: list[str] = []
        self._skip_depth = 0          # >0 while inside <script>/<style>
        self._href: str | None = None
        self._anchor: list[str] = []

    @property
    def visible_text(self) -> str:
        return "".join(self._text)

    def _flush_anchor(self) -> None:
        if self._href is not None:
            self.links.append((self._href, " ".join("".join(self._anchor).split()), "anchor"))
        self._href = None
        self._anchor = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "a":
            self._flush_anchor()  # tolerate unclosed <a> tags
            self._href = attr.get("href", "").strip()
        elif tag == "form" and attr.get("action"):
            self.links.append((attr["action"].strip(), "", "form_action"))
        elif tag in self._BLOCK_TAGS:
            self._text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a":
            self._flush_anchor()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self._text.append(data)
        if self._href is not None:
            self._anchor.append(data)

    def close(self) -> None:
        super().close()
        self._flush_anchor()


# --------------------------------------------------------------------------- #
# Extraction routines
# --------------------------------------------------------------------------- #
def _extract_identity(msg: Message) -> dict[str, str]:
    from_raw = _header(msg, "From")
    display_name, from_addr = parseaddr(from_raw)
    _, reply_addr = parseaddr(_header(msg, "Reply-To"))
    _, return_addr = parseaddr(_header(msg, "Return-Path"))
    message_id = _header(msg, "Message-ID")
    mid_match = re.search(r"@([^>\s]+)", message_id)

    return {
        "from_raw": from_raw,
        "from_display_name": display_name.strip(),
        "from_address": from_addr.lower(),
        "from_domain": _domain_of(from_addr),
        "reply_to": _header(msg, "Reply-To"),
        "reply_to_domain": _domain_of(reply_addr),
        "return_path": _header(msg, "Return-Path"),
        "return_path_domain": _domain_of(return_addr),
        "to": _header(msg, "To"),
        "subject": _header(msg, "Subject"),
        "date": _header(msg, "Date"),
        "message_id": message_id,
        "message_id_domain": mid_match.group(1).lower() if mid_match else "",
        "x_mailer": _header(msg, "X-Mailer") or _header(msg, "User-Agent"),
        "x_priority": _header(msg, "X-Priority"),
    }


def _extract_authentication(msg: Message) -> dict[str, str]:
    """Pull SPF / DKIM / DMARC verdicts stamped by the receiving mail server."""
    auth_headers = _all_headers(msg, "Authentication-Results")
    results = {}
    for method, pattern in _AUTH_PATTERNS.items():
        results[method] = "not_found"
        for header in auth_headers:
            match = pattern.search(header)
            if match:
                results[method] = match.group(1).lower()
                break

    # Fallback: dedicated Received-SPF header (Gmail, Postfix policyd, etc.)
    if results["spf"] == "not_found":
        for value in _all_headers(msg, "Received-SPF"):
            match = re.match(r"\s*([A-Za-z]+)", value)
            if match:
                results["spf"] = match.group(1).lower()
                break

    joined = " ".join(auth_headers)
    mailfrom = re.search(r"(?i)smtp\.mailfrom\s*=\s*([^\s;]+)", joined)
    sig_domain = ""
    for value in _all_headers(msg, "DKIM-Signature"):
        match = re.search(r"\bd=([^;\s]+)", value)
        if match:
            sig_domain = match.group(1).lower()
            break
    if not sig_domain:
        match = re.search(r"(?i)header\.d\s*=\s*([^\s;]+)", joined)
        sig_domain = match.group(1).lower() if match else ""

    results.update({
        "spf_mailfrom": mailfrom.group(1).strip("<>").lower() if mailfrom else "",
        "dkim_signing_domain": sig_domain,
        "raw_authentication_results": joined[:600],
    })
    return results


def _extract_network(msg: Message) -> dict[str, Any]:
    """Derive origin / connecting IPs and a trimmed Received chain."""
    received = _all_headers(msg, "Received")  # index 0 = added last (closest to us)

    def external_ips(header: str) -> list[str]:
        # Only the "from ..." part describes the *sending* host; "by ..." is the receiver.
        from_part = re.split(r"(?i)\bby\b", header, maxsplit=1)[0]
        return [ip for ip in _find_ips(from_part) if not _is_internal_ip(ip)]

    connecting_ip = None  # added by OUR MX -> trustworthy
    for header in received:
        ips = external_ips(header)
        if ips:
            connecting_ip = ips[0]
            break

    originating_ip = None  # earliest external hop -> attacker-controlled, lower trust
    for header in reversed(received):
        ips = external_ips(header)
        if ips:
            originating_ip = ips[0]
            break

    x_orig = None
    for name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        found = [ip for ip in _find_ips(_header(msg, name)) if not _is_internal_ip(ip)]
        if found:
            x_orig = found[0]
            break

    return {
        "originating_ip": originating_ip or x_orig,
        "connecting_ip": connecting_ip,
        "x_originating_ip": x_orig,
        "hop_count": len(received),
        "received_chain": [r[:MAX_RECEIVED_CHARS] for r in received[:MAX_RECEIVED_HOPS]],
    }


def _part_text(part: Message) -> str:
    """Decode a text part robustly, whatever charset/transfer-encoding it uses."""
    try:
        content = part.get_content()  # type: ignore[attr-defined]
        if isinstance(content, str):
            return content
    except Exception:
        pass
    payload = part.get_payload(decode=True)
    if isinstance(payload, (bytes, bytearray)):
        try:
            return bytes(payload).decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            return bytes(payload).decode("utf-8", errors="replace")
    return payload if isinstance(payload, str) else ""


def _describe_attachment(part: Message, filename: str | None, content_type: str) -> dict[str, Any]:
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:
        payload = b""
    if not isinstance(payload, (bytes, bytearray)):
        payload = str(payload).encode("utf-8", errors="replace")
    payload = bytes(payload)

    name = filename or "(unnamed)"
    extension = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    flags = []
    if extension in _RISKY_EXTENSIONS:
        flags.append("risky_extension")
    if _DOUBLE_EXT_RE.search(name):
        flags.append("double_extension")
    return {
        "filename": name,
        "content_type": content_type,
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "flags": flags,
    }


def _extract_content(msg: Message) -> tuple[str, str, list[dict[str, Any]]]:
    """Walk the MIME tree -> (plain_text, html_source, attachments)."""
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            filename = part.get_filename()
        except Exception:
            filename = None
        disposition = (part.get_content_disposition() or "").lower()
        content_type = part.get_content_type()

        if disposition == "attachment" or filename:
            attachments.append(_describe_attachment(part, filename, content_type))
        elif content_type == "text/plain":
            plain_parts.append(_part_text(part))
        elif content_type == "text/html":
            html_parts.append(_part_text(part))

    return "\n".join(plain_parts).strip(), "\n".join(html_parts).strip(), attachments


# --------------------------------------------------------------------------- #
# URL analysis
# --------------------------------------------------------------------------- #
def _analyze_url(url: str, anchor_text: str = "", source: str = "body_text") -> dict[str, Any]:
    record: dict[str, Any] = {
        "url": url, "defanged": defang(url), "host": "",
        "source": source, "anchor_text": anchor_text[:120], "flags": [],
    }
    normalized = url if re.match(r"(?i)^https?://", url) else "http://" + url
    try:
        parts = urlsplit(normalized)
        host = (parts.hostname or "").lower()
    except ValueError:
        record["flags"].append("malformed_url")
        return record

    record["host"] = host
    flags: list[str] = record["flags"]

    if _is_ip(host):
        flags.append("ip_address_host")
    if host in _URL_SHORTENERS:
        flags.append("url_shortener")
    if host.rsplit(".", 1)[-1] in _SUSPICIOUS_TLDS:
        flags.append("suspicious_tld")
    if "xn--" in host:
        flags.append("punycode_idn")
    if "@" in parts.netloc:
        flags.append("userinfo_in_url")
    if host.count(".") >= 4:
        flags.append("excessive_subdomains")
    if url.lower().startswith("http://"):
        flags.append("non_https")

    brand = _brand_in_domain(host)
    if brand:
        flags.append(f"brand_lookalike:{brand}")

    shown = _DOMAINISH_RE.match(anchor_text.strip()) if anchor_text else None
    if shown:
        shown_host = shown.group(1).lower().removeprefix("www.")
        if not _related_domains(shown_host, host.removeprefix("www.")):
            flags.append("display_text_mismatch")
    return record


def _collect_urls(plain: str, html: str) -> tuple[list[dict[str, Any]], str]:
    """Return (url_records, visible_text_of_html)."""
    scanner = _HTMLScanner()
    if html:
        try:
            scanner.feed(html)
            scanner.close()
        except Exception:
            pass  # partial results are still useful

    candidates: list[tuple[str, str, str]] = []
    anchor_texts = {text.strip() for _, text, _ in scanner.links if text}

    for href, text, kind in scanner.links:  # real link targets first (they carry anchor text)
        if re.match(r"(?i)^(https?://|www\.)", href):
            candidates.append((href, text, "html_form_action" if kind == "form_action" else "html_link"))

    for match in _URL_RE.finditer(plain or scanner.visible_text):
        url = match.group(0).rstrip(_TRAILING_PUNCT)
        if url not in anchor_texts:  # skip "display text" that merely looks like a URL
            candidates.append((url, "", "body_text"))

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url, anchor, source in candidates:
        if url in seen:
            continue
        seen.add(url)
        records.append(_analyze_url(url, anchor, source))
        if len(records) >= MAX_URLS:
            break
    return records, scanner.visible_text


# --------------------------------------------------------------------------- #
# Heuristics
# --------------------------------------------------------------------------- #
def compute_heuristics(parsed: dict[str, Any]) -> dict[str, Any]:
    """Deterministic, explainable pre-score (0-100) based on well-known phishing tells."""
    h, a = parsed["headers"], parsed["authentication"]
    findings: list[dict[str, Any]] = []

    def add(fid: str, weight: int, category: str, description: str, evidence: str = "") -> None:
        findings.append({"id": fid, "weight": weight, "category": category,
                         "description": description, "evidence": evidence})

    # -- Authentication --------------------------------------------------------
    if a["spf"] == "fail":
        add("SPF_FAIL", 15, "Authentication Failure",
            "SPF hard-fail: sending IP is not authorised for the envelope domain.",
            f"spf={a['spf']} mailfrom={a['spf_mailfrom'] or 'n/a'}")
    elif a["spf"] in ("softfail", "permerror"):
        add("SPF_SOFTFAIL", 8, "Authentication Failure",
            "SPF softfail/permerror: sender authorisation is doubtful.", f"spf={a['spf']}")
    if a["dkim"] in ("fail", "permerror"):
        add("DKIM_FAIL", 15, "Authentication Failure",
            "DKIM signature failed validation (possible spoofing or tampering).", f"dkim={a['dkim']}")
    elif a["dkim"] == "none":
        add("DKIM_UNSIGNED", 5, "Authentication Failure",
            "Message carries no DKIM signature.", "dkim=none")
    if a["dmarc"] == "fail":
        add("DMARC_FAIL", 20, "Authentication Failure",
            "DMARC failed: From-domain alignment not satisfied by SPF or DKIM.", "dmarc=fail")
    if all(a[m] == "not_found" for m in ("spf", "dkim", "dmarc")):
        add("NO_AUTH_RESULTS", 5, "Header Anomaly",
            "No SPF/DKIM/DMARC results present; sender authenticity cannot be verified.")

    # -- Identity / spoofing ---------------------------------------------------
    if not _related_domains(h["reply_to_domain"], h["from_domain"]):
        add("REPLY_TO_MISMATCH", 10, "Spoofing",
            "Reply-To domain differs from From domain (replies are diverted).",
            f"From={h['from_domain']} Reply-To={h['reply_to_domain']}")
    if not _related_domains(h["return_path_domain"], h["from_domain"]):
        add("RETURN_PATH_MISMATCH", 8, "Spoofing",
            "Return-Path (envelope sender) domain differs from From domain.",
            f"From={h['from_domain']} Return-Path={h['return_path_domain']}")
    if not h["message_id"]:
        add("MISSING_MESSAGE_ID", 5, "Header Anomaly", "Message-ID header is missing.")
    elif not _related_domains(h["message_id_domain"], h["from_domain"]):
        add("MESSAGE_ID_MISMATCH", 5, "Header Anomaly",
            "Message-ID domain does not match the From domain.",
            f"From={h['from_domain']} Message-ID={h['message_id_domain']}")

    spoofed = re.search(r"[\w.+-]+@([\w.-]+\.[a-z]{2,})", h["from_display_name"], re.I)
    if spoofed and not _related_domains(spoofed.group(1).lower(), h["from_domain"]):
        add("DISPLAY_NAME_EMAIL_SPOOF", 15, "Spoofing",
            "Display name embeds an e-mail address that differs from the real sender.",
            f"display={h['from_display_name']!r} actual={h['from_address']}")

    brand = _brand_in_display_name(h["from_display_name"], h["from_domain"]) or _brand_in_domain(h["from_domain"])
    if brand:
        add("BRAND_IMPERSONATION", 15, "Spoofing",
            f"Sender presents as '{brand}' but the domain does not belong to that brand.",
            f"display={h['from_display_name']!r} domain={h['from_domain']}")

    # -- URLs (each tell counted once, with the number of affected links) -------
    url_rules = {
        "ip_address_host": (15, "URL points to a bare IP address instead of a domain."),
        "display_text_mismatch": (15, "Link text shows one destination but the href goes to another."),
        "userinfo_in_url": (10, "URL contains '@' user-info (classic host obfuscation)."),
        "punycode_idn": (10, "Punycode/IDN host (possible homograph attack)."),
        "suspicious_tld": (8, "URL uses a TLD frequently abused for phishing."),
        "url_shortener": (8, "URL shortener hides the real destination."),
        "excessive_subdomains": (4, "URL has an unusually deep sub-domain chain."),
        "non_https": (3, "URL uses unencrypted HTTP."),
    }
    for flag, (weight, text) in url_rules.items():
        hits = [u for u in parsed["urls"] if flag in u["flags"]]
        if hits:
            add(f"URL_{flag.upper()}", weight, "Malicious URL", text,
                f"{len(hits)} link(s), e.g. {hits[0]['defanged']}")
    lookalikes = [u for u in parsed["urls"] if any(f.startswith("brand_lookalike") for f in u["flags"])]
    if lookalikes:
        add("URL_BRAND_LOOKALIKE", 15, "Malicious URL",
            "Link host imitates a well-known brand domain.",
            f"{len(lookalikes)} link(s), e.g. {lookalikes[0]['defanged']}")

    # -- Attachments -----------------------------------------------------------
    for att in parsed["attachments"]:
        if "double_extension" in att["flags"]:
            add("ATTACHMENT_DOUBLE_EXT", 20, "Malicious Attachment",
                "Attachment uses a double extension to masquerade as a document.",
                f"{att['filename']} sha256={att['sha256'][:16]}...")
        elif "risky_extension" in att["flags"]:
            add("ATTACHMENT_RISKY_EXT", 20, "Malicious Attachment",
                "Attachment has an executable/script/container extension commonly used to deliver malware.",
                f"{att['filename']} sha256={att['sha256'][:16]}...")

    # -- Social-engineering language --------------------------------------------
    keywords = parsed["body"]["suspicious_keywords"]
    if len(keywords) >= 3:
        add("SOCIAL_ENGINEERING_LANGUAGE", 10, "Social Engineering",
            "Multiple urgency / credential-harvesting phrases present.", ", ".join(keywords[:8]))
    elif keywords:
        add("SOCIAL_ENGINEERING_LANGUAGE", 5, "Social Engineering",
            "Some urgency / credential-related phrases present.", ", ".join(keywords))

    return {"score": min(100, sum(f["weight"] for f in findings)), "findings": findings}


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
_EXPECTED_HEADERS = {"from", "subject", "received", "message-id", "return-path",
                     "authentication-results", "to", "date"}


def parse_email(raw: bytes | str) -> dict[str, Any]:
    """
    Parse raw email bytes (.eml) or text (full message OR headers only).

    Returns a dict with keys: headers, authentication, network, urls,
    attachments, body, heuristics.  Raises EmailParseError on unusable input.
    """
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw).lstrip()
        if not data:
            raise EmailParseError("Input is empty.")
        msg = BytesParser(policy=policy.default).parsebytes(data)
    elif isinstance(raw, str):
        text = raw.lstrip()
        if not text:
            raise EmailParseError("Input is empty.")
        msg = Parser(policy=policy.default).parsestr(text)
    else:
        raise TypeError("parse_email() expects bytes or str")

    if not {k.lower() for k in msg.keys()} & _EXPECTED_HEADERS:
        raise EmailParseError(
            "No recognisable e-mail headers found (expected From/Subject/Received/...). "
            "Is this an .eml file or raw header text?"
        )

    headers = _extract_identity(msg)
    plain, html, attachments = _extract_content(msg)
    urls, html_text = _collect_urls(plain, html)

    body_text = plain or html_text
    body_text = re.sub(r"[ \t]+", " ", body_text)
    body_text = re.sub(r"\n\s*\n+", "\n\n", body_text).strip()

    haystack = f"{headers['subject']} {body_text}".lower()
    keywords = [kw for kw in _KEYWORDS if kw in haystack]

    parsed: dict[str, Any] = {
        "headers": headers,
        "authentication": _extract_authentication(msg),
        "network": _extract_network(msg),
        "urls": urls,
        "attachments": attachments,
        "body": {
            "text": body_text[:MAX_BODY_CHARS],
            "total_chars": len(body_text),
            "truncated": len(body_text) > MAX_BODY_CHARS,
            "has_plain": bool(plain),
            "has_html": bool(html),
            "suspicious_keywords": keywords,
        },
    }
    parsed["heuristics"] = compute_heuristics(parsed)
    return parsed
