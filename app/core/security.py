"""
security.py — Core security primitives for the Master Profiler pipeline.

Implements:
- SHA-256 payload hashing (SOURCES pillar)
- Prompt injection / profile poisoning detection
- PII redaction (emails, phone numbers, national IDs, credit cards)
- UU PDP (Indonesian privacy law) blocklist enforcement
- HMAC-SHA256 hash chain for audit_events (RECORD pillar)
"""
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

# ============================================================================
# SHA-256 Payload Hashing (SOURCES Pillar)
# ============================================================================

def sha256_hash(data: str | bytes) -> str:
    """Compute SHA-256 hex digest of a string or bytes payload."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_hash(payload: dict) -> str:
    """Compute a canonical SHA-256 of a JSON-serializable dict (sorted keys)."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return sha256_hash(canonical)

# ============================================================================
# HMAC-SHA256 Hash Chain (RECORD Pillar — TR-14)
# ============================================================================

def compute_chain_hash(prev_hash: str | None, actor: str, action: str,
                       target_type: str, target_id: str, details: dict,
                       hmac_key: str = "") -> str:
    """
    Compute the next hash in the audit chain.
    If hmac_key is provided, uses HMAC-SHA256; otherwise plain SHA-256.
    """
    chain_input = (
        f"{prev_hash or ''}|{actor}|{action}|{target_type}|{target_id}|{details}"
    )
    encoded = chain_input.encode("utf-8")
    if hmac_key:
        return hmac.new(hmac_key.encode("utf-8"), encoded, hashlib.sha256).hexdigest()
    return hashlib.sha256(encoded).hexdigest()


def verify_chain(events: list[dict], hmac_key: str = "") -> tuple[bool, list[str]]:
    """
    Verify the integrity of an audit chain.
    Returns (is_valid, list_of_break_points).
    """
    breaks = []
    prev_hash = None
    for i, event in enumerate(events):
        expected = compute_chain_hash(
            prev_hash, event["actor"], event["action"],
            event.get("target_type", ""), event.get("target_id", ""),
            event.get("details", {}), hmac_key
        )
        if event["curr_hash"] != expected:
            breaks.append(f"Chain break at event_id={event.get('event_id', i)}: "
                         f"expected={expected[:16]}... got={event['curr_hash'][:16]}...")
        prev_hash = event["curr_hash"]
    return len(breaks) == 0, breaks

# ============================================================================
# Prompt Injection / Profile Poisoning Detection (TR-08)
# ============================================================================

# Patterns that indicate prompt injection attempts in message bodies
INJECTION_PATTERNS = [
    # Direct instruction override attempts
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.IGNORECASE),
     "instruction_override"),
    (re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:messages|instructions|rules)", re.IGNORECASE),
     "instruction_disregard"),
    (re.compile(r"you\s+are\s+(?:now|actually)\s+(?:a|an)\s+", re.IGNORECASE),
     "role_hijack"),
    # Profile poisoning — attempts to overwrite contact data
    (re.compile(r"(?:update|change|set|overwrite)\s+(?:my|the)\s+(?:email|phone|number|address|contact)", re.IGNORECASE),
     "profile_poisoning_contact"),
    (re.compile(r"(?:my\s+new\s+email\s+is|my\s+new\s+phone\s+is|call\s+me\s+at)\s+[\w.@+-]+", re.IGNORECASE),
     "profile_poisoning_identity"),
    # System prompt extraction attempts
    (re.compile(r"(?:show|reveal|print|output)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?prompt", re.IGNORECASE),
     "prompt_extraction"),
    (re.compile(r"what\s+(?:are|is)\s+your\s+(?:instructions|rules|guidelines)", re.IGNORECASE),
     "prompt_extraction"),
    # Data exfiltration attempts
    (re.compile(r"(?:send|post|upload|forward)\s+(?:this|the\s+)?(?:data|info|conversation)\s+to\s+\S+", re.IGNORECASE),
     "data_exfiltration"),
    # Jailbreak attempts
    (re.compile(r"(?:developer|admin|root|sudo)\s+mode", re.IGNORECASE),
     "jailbreak_mode"),
    (re.compile(r"(?:I\s+am|act\s+as)\s+(?:the\s+)?(?:developer|admin|creator|owner)", re.IGNORECASE),
     "jailbreak_role"),
]


def scan_injections(text: str) -> list[dict]:
    """
    Scan message text for prompt injection / profile poisoning patterns.
    Returns a list of flagged items with pattern type and matched text.
    """
    flags = []
    for pattern, flag_type in INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            flags.append({
                "type": flag_type,
                "match": match.group()[:200],  # Truncate for storage
                "position": match.start(),
            })
    return flags

# ============================================================================
# PII Redaction
# ============================================================================

# Indonesian phone number patterns
PHONE_PATTERNS = [
    # +62 8xxxxxxxxx (international, 9-13 digits after 62)
    (re.compile(r"\+62[\s-]?8\d{1,13}"), "[PHONE]"),
    # 08xx-xxxx-xxxx (domestic format, 08 + 8-12 digits)
    (re.compile(r"\b08\d{1,12}\b"), "[PHONE]"),
    # 021-xxx-xxxx / 031-xxx-xxxx (landline)
    (re.compile(r"\b0\d{2}[\s-]?\d{3,4}[\s-]?\d{3,4}\b"), "[PHONE]"),
]

# Email pattern
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

# Indonesian NIK (16 digits)
NIK_PATTERN = re.compile(r"\b\d{16}\b")

# Credit card number (16 digits with optional spaces/dashes)
CC_PATTERN = re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b")

# NPWP (Indonesian tax ID: xx.xxx.xxx.x-xxx.xxx)
NPWP_PATTERN = re.compile(r"\b\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}\b")


def redact_pii(text: str) -> str:
    """
    Redact PII from message text before sending to the Expert model.
    Replaces emails, phone numbers, NIK, credit cards, and NPWP with placeholders.
    """
    # Order matters: redact longer patterns first to avoid partial matches
    text = EMAIL_PATTERN.sub("[EMAIL]", text)
    for pattern, replacement in PHONE_PATTERNS:
        text = pattern.sub(replacement, text)
    text = NPWP_PATTERN.sub("[NPWP]", text)
    text = NIK_PATTERN.sub("[NIK]", text)
    text = CC_PATTERN.sub("[CARD]", text)
    return text


def extract_phone_e164(text: str) -> str | None:
    """
    Extract a phone number from text and normalize to E.164 format (+628...).
    Returns None if no phone found, or if it's a landline (0xx prefix).
    """
    # Try +62 format first
    match = re.search(r"\+62[\s-]?8\d{1,13}", text)
    if match:
        digits = re.sub(r"[\s-]", "", match.group())
        return digits

    # Try domestic 08xx format
    match = re.search(r"\b08\d{1,12}\b", text)
    if match:
        digits = re.sub(r"[\s-]", "", match.group())
        if digits.startswith("0"):
            digits = "+62" + digits[1:]
        return digits

    return None


def extract_email(text: str) -> str | None:
    """Extract the first email address from text."""
    match = EMAIL_PATTERN.search(text)
    return match.group() if match else None


def is_landline(phone: str) -> bool:
    """Check if a phone number is a landline (0xx area code, not 08xx mobile)."""
    digits = re.sub(r"[\s\-+]", "", phone)
    # Indonesian landlines start with 0 + area code (021, 022, 031, etc.)
    # Mobile numbers start with 08 or +628
    if digits.startswith("6208") or digits.startswith("08"):
        return False
    if digits.startswith("620") and not digits.startswith("6208"):
        return True
    if digits.startswith("0") and not digits.startswith("08"):
        return True
    return False

# ============================================================================
# UU PDP Blocklist (BR-17 — Indonesian Personal Data Protection Law)
# ============================================================================

# Sensitive attributes that must NEVER be inferred or stored
PDP_BLOCKLIST = (
    # English
    "health", "religion", "politics", "political", "ethnicity", "sexual orientation",
    "union membership", "biometric", "genetic",
    # Indonesian
    "kesehatan", "agama", "politik", "suku", "orientasi seksual",
    "keanggotaan serikat", "biometrik", "genetik",
)


def check_pdp_blocklist(intent: str, topics: list[str]) -> str | None:
    """
    Check if enrichment output contains blocked sensitive attributes.
    Returns the blocked term if found, None otherwise.
    """
    haystack = " ".join([intent] + topics).lower()
    for term in PDP_BLOCKLIST:
        if term in haystack:
            return term
    return None

# ============================================================================
# Body Cleaning
# ============================================================================

# Patterns for stripping email artifacts
SIGNATURE_PATTERN = re.compile(
    r"(?:--[ \t]*\r?\n.*|--\s*\r?\n.*|"
    r"Best regards,.*|Sincerely,.*|Regards,.*|"
    r"Hormat kami,.*|Terima kasih,.*|"
    r"Sent from my.*|Get Outlook for.*|"
    r"This email and any attachments.*|CONFIDENTIAL.*)",
    re.IGNORECASE | re.DOTALL
)

QUOTED_REPLY_PATTERN = re.compile(
    r"(?:On .+ wrote:.*|>.+|"
    r"Pada .+ menulis:.*|"
    r"-----Original Message-----.*|"
    r"From:.*|Sent:.*|To:.*|Cc:.*)",
    re.IGNORECASE | re.DOTALL
)

DISCLAIMER_PATTERN = re.compile(
    r"(?:This message(?: and any attachments)? is confidential.*"
    r"|Pesan ini bersifat rahasia.*"
    r"|Disclaimer:.*)",
    re.IGNORECASE | re.DOTALL
)


def clean_body(raw_body: str) -> str:
    """
    Strip signatures, quoted replies, and disclaimers from a message body.
    Returns the clean actionable text.
    """
    text = raw_body

    # Remove quoted reply sections
    text = QUOTED_REPLY_PATTERN.sub("", text)

    # Remove signatures
    text = SIGNATURE_PATTERN.sub("", text)

    # Remove disclaimers
    text = DISCLAIMER_PATTERN.sub("", text)

    # Collapse excessive whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()

    return text if text else raw_body.strip()

# ============================================================================
# Deterministic Features
# ============================================================================

GREETING_PATTERNS = [
    re.compile(r"^(halo|hai|selamat\s+(pagi|siang|sore|malam)|dear|good\s+(morning|afternoon|evening))", re.IGNORECASE),
]

QUESTION_PATTERN = re.compile(r"[?؟]")


def compute_features(text: str, message_date: datetime | None = None) -> dict:
    """
    Compute deterministic, non-model features from message text.
    """
    char_count = len(text)
    word_count = len(text.split()) if text else 0
    emoji_count = sum(1 for c in text if ord(c) > 0x1F600 and ord(c) < 0x1FAFF)
    has_greeting = any(p.search(text) for p in GREETING_PATTERNS)
    has_question = bool(QUESTION_PATTERN.search(text))
    hour_of_day = message_date.hour if message_date else None

    return {
        "char_count": char_count,
        "word_count": word_count,
        "emoji_count": emoji_count,
        "has_greeting": has_greeting,
        "has_question": has_question,
        "hour_of_day": hour_of_day,
    }


# ============================================================================
# Website Login: Password Hashing, JWT Auth & Owner Resolution (PERMISSIONS)
# ============================================================================

PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: str | None = None) -> str:
    """Hash a password with salted PBKDF2-HMAC-SHA256."""
    salt_hex = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_hex.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_hex}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2 hash in constant time."""
    if not password or not stored_hash or not stored_hash.startswith("pbkdf2_sha256$"):
        return False
    try:
        _, iter_str, salt_hex, expected_hex = stored_hash.split("$", 3)
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_hex.encode("utf-8"),
            int(iter_str),
        )
        return hmac.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


def _get_jwt_secret() -> str:
    return (
        os.environ.get("JWT_SECRET_KEY")
        or os.environ.get("AUDIT_HMAC_KEY")
        or "sekre-v3-workbuddy-default-jwt-secret-key-2026"
    )


def create_access_token(
    owner_id: str,
    name: str,
    role: str = "Owner / Admin",
    permissions: list[str] | None = None,
    visible_categories: list[str] | None = None,
    expires_hours: int = 24,
) -> str:
    """Create an HS256 JWT access token for Website login."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": owner_id,
        "owner_id": owner_id,
        "name": name,
        "role": role,
        "permissions": permissions or ["ingest", "enrich", "build_master", "approve_staging", "send_external"],
        "visible_categories": visible_categories or ["customer", "peer"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=expires_hours)).timestamp()),
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm="HS256")


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and verify an HS256 JWT access token. Raises jwt.PyJWTError on invalid/expired."""
    return jwt.decode(token, _get_jwt_secret(), algorithms=["HS256"])


def normalize_owner_id(
    raw_owner: str = "",
    meeting_text: str = "",
    visible_to_roles: list[str] | None = None,
) -> str:
    """
    Deterministically map an owner name/ID or meeting discussion assignment
    to 'owner_rifat' or 'owner_andi'.
    """
    cand = (raw_owner or "").strip().lower()
    if cand in ("owner_andi", "andi", "pak andi", "bapak andi", "andi wijaya"):
        return "owner_andi"
    if cand in ("owner_rifat", "rifat", "pak rifat", "bapak rifat", "muhammad rifat"):
        return "owner_rifat"

    # Check meeting discussion text for explicit owner assignment
    text_lower = (meeting_text or "").lower()
    if re.search(r"\b(?:pak\s+andi|bapak\s+andi|owner_andi)\b", text_lower) and not re.search(
        r"\b(?:pak\s+rifat|bapak\s+rifat|owner_rifat)\b", text_lower
    ):
        return "owner_andi"
    if re.search(r"\b(?:pak\s+rifat|bapak\s+rifat|owner_rifat)\b", text_lower):
        return "owner_rifat"

    if visible_to_roles and isinstance(visible_to_roles, list):
        first = str(visible_to_roles[0]).strip().lower()
        if first in ("owner_rifat", "owner_andi"):
            return first

    return os.environ.get("DEFAULT_OWNER", "owner_rifat")
