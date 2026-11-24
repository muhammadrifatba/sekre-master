"""
rules_engine.py — Indonesian Cultural & Temporal Rules Engine.

Implements:
- City/site -> WIB / WITA / WIT timezone resolver (TR-09, BR-04)
- Jumatan block (Friday 11:30–13:00 local)
- Ramadan after-hours adjustment (15:00–08:00)
- Work hours enforcement (08:00–17:00 local)
- best_contact_window calculator (excludes Jumatan & after-hours)
- Fleet unit normalization for heavy machinery domain
"""
import re
from datetime import datetime, time, timedelta, timezone
from typing import Optional
from urllib.parse import quote
from zoneinfo import ZoneInfo

# ============================================================================
# Timezone Mapping: WIB / WITA / WIT (TR-09)
# ============================================================================

# Indonesian timezone zones
TZ_WIB = "Asia/Jakarta"        # UTC+7 — Western Indonesia (Jakarta, Surabaya, Bandung)
TZ_WITA = "Asia/Makassar"      # UTC+8 — Central Indonesia (Balikpapan, Samarinda, Makassar)
TZ_WIT = "Asia/Jayapura"       # UTC+9 — Eastern Indonesia (Jayapura, Timika, Sorong)

# City -> timezone mapping (BR-04)
CITY_TZ_MAP = {
    # WIB (UTC+7)
    "jakarta": ("Asia/Jakarta", "WIB"),
    "surabaya": ("Asia/Jakarta", "WIB"),
    "bandung": ("Asia/Jakarta", "WIB"),
    "bekasi": ("Asia/Jakarta", "WIB"),
    "tangerang": ("Asia/Jakarta", "WIB"),
    "depok": ("Asia/Jakarta", "WIB"),
    "bogor": ("Asia/Jakarta", "WIB"),
    "semarang": ("Asia/Jakarta", "WIB"),
    "medan": ("Asia/Jakarta", "WIB"),
    "palembang": ("Asia/Jakarta", "WIB"),
    "pekanbaru": ("Asia/Jakarta", "WIB"),
    "jambi": ("Asia/Jakarta", "WIB"),
    "padang": ("Asia/Jakarta", "WIB"),
    "pontianak": ("Asia/Jakarta", "WIB"),

    # WITA (UTC+8)
    "balikpapan": ("Asia/Makassar", "WITA"),
    "samarinda": ("Asia/Makassar", "WITA"),
    "bengalon": ("Asia/Makassar", "WITA"),
    "kutai kartanegara": ("Asia/Makassar", "WITA"),
    "kutai": ("Asia/Makassar", "WITA"),
    "makassar": ("Asia/Makassar", "WITA"),
    "ujung pandang": ("Asia/Makassar", "WITA"),
    "konawe": ("Asia/Makassar", "WITA"),
    "morowali": ("Asia/Makassar", "WITA"),
    "palu": ("Asia/Makassar", "WITA"),
    "kendari": ("Asia/Makassar", "WITA"),
    "banjarmasin": ("Asia/Makassar", "WITA"),
    "denpasar": ("Asia/Makassar", "WITA"),
    "bali": ("Asia/Makassar", "WITA"),
    "lombok": ("Asia/Makassar", "WITA"),
    "mataram": ("Asia/Makassar", "WITA"),
    "tarakan": ("Asia/Makassar", "WITA"),

    # WIT (UTC+9)
    "jayapura": ("Asia/Jayapura", "WIT"),
    "timika": ("Asia/Jayapura", "WIT"),
    "sorong": ("Asia/Jayapura", "WIT"),
    "manokwari": ("Asia/Jayapura", "WIT"),
    "merauke": ("Asia/Jayapura", "WIT"),
    "biak": ("Asia/Jayapura", "WIT"),
}

# Site name aliases (common mining/construction site names -> city)
SITE_ALIASES = {
    "pit 3": "samarinda",
    "pit 4": "samarinda",
    "site samarinda": "samarinda",
    "site balikpapan": "balikpapan",
    "site bengalon": "bengalon",
    "site konawe": "konawe",
    "site morowali": "morowali",
    "site jayapura": "jayapura",
    "workshop samarinda": "samarinda",
    "kkt": "kutai kartanegara",
    "borneo": "balikpapan",
}


def resolve_timezone(city: str = "", site: str = "") -> tuple[str, str]:
    """
    Resolve a city or site name to (timezone, tz_label).
    Returns ("Asia/Jakarta", "WIB") as default if no match.

    Args:
        city: City name (e.g., "Balikpapan", "Jakarta")
        site: Site name (e.g., "Pit 3", "site Samarinda")

    Returns:
        Tuple of (IANA timezone, label like "WIB"/"WITA"/"WIT")
    """
    # Try site alias first, then city
    candidates = []
    if site:
        candidates.append(site.lower().strip())
    if city:
        candidates.append(city.lower().strip())

    for candidate in candidates:
        # Direct city match
        if candidate in CITY_TZ_MAP:
            return CITY_TZ_MAP[candidate]
        # Try site alias
        if candidate in SITE_ALIASES:
            resolved_city = SITE_ALIASES[candidate]
            if resolved_city in CITY_TZ_MAP:
                return CITY_TZ_MAP[resolved_city]
        # Partial match (city contains candidate or vice versa)
        for known_city, tz_info in CITY_TZ_MAP.items():
            if candidate in known_city or known_city in candidate:
                return tz_info

    # Default to WIB
    return ("Asia/Jakarta", "WIB")

# ============================================================================
# Work Hours & Jumatan Rules
# ============================================================================

WORK_START = time(8, 0)    # 08:00 local
WORK_END = time(17, 0)     # 17:00 local

# Jumatan: Friday prayer block (TR-09)
JUMATAN_START = time(11, 30)
JUMATAN_END = time(13, 0)

# Ramadan: shorter work hours, after-hours starts earlier
RAMADAN_AFTER_HOURS_START = time(15, 0)


def is_friday(dt: datetime) -> bool:
    """Check if datetime falls on Friday."""
    return dt.weekday() == 4  # Monday=0, Friday=4


def is_within_jumatan(dt: datetime) -> bool:
    """Check if datetime falls within Friday Jumatan block (11:30–13:00 local)."""
    if not is_friday(dt):
        return False
    local_time = dt.time()
    return JUMATAN_START <= local_time < JUMATAN_END


def is_within_work_hours(dt: datetime) -> bool:
    """Check if datetime falls within work hours (08:00–17:00 local)."""
    local_time = dt.time()
    return WORK_START <= local_time < WORK_END


def is_after_hours(dt: datetime, is_ramadan: bool = False) -> bool:
    """
    Check if datetime is after work hours.
    Ramadan: after-hours starts at 15:00; normal: after 17:00.
    """
    local_time = dt.time()
    threshold = RAMADAN_AFTER_HOURS_START if is_ramadan else WORK_END
    return local_time >= threshold or local_time < WORK_START


def defer_to_next_workday(dt: datetime, is_ramadan: bool = False) -> datetime:
    """
    Defer a datetime to 08:00 local on the next working day.
    Skips weekends (Saturday=5, Sunday=6).
    """
    next_day = dt.replace(hour=8, minute=0, second=0, microsecond=0) + timedelta(days=1)
    while next_day.weekday() >= 5:  # Skip Sat/Sun
        next_day += timedelta(days=1)
    return next_day


def compute_best_contact_window(
    timezone_str: str,
    is_ramadan: bool = False,
    reference_date: datetime | None = None
) -> str:
    """
    Compute the best contact window string for a customer.

    Returns a human-readable description of when it's safe to contact
    this person, excluding Jumatan and after-hours.

    Example: "Mon–Thu 08:00–17:00 WITA, Fri 08:00–11:30 & 13:00–17:00 WITA"
    """
    tz_label = "WIB"
    if "Makassar" in timezone_str:
        tz_label = "WITA"
    elif "Jayapura" in timezone_str:
        tz_label = "WIT"

    work_end_str = "15:00" if is_ramadan else "17:00"

    return (
        f"Mon–Thu 08:00–{work_end_str} {tz_label}, "
        f"Fri 08:00–11:30 & 13:00–{work_end_str} {tz_label} "
        f"(excludes Jumatan 11:30–13:00)"
    )


def _get_indonesian_tz(timezone_str: str) -> timezone:
    """Return a tzinfo for Indonesian zones (works on Windows without tzdata)."""
    offsets = {
        TZ_WIB: timezone(timedelta(hours=7)),
        TZ_WITA: timezone(timedelta(hours=8)),
        TZ_WIT: timezone(timedelta(hours=9)),
    }
    if timezone_str in offsets:
        return offsets[timezone_str]
    try:
        return ZoneInfo(timezone_str)  # type: ignore[return-value]
    except Exception:
        return offsets[TZ_WIB]


def compute_scheduled_send_at(
    timezone_str: str = TZ_WIB,
    now_utc: datetime | None = None,
    is_ramadan: bool = False,
) -> tuple[datetime, str]:
    """
    Compute the earliest safe send timestamp (UTC-aware) and the rule applied.

    Rules enforced (BR-04, TR-09):
    - Weekend (Sat/Sun): defer to Monday 08:00 local
    - Before 08:00 local: defer to 08:00 same day local
    - Friday Jumatan (11:30-13:00 local): defer to Friday 13:00 local
    - After hours (>=17:00 local, or >=15:00 in Ramadan): defer to next workday 08:00 local
    """
    ref_utc = now_utc or datetime.now(timezone.utc)
    if ref_utc.tzinfo is None:
        ref_utc = ref_utc.replace(tzinfo=timezone.utc)

    local_tz = _get_indonesian_tz(timezone_str)
    local_dt = ref_utc.astimezone(local_tz)
    work_end = RAMADAN_AFTER_HOURS_START if is_ramadan else WORK_END

    if local_dt.weekday() >= 5:
        deferred = defer_to_next_workday(local_dt, is_ramadan=is_ramadan)
        return deferred.astimezone(timezone.utc), "BR-04_WEEKEND_DEFER"

    if local_dt.time() < WORK_START:
        scheduled = local_dt.replace(hour=8, minute=0, second=0, microsecond=0)
        return scheduled.astimezone(timezone.utc), "BR-04_PRE_HOURS_DEFER"

    if is_within_jumatan(local_dt):
        scheduled = local_dt.replace(hour=13, minute=0, second=0, microsecond=0)
        return scheduled.astimezone(timezone.utc), "BR-04_JUMATAN_DEFER"

    if local_dt.time() >= work_end:
        deferred = defer_to_next_workday(local_dt, is_ramadan=is_ramadan)
        rule = "BR-04_RAMADAN_DEFER" if is_ramadan else "BR-04_AFTER_HOURS_DEFER"
        return deferred.astimezone(timezone.utc), rule

    return ref_utc, "IMMEDIATE_WITHIN_HOURS"


def build_wa_handoff_link(phone_wa: str, body_draft: str = "") -> str:
    """Build a https://wa.me/ handoff URL for E.164 WhatsApp numbers."""
    digits = re.sub(r"[^\d]", "", phone_wa or "")
    if not digits:
        return ""
    if digits.startswith("0"):
        digits = "62" + digits[1:]
    base = f"https://wa.me/{digits}"
    if body_draft:
        return f"{base}?text={quote(body_draft[:1000])}"
    return base

# ============================================================================
# Peer Privacy Rule (TR-10)
# ============================================================================

def apply_peer_privacy(profile_data: dict) -> dict:
    """
    If category == 'peer', strip all personal behavioral data.
    Peer profiles get timing_only personalization.

    Removes: sentiment_mix, open_complaints, private notes
    Keeps: timezone, work hours, best_contact_window, role_title, org_name
    """
    if profile_data.get("category") != "peer":
        return profile_data

    # Enforce timing_only for peers
    profile_data["personalization_level"] = "timing_only"
    # Strip behavioral/privacy-sensitive fields
    profile_data["sentiment_mix"] = {}
    profile_data["open_complaints"] = []
    profile_data["top_intents"] = {}
    # Strip v3 psychographic & relational intelligence (keep timing-only comms prefs)
    profile_data["character_style"] = "unknown"
    profile_data["churn_risk_level"] = "low"
    profile_data["character_profile"] = {}
    profile_data["motivation_and_pain"] = {}
    profile_data["persuasion_profile"] = {}
    profile_data["relationship_health"] = {}
    profile_data["agent_brief"] = ""

    return profile_data

# ============================================================================
# Fleet Unit Normalization (Heavy Machinery Domain)
# ============================================================================

# Known Komatsu/heavy machinery fleet unit patterns
FLEET_UNIT_PATTERN = re.compile(
    r"\b("
    r"HD\d{3}[-]?\d+"           # HD785-7 (Dump Truck)
    r"|PC\d{3}[-]?\w*(?:[-]\d+)?"  # PC200-8M0, PC400LC-8, PC300-8M0 (Excavator)
    r"|D\d{2}[A-Z]*[-]?\d*"      # D85ESS-2 (Bulldozer)
    r"|GD\d{3}[-]?\d+"           # GD535-5 (Motor Grader)
    r"|WA\d{3}[-]?\d+"           # WA380-6 (Wheel Loader)
    r"|VR\d{3}[-]?\w*"           # Vibratory Roller
    r")\b",
    re.IGNORECASE
)


def extract_fleet_units(text: str) -> list[str]:
    """
    Extract fleet unit model numbers from message text.
    Returns unique, uppercase list of matched units.
    """
    matches = FLEET_UNIT_PATTERN.findall(text)
    # Normalize: uppercase, remove duplicate whitespace in model
    seen = []
    for m in matches:
        normalized = re.sub(r"\s+", "", m.upper())
        if normalized not in seen:
            seen.append(normalized)
    return seen

# ============================================================================
# Salutation Inference
# ============================================================================

# Indonesian name -> gendered salutation inference
# This is a heuristic based on common Indonesian names
MALE_NAME_INDICATORS = {"budi", "hendra", "surya", "rendi", "andi", "ahmad", "bambang",
                        "dwi", "agus", "bayu", "erik", "fajar", "gunawan", "hadi",
                        "iman", "joko", "krisna", "luki", "made", "nanda", "putra",
                        "rizki", "satu", "tama", "wahyu", "yoga", "yusuf", "rifat"}
FEMALE_NAME_INDICATORS = {"siti", "dewi", "putri", "nia", "rina", "sri", "ani", "maya",
                          "lara", "sari", "wulan", "citra", "indah", "kartika", "mayang",
                          "nurul", "ratna", "tari", "utami", "yanti"}


def infer_salutation(full_name: str) -> str:
    """
    Infer Indonesian salutation from name.
    Returns 'formal_bapak' (male) or 'formal_ibu' (female).
    Default: 'formal_bapak' (conservative default).
    """
    first_name = full_name.lower().split()[0] if full_name else ""
    if first_name in FEMALE_NAME_INDICATORS:
        return "formal_ibu"
    # Also check for "ibu" prefix in the name
    if "ibu" in full_name.lower().split():
        return "formal_ibu"
    return "formal_bapak"

# ============================================================================
# Contact ID & Master ID Generation
# ============================================================================

def generate_contact_id(full_name: str, org_name: str = "") -> str:
    """
    Generate a deterministic contact_id from name and org.
    Format: c_<firstname>_<lastinitial> or c_<firstname>_<org_prefix>

    Examples:
        "Budi Santoso" -> "c_budi_s"
        "Hendra Pratama" -> "c_hendra_p"
    """
    parts = full_name.lower().strip().split()
    if not parts:
        return "c_unknown"
    first = re.sub(r"[^a-z]", "", parts[0])
    if len(parts) > 1:
        last = re.sub(r"[^a-z]", "", parts[-1])
        last_initial = last[0] if last else "x"
    else:
        last_initial = "x"
    return f"c_{first}_{last_initial}"


def generate_master_id(contact_id: str, org_name: str = "") -> str:
    """
    Generate a master_id from contact_id and optional org prefix.
    Format: mp_<contact_id without c_ prefix> or mp_<org_prefix>_<name>

    Examples:
        "c_budi_s" -> "mp_c_budi_s"
        "c_hendra_p", "PT Borneo Karya Tambang" -> "mp_bkt_hendra"
    """
    if org_name:
        # Extract org prefix: PT Borneo Karya Tambang -> bkt
        org_words = re.findall(r"[A-Z]", org_name.split("PT")[-1].strip()) if "PT" in org_name else []
        org_prefix = "".join(org_words[:4]).lower()
        if org_prefix:
            name_part = contact_id.replace("c_", "")
            return f"mp_{org_prefix}_{name_part}"
    return f"mp_{contact_id}"
