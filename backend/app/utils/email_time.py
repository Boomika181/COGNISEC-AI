"""Centralized UTC-to-display-timezone formatting utilities for COGNISEC-AI emails."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Union
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_DISPLAY_TIMEZONE = "Asia/Kolkata"
_UNAVAILABLE_FALLBACK = "Unavailable (server timestamp missing)"


def resolve_display_timezone(target_tz: Optional[str] = None) -> ZoneInfo:
    """Resolve a valid ZoneInfo, defaulting to Asia/Kolkata (IST, UTC+05:30)."""
    candidate = (target_tz or "").strip() or DEFAULT_DISPLAY_TIMEZONE
    try:
        return ZoneInfo(candidate)
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        return ZoneInfo(DEFAULT_DISPLAY_TIMEZONE)


def ensure_utc(value: Optional[Union[datetime, str]]) -> Optional[datetime]:
    """
    Normalize a datetime or timestamp string into a timezone-aware UTC datetime.
    Returns None if missing or unparseable.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if not isinstance(value, str):
        return None

    raw = value.strip()
    if not raw:
        return None

    # Handle explicit "UTC" suffix (e.g. "2026-11-12 10:00:00 UTC")
    if raw.upper().endswith(" UTC"):
        inner = raw[:-4].strip()
        parsed = _parse_naive_or_iso(inner)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    # Handle explicit "IST" suffix (e.g. "2026-11-12 15:30:00 IST")
    if raw.upper().endswith(" IST"):
        inner = raw[:-4].strip()
        parsed = _parse_naive_or_iso(inner)
        if parsed is None:
            return None
        ist = ZoneInfo(DEFAULT_DISPLAY_TIMEZONE)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=ist).astimezone(timezone.utc)
        return parsed.astimezone(timezone.utc)

    parsed = _parse_naive_or_iso(raw)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_naive_or_iso(raw: str) -> Optional[datetime]:
    iso_candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        return datetime.fromisoformat(iso_candidate)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d %B %Y, %I:%M %p",
        "%d %b %Y, %I:%M %p",
    ):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def format_readable_datetime(dt_local: datetime) -> str:
    """Format a timezone-aware datetime as e.g. '12 November 2026, 3:30 PM IST'."""
    hour = dt_local.strftime("%I").lstrip("0") or "12"
    tz_abbr = dt_local.tzname() or "IST"
    return f"{dt_local.day} {dt_local.strftime('%B %Y')}, {hour}:{dt_local.strftime('%M %p')} {tz_abbr}"


def format_email_timestamp(
    value: Optional[Union[datetime, str]],
    target_tz: Optional[str] = None,
    fallback: str = _UNAVAILABLE_FALLBACK,
) -> str:
    """Convert a UTC/aware datetime or timestamp string to the display timezone (IST by default)."""
    dt_utc = ensure_utc(value)
    if dt_utc is None:
        return fallback
    tz = resolve_display_timezone(target_tz)
    return format_readable_datetime(dt_utc.astimezone(tz))


def format_appointment_datetime(
    appointment_date: Optional[str],
    time_slot: Optional[str],
    target_tz: Optional[str] = None,
) -> str:
    """
    Format a hospital-scheduled appointment date + slot (in Asia/Kolkata) into the display timezone.
    Example: ('2026-11-13', '09:00 AM') -> '13 November 2026, 9:00 AM IST'.
    """
    date_str = (appointment_date or "").strip()
    slot_str = (time_slot or "").strip()
    if not date_str or not slot_str:
        return "Unavailable (appointment schedule missing)"

    ist = ZoneInfo(DEFAULT_DISPLAY_TIMEZONE)
    combined = f"{date_str} {slot_str}"
    parsed: Optional[datetime] = None
    for fmt in ("%Y-%m-%d %I:%M %p", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(combined, fmt)
            break
        except ValueError:
            continue

    if parsed is None:
        return f"{date_str}, {slot_str} IST"

    aware_ist = parsed.replace(tzinfo=ist)
    tz = resolve_display_timezone(target_tz)
    return format_readable_datetime(aware_ist.astimezone(tz))


def compute_expiry_display(
    issued_at: Optional[Union[datetime, str]] = None,
    expires_at: Optional[Union[datetime, str]] = None,
    expires_in_minutes: Optional[int] = None,
    target_tz: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    Return (issued_display, expires_display, remaining_label) in the target display timezone.
    Derives expiry from expires_at when provided; never extends expired OTPs.
    """
    if issued_at is not None:
        issued_utc = ensure_utc(issued_at)
        if issued_utc is None:
            return (_UNAVAILABLE_FALLBACK, _UNAVAILABLE_FALLBACK, "Unavailable")
    else:
        issued_utc = datetime.now(timezone.utc)

    if expires_at is not None:
        expires_utc = ensure_utc(expires_at)
        if expires_utc is None:
            return (
                format_email_timestamp(issued_utc, target_tz=target_tz),
                _UNAVAILABLE_FALLBACK,
                "Unavailable",
            )
    else:
        ttl_mins = max(1, int(expires_in_minutes or 5))
        expires_utc = issued_utc + timedelta(minutes=ttl_mins)

    delta_seconds = int((expires_utc - issued_utc).total_seconds())
    if delta_seconds <= 0:
        remaining_label = "Expired"
    elif delta_seconds < 60:
        remaining_label = f"{delta_seconds} second" if delta_seconds == 1 else f"{delta_seconds} seconds"
    else:
        mins = max(1, round(delta_seconds / 60))
        remaining_label = f"{mins} minute" if mins == 1 else f"{mins} minutes"

    return (
        format_email_timestamp(issued_utc, target_tz=target_tz),
        format_email_timestamp(expires_utc, target_tz=target_tz),
        remaining_label,
    )

