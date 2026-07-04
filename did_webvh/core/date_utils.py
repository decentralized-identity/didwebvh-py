"""Date-time handling utilities."""

from datetime import datetime, timedelta, timezone
from typing import Union

MAX_FUTURE_SKEW = timedelta(minutes=5)


def iso_format_datetime(dt: datetime) -> str:
    """Convert a datetime to a string in ISO format."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def make_timestamp(timestamp: Union[datetime, str, None] = None) -> tuple[datetime, str]:
    """Convert from either a string or datetime value into a pair of both."""
    if not timestamp:
        timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    if isinstance(timestamp, str):
        timestamp_raw = timestamp
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        timestamp = datetime.fromisoformat(timestamp)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.replace(microsecond=0)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp_raw = iso_format_datetime(timestamp)
    return timestamp, timestamp_raw


def create_next_version_time(
    previous_version_time: str,
    requested_version_time: Union[datetime, str, None] = None,
) -> tuple[datetime, str]:
    """Choose a versionTime strictly after the previous log entry.

    Mirrors didwebvh-ts ``createNextVersionTime``: use the current time when it
    is already later than the previous entry, otherwise bump by one second.
    """
    previous, _ = make_timestamp(previous_version_time)

    if requested_version_time is not None:
        requested, requested_raw = make_timestamp(requested_version_time)
        if requested <= previous:
            raise ValueError("versionTime must be greater than previous versionTime")
        return requested, requested_raw

    now, now_raw = make_timestamp(None)
    if now <= previous:
        bumped = previous + timedelta(seconds=1)
        return bumped, iso_format_datetime(bumped)
    return now, now_raw
