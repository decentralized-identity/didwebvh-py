from datetime import datetime, timedelta, timezone

import pytest

from did_webvh.core.date_utils import create_next_version_time


def test_create_next_version_time_uses_requested_when_later():
    previous = "2020-01-01T00:00:00Z"
    requested = datetime(2030, 1, 1, tzinfo=timezone.utc)
    ts, raw = create_next_version_time(previous, requested)
    assert raw == "2030-01-01T00:00:00Z"
    assert ts == requested


def test_create_next_version_time_bumps_when_now_not_later():
    future = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=1)
    previous_raw = future.isoformat().replace("+00:00", "Z")
    ts, raw = create_next_version_time(previous_raw)
    assert ts == future + timedelta(seconds=1)
    assert raw == ts.isoformat().replace("+00:00", "Z")


def test_create_next_version_time_rejects_requested_not_after_previous():
    previous = "2024-06-01T12:00:00Z"
    with pytest.raises(ValueError, match="greater than previous"):
        create_next_version_time(previous, "2024-06-01T11:59:59Z")
    with pytest.raises(ValueError, match="greater than previous"):
        create_next_version_time(previous, "2024-06-01T12:00:00Z")


def test_create_next_version_time_bumps_from_previous_when_clocks_match(monkeypatch):
    previous = "2099-06-01T12:00:00Z"
    fixed_now = datetime(2099, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr("did_webvh.core.date_utils.datetime", FixedDatetime)
    bumped, bumped_raw = create_next_version_time(previous)
    assert bumped == datetime(2099, 6, 1, 12, 0, 1, tzinfo=timezone.utc)
    assert bumped_raw == "2099-06-01T12:00:01Z"
