"""Fail-closed, read-only capacity decisions from the normalized quota cache.

This module is intentionally independent from the queue, tick planner, process
control, environment variables, and every provider API.  A caller supplies the
absolute path to ``ai-quotas-state.json`` and one exact wall-clock timestamp.
The cache is read once, validated, and reduced to immutable Claude quota
evidence.  No reset timestamp is treated as permission: a later, fresh cache
observation must show capacity before work is admitted again.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType
from typing import Mapping


__all__ = [
    "CACHE_SCHEMA_VERSION",
    "MAX_CACHE_BYTES",
    "PROFILE_ALIASES",
    "MODEL_FAMILIES",
    "ModelFamily",
    "CapacityReason",
    "QuotaPolicy",
    "WindowSample",
    "AccountQuota",
    "QuotaSnapshot",
    "CapacityDecision",
    "QuotaEvidenceError",
    "QuotaBindingError",
    "load_snapshot",
    "decide",
]


CACHE_SCHEMA_VERSION = 1
MAX_CACHE_BYTES = 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_HUNDRED = Decimal("100")
_USE_LIMITING_RESET = object()


class ModelFamily(str, Enum):
    FABLE = "fable"
    OPUS = "opus"


# These are bindings, not normalization rules.  New spellings require an
# explicit reviewed code change; prefix matching could silently select a model
# whose quota semantics are unknown.
PROFILE_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        "claude": ".claude",
        "claude-work": ".claude-work",
        "claude-test1": ".claude-test1",
        "claude-test2": ".claude-test2",
        "claude-test3": ".claude-test3",
    }
)
MODEL_FAMILIES: Mapping[str, ModelFamily] = MappingProxyType(
    {
        "fable-5": ModelFamily.FABLE,
        "claude-fable-5": ModelFamily.FABLE,
        "opus-4.8": ModelFamily.OPUS,
        "claude-opus-4-8": ModelFamily.OPUS,
    }
)


class CapacityReason(str, Enum):
    ADMITTED = "admitted"
    FABLE_EXHAUSTED = "fable-exhausted"
    FABLE_RESERVE = "fable-reserve"
    GENERAL_WEEK_RESERVE = "general-week-reserve"
    FIVE_HOUR_RESERVE = "five-hour-reserve"


class QuotaEvidenceError(ValueError):
    """The normalized cache cannot safely support a capacity decision."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class QuotaBindingError(QuotaEvidenceError):
    """A task profile/model cannot be bound to the closed quota contract."""


def _exact_int(value: object, code: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise QuotaEvidenceError(code)
    return value


def _reserve(value: object, code: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise QuotaEvidenceError(code)
    if value < Decimal(0) or value >= _HUNDRED:
        raise QuotaEvidenceError(code)
    return value


@dataclass(frozen=True, slots=True)
class QuotaPolicy:
    cache_max_age_s: int = 180
    observation_max_age_s: int = 600
    future_skew_s: int = 30
    fable_reserve_pct: Decimal = Decimal("5")
    general_week_reserve_pct: Decimal = Decimal("5")
    five_hour_reserve_pct: Decimal = Decimal("10")

    def __post_init__(self) -> None:
        _exact_int(self.cache_max_age_s, "cache-max-age-invalid", minimum=1)
        _exact_int(
            self.observation_max_age_s,
            "observation-max-age-invalid",
            minimum=1,
        )
        _exact_int(self.future_skew_s, "future-skew-invalid")
        _reserve(self.fable_reserve_pct, "fable-reserve-invalid")
        _reserve(self.general_week_reserve_pct, "general-week-reserve-invalid")
        _reserve(self.five_hour_reserve_pct, "five-hour-reserve-invalid")


@dataclass(frozen=True, slots=True)
class WindowSample:
    key: str
    used_pct: Decimal
    reset_at_s: int | None
    observed_at_s: int
    stale: bool
    source: str

    @property
    def remaining_pct(self) -> Decimal:
        return _HUNDRED - self.used_pct


@dataclass(frozen=True, slots=True)
class AccountQuota:
    cache_profile: str
    last_success_s: int
    auth_valid: bool
    collector_success: bool
    fallback_active: bool
    source: str
    five_hour: WindowSample | None
    seven_day: WindowSample | None
    fable_week: WindowSample | None


@dataclass(frozen=True, slots=True)
class QuotaSnapshot:
    generated_at_s: int
    validated_at_s: int
    accounts: Mapping[str, AccountQuota]


@dataclass(frozen=True, slots=True)
class CapacityDecision:
    allowed: bool
    reason: CapacityReason
    profile: str
    model: str
    family: ModelFamily
    effective_remaining_pct: Decimal
    reset_at_s: int | None
    limiting_windows: tuple[str, ...]
    observed_at_s: int

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool:
            raise QuotaEvidenceError("decision-allowed-invalid")
        if type(self.reason) is not CapacityReason:
            raise QuotaEvidenceError("decision-reason-invalid")
        if type(self.family) is not ModelFamily:
            raise QuotaEvidenceError("decision-family-invalid")
        if self.allowed is not (self.reason is CapacityReason.ADMITTED):
            raise QuotaEvidenceError("decision-reason-inconsistent")


_TOP_KEYS = frozenset({"SchemaVersion", "GeneratedAt", "Accounts"})
_ACCOUNT_REQUIRED_KEYS = frozenset(
    {
        "Provider",
        "Profile",
        "Source",
        "AuthValid",
        "CollectorSuccess",
        "FallbackActive",
        "LastSuccessTimestampSeconds",
        "Windows",
    }
)
_ACCOUNT_ALLOWED_KEYS = frozenset(
    {
        "Provider",
        "Profile",
        "Plan",
        "Tier",
        "Source",
        "AuthValid",
        "CollectorSuccess",
        "FallbackActive",
        "LastPollTimestampSeconds",
        "LastSuccessTimestampSeconds",
        "Windows",
        "Spend",
        "Credits",
        "ResetCreditsAvailable",
        "OAuthRefreshSucceeded",
        "OAuthRefreshOutcome",
        "OAuthRefreshLastAttemptTimestampSeconds",
        "OAuthRefreshNextAttemptTimestampSeconds",
    }
)
_WINDOW_REQUIRED_KEYS = frozenset(
    {
        "Bucket",
        "Window",
        "ScopeType",
        "Scope",
        "UsedPercent",
        "ResetsAtUnixSeconds",
        "CollectedAtUnixSeconds",
        "Source",
        "Stale",
    }
)
_WINDOW_ALLOWED_KEYS = frozenset(
    {
        "Bucket",
        "Window",
        "ScopeType",
        "Scope",
        "UsedPercent",
        "WindowDurationMinutes",
        "ResetsAtUnixSeconds",
        "Active",
        "CollectedAtUnixSeconds",
        "Source",
        "Stale",
    }
)
_WINDOW_IDENTITIES = {
    ("session", "five_hour", "none", ""): "five_hour",
    ("weekly_all", "seven_day", "none", ""): "seven_day",
    ("weekly_scoped", "weekly_scoped", "model", "Fable"): "fable_week",
}


def _path_components(path: Path) -> tuple[Path, ...]:
    anchor = Path(path.anchor)
    current = anchor
    result = [anchor]
    for part in path.parts[1:]:
        current = current / part
        result.append(current)
    return tuple(result)


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _REPARSE_POINT)


def _read_cache_bytes(path: Path) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise QuotaEvidenceError("cache-path-invalid")

    final_info: os.stat_result | None = None
    for component in _path_components(path):
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            raise QuotaEvidenceError("cache-missing") from None
        except OSError:
            raise QuotaEvidenceError("cache-path-unreadable") from None
        if _is_reparse(info):
            raise QuotaEvidenceError("cache-reparse-forbidden")
        final_info = info

    if final_info is None or not stat.S_ISREG(final_info.st_mode):
        raise QuotaEvidenceError("cache-not-regular")
    if final_info.st_nlink != 1:
        raise QuotaEvidenceError("cache-hardlink-forbidden")
    if final_info.st_size > MAX_CACHE_BYTES:
        raise QuotaEvidenceError("cache-too-large")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise QuotaEvidenceError("cache-open-failed") from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (final_info.st_dev, final_info.st_ino)
        ):
            raise QuotaEvidenceError("cache-identity-changed")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, MAX_CACHE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CACHE_BYTES:
                raise QuotaEvidenceError("cache-too-large")
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_size != opened.st_size
        ):
            raise QuotaEvidenceError("cache-changed-during-read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _reject_constant(_value: str) -> object:
    raise QuotaEvidenceError("cache-nonfinite-number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise QuotaEvidenceError("cache-duplicate-json-key")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, object]:
    raw = _read_cache_bytes(path)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise QuotaEvidenceError("cache-utf8-invalid") from None
    try:
        document = json.loads(
            text,
            parse_float=Decimal,
            parse_int=int,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except QuotaEvidenceError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise QuotaEvidenceError("cache-json-invalid") from None
    if type(document) is not dict:
        raise QuotaEvidenceError("cache-document-invalid")
    return document


def _iso_timestamp(value: object, code: str) -> int:
    if type(value) is not str or not value:
        raise QuotaEvidenceError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise QuotaEvidenceError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QuotaEvidenceError(code)
    delta = parsed.astimezone(timezone.utc) - _EPOCH
    seconds = delta.days * 86400 + delta.seconds
    if seconds < 0:
        raise QuotaEvidenceError(code)
    return seconds


def _check_fresh(
    timestamp_s: int,
    *,
    now_s: int,
    max_age_s: int,
    future_skew_s: int,
    stale_code: str,
    future_code: str,
) -> None:
    if timestamp_s > now_s + future_skew_s:
        raise QuotaEvidenceError(future_code)
    if now_s - timestamp_s > max_age_s:
        raise QuotaEvidenceError(stale_code)


def _percentage(value: object) -> Decimal:
    if type(value) is int:
        result = Decimal(value)
    elif type(value) is Decimal:
        result = value
    else:
        raise QuotaEvidenceError("window-used-percent-invalid")
    if not result.is_finite() or result < 0 or result > _HUNDRED:
        raise QuotaEvidenceError("window-used-percent-invalid")
    return result


def _optional_timestamp(value: object, code: str) -> int | None:
    if value is None:
        return None
    exact = _exact_int(value, code)
    return None if exact == 0 else exact


def _parse_window(value: object) -> tuple[str, WindowSample] | None:
    if type(value) is not dict:
        raise QuotaEvidenceError("window-invalid")
    keys = frozenset(value)
    if not _WINDOW_REQUIRED_KEYS.issubset(keys) or not keys.issubset(
        _WINDOW_ALLOWED_KEYS
    ):
        raise QuotaEvidenceError("window-schema-invalid")
    identity = (
        value["Bucket"],
        value["Window"],
        value["ScopeType"],
        value["Scope"],
    )
    if any(type(item) is not str for item in identity):
        raise QuotaEvidenceError("window-identity-invalid")
    key = _WINDOW_IDENTITIES.get(identity)
    if key is None:
        return None
    if "Active" in value and type(value["Active"]) is not bool:
        raise QuotaEvidenceError("window-active-invalid")
    duration = value.get("WindowDurationMinutes")
    if duration is not None:
        _exact_int(duration, "window-duration-invalid", minimum=1)
    if type(value["Source"]) is not str:
        raise QuotaEvidenceError("window-source-invalid")
    if type(value["Stale"]) is not bool:
        raise QuotaEvidenceError("window-stale-invalid")
    sample = WindowSample(
        key=key,
        used_pct=_percentage(value["UsedPercent"]),
        reset_at_s=_optional_timestamp(
            value["ResetsAtUnixSeconds"], "window-reset-invalid"
        ),
        observed_at_s=_exact_int(
            value["CollectedAtUnixSeconds"],
            "window-observed-at-invalid",
            minimum=1,
        ),
        stale=value["Stale"],
        source=value["Source"],
    )
    return key, sample


def _parse_account(value: dict[str, object]) -> AccountQuota:
    keys = frozenset(value)
    if not _ACCOUNT_REQUIRED_KEYS.issubset(keys) or not keys.issubset(
        _ACCOUNT_ALLOWED_KEYS
    ):
        raise QuotaEvidenceError("account-schema-invalid")
    if value["Provider"] != "claude":
        raise QuotaEvidenceError("account-provider-invalid")
    profile = value["Profile"]
    if type(profile) is not str:
        raise QuotaEvidenceError("account-profile-invalid")
    for key in ("AuthValid", "CollectorSuccess", "FallbackActive"):
        if type(value[key]) is not bool:
            raise QuotaEvidenceError("account-status-invalid")
    if type(value["Source"]) is not str:
        raise QuotaEvidenceError("account-source-invalid")
    windows_value = value["Windows"]
    if type(windows_value) is not list:
        raise QuotaEvidenceError("account-windows-invalid")
    samples: dict[str, WindowSample] = {}
    for window_value in windows_value:
        parsed = _parse_window(window_value)
        if parsed is None:
            continue
        key, sample = parsed
        if key in samples:
            raise QuotaEvidenceError("window-duplicate")
        samples[key] = sample
    return AccountQuota(
        cache_profile=profile,
        last_success_s=_exact_int(
            value["LastSuccessTimestampSeconds"],
            "account-last-success-invalid",
            minimum=1,
        ),
        auth_valid=value["AuthValid"],
        collector_success=value["CollectorSuccess"],
        fallback_active=value["FallbackActive"],
        source=value["Source"],
        five_hour=samples.get("five_hour"),
        seven_day=samples.get("seven_day"),
        fable_week=samples.get("fable_week"),
    )


def load_snapshot(
    path: Path,
    *,
    now_s: int,
    policy: QuotaPolicy = QuotaPolicy(),
) -> QuotaSnapshot:
    """Read one normalized cache snapshot without any provider fallback."""

    _exact_int(now_s, "now-invalid")
    if type(policy) is not QuotaPolicy:
        raise QuotaEvidenceError("policy-invalid")
    document = _read_json(path)
    if frozenset(document) != _TOP_KEYS:
        raise QuotaEvidenceError("cache-schema-invalid")
    if (
        type(document["SchemaVersion"]) is not int
        or document["SchemaVersion"] != CACHE_SCHEMA_VERSION
    ):
        raise QuotaEvidenceError("cache-version-invalid")
    generated_at_s = _iso_timestamp(
        document["GeneratedAt"], "cache-generated-at-invalid"
    )
    _check_fresh(
        generated_at_s,
        now_s=now_s,
        max_age_s=policy.cache_max_age_s,
        future_skew_s=policy.future_skew_s,
        stale_code="cache-stale",
        future_code="cache-generated-in-future",
    )
    accounts_value = document["Accounts"]
    if type(accounts_value) is not list:
        raise QuotaEvidenceError("cache-accounts-invalid")

    known_cache_profiles = frozenset(PROFILE_ALIASES.values())
    accounts: dict[str, AccountQuota] = {}
    for value in accounts_value:
        if type(value) is not dict:
            raise QuotaEvidenceError("cache-account-invalid")
        provider = value.get("Provider")
        profile = value.get("Profile")
        if type(provider) is not str or type(profile) is not str:
            raise QuotaEvidenceError("cache-account-identity-invalid")
        if provider != "claude" or profile not in known_cache_profiles:
            continue
        if profile in accounts:
            raise QuotaEvidenceError("account-duplicate")
        accounts[profile] = _parse_account(value)

    return QuotaSnapshot(
        generated_at_s=generated_at_s,
        validated_at_s=now_s,
        accounts=MappingProxyType(accounts),
    )


def _validate_sample(
    sample: WindowSample | None,
    *,
    key: str,
    snapshot: QuotaSnapshot,
    policy: QuotaPolicy,
) -> WindowSample:
    if sample is None:
        raise QuotaEvidenceError(f"{key}-window-missing")
    if sample.key != key:
        raise QuotaEvidenceError(f"{key}-window-binding-invalid")
    if sample.source != "oauth":
        raise QuotaEvidenceError(f"{key}-window-source-invalid")
    if sample.stale:
        raise QuotaEvidenceError(f"{key}-window-stale")
    _check_fresh(
        sample.observed_at_s,
        now_s=snapshot.validated_at_s,
        max_age_s=policy.observation_max_age_s,
        future_skew_s=policy.future_skew_s,
        stale_code=f"{key}-window-observation-stale",
        future_code=f"{key}-window-observation-future",
    )
    return sample


def _limiting(samples: tuple[WindowSample, ...]) -> tuple[Decimal, tuple[str, ...], int | None]:
    remaining = min(sample.remaining_pct for sample in samples)
    limiting = tuple(sample for sample in samples if sample.remaining_pct == remaining)
    resets = tuple(
        sample.reset_at_s for sample in limiting if sample.reset_at_s is not None
    )
    return (
        remaining,
        tuple(sample.key for sample in limiting),
        min(resets) if resets else None,
    )


def _decision(
    *,
    allowed: bool,
    reason: CapacityReason,
    profile: str,
    model: str,
    family: ModelFamily,
    samples: tuple[WindowSample, ...],
    reset_at_s: int | None | object = _USE_LIMITING_RESET,
) -> CapacityDecision:
    remaining, limiting_windows, limiting_reset = _limiting(samples)
    return CapacityDecision(
        allowed=allowed,
        reason=reason,
        profile=profile,
        model=model,
        family=family,
        effective_remaining_pct=remaining,
        reset_at_s=(
            limiting_reset
            if reset_at_s is _USE_LIMITING_RESET
            else reset_at_s
        ),
        limiting_windows=limiting_windows,
        observed_at_s=min(sample.observed_at_s for sample in samples),
    )


def decide(
    snapshot: QuotaSnapshot,
    *,
    profile: str,
    model: str,
    policy: QuotaPolicy = QuotaPolicy(),
) -> CapacityDecision:
    """Return capacity only for one exact, recognized task binding.

    Evidence errors are distinct from ordinary capacity exhaustion.  A future
    ``TickEvidenceAdapter.peek_prepared`` must propagate those errors so the
    existing tick planner writes a fail-closed HALT instead of silently
    starving a malformed task.
    """

    if type(snapshot) is not QuotaSnapshot:
        raise QuotaEvidenceError("snapshot-invalid")
    if type(policy) is not QuotaPolicy:
        raise QuotaEvidenceError("policy-invalid")
    if type(profile) is not str or profile not in PROFILE_ALIASES:
        raise QuotaBindingError("profile-binding-unknown")
    if type(model) is not str or model not in MODEL_FAMILIES:
        raise QuotaBindingError("model-binding-unknown")
    family = MODEL_FAMILIES[model]
    account = snapshot.accounts.get(PROFILE_ALIASES[profile])
    if account is None:
        raise QuotaBindingError("profile-cache-missing")
    if account.cache_profile != PROFILE_ALIASES[profile]:
        raise QuotaEvidenceError("profile-cache-binding-invalid")
    if not account.auth_valid:
        raise QuotaEvidenceError("account-auth-invalid")
    if not account.collector_success:
        raise QuotaEvidenceError("account-collector-failed")
    if account.fallback_active:
        raise QuotaEvidenceError("account-fallback-active")
    if account.source != "oauth":
        raise QuotaEvidenceError("account-source-invalid")
    _check_fresh(
        account.last_success_s,
        now_s=snapshot.validated_at_s,
        max_age_s=policy.observation_max_age_s,
        future_skew_s=policy.future_skew_s,
        stale_code="account-observation-stale",
        future_code="account-observation-future",
    )

    five = _validate_sample(
        account.five_hour,
        key="five_hour",
        snapshot=snapshot,
        policy=policy,
    )
    week = _validate_sample(
        account.seven_day,
        key="seven_day",
        snapshot=snapshot,
        policy=policy,
    )
    samples: tuple[WindowSample, ...]

    if family is ModelFamily.FABLE:
        fable = _validate_sample(
            account.fable_week,
            key="fable_week",
            snapshot=snapshot,
            policy=policy,
        )
        samples = (fable, five, week)
        if fable.remaining_pct == 0:
            return _decision(
                allowed=False,
                reason=CapacityReason.FABLE_EXHAUSTED,
                profile=profile,
                model=model,
                family=family,
                samples=samples,
                reset_at_s=fable.reset_at_s,
            )
        if fable.remaining_pct <= policy.fable_reserve_pct:
            return _decision(
                allowed=False,
                reason=CapacityReason.FABLE_RESERVE,
                profile=profile,
                model=model,
                family=family,
                samples=samples,
                reset_at_s=fable.reset_at_s,
            )
    else:
        samples = (five, week)

    if week.remaining_pct <= policy.general_week_reserve_pct:
        return _decision(
            allowed=False,
            reason=CapacityReason.GENERAL_WEEK_RESERVE,
            profile=profile,
            model=model,
            family=family,
            samples=samples,
            reset_at_s=week.reset_at_s,
        )
    if five.remaining_pct <= policy.five_hour_reserve_pct:
        return _decision(
            allowed=False,
            reason=CapacityReason.FIVE_HOUR_RESERVE,
            profile=profile,
            model=model,
            family=family,
            samples=samples,
            reset_at_s=five.reset_at_s,
        )
    return _decision(
        allowed=True,
        reason=CapacityReason.ADMITTED,
        profile=profile,
        model=model,
        family=family,
        samples=samples,
    )
