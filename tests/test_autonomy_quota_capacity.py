from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from autonomy import quota_capacity as capacity


NOW = 2_000_000_000
FABLE_RESET = NOW + 50_000
WEEK_RESET = NOW + 60_000
FIVE_RESET = NOW + 7_000


def iso_time(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def window(
    key: str,
    used: object,
    *,
    observed: int = NOW - 30,
    reset: int | None = None,
    stale: bool = False,
    source: str = "oauth",
) -> dict:
    identities = {
        "five_hour": ("session", "five_hour", "none", ""),
        "seven_day": ("weekly_all", "seven_day", "none", ""),
        "fable_week": ("weekly_scoped", "weekly_scoped", "model", "Fable"),
    }
    bucket, name, scope_type, scope = identities[key]
    return {
        "Bucket": bucket,
        "Window": name,
        "ScopeType": scope_type,
        "Scope": scope,
        "UsedPercent": used,
        "WindowDurationMinutes": None,
        "ResetsAtUnixSeconds": reset,
        "Active": key == "fable_week",
        "CollectedAtUnixSeconds": observed,
        "Source": source,
        "Stale": stale,
    }


def account(
    profile: str = ".claude-work",
    *,
    five_used: object = 26,
    week_used: object = 54,
    fable_used: object = 60,
    last_success: int = NOW - 30,
) -> dict:
    return {
        "Provider": "claude",
        "Profile": profile,
        "Source": "oauth",
        "AuthValid": True,
        "CollectorSuccess": True,
        "FallbackActive": False,
        "LastSuccessTimestampSeconds": last_success,
        "Windows": [
            window("five_hour", five_used, reset=FIVE_RESET),
            window("seven_day", week_used, reset=WEEK_RESET),
            window("fable_week", fable_used, reset=FABLE_RESET),
        ],
    }


def document(*accounts: dict, generated: int = NOW - 10) -> dict:
    return {
        "SchemaVersion": 1,
        "GeneratedAt": iso_time(generated),
        "Accounts": list(accounts),
    }


class CacheCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "ai-quotas-state.json"

    def write(self, value: object) -> Path:
        self.path.write_text(
            json.dumps(value, ensure_ascii=True, allow_nan=False),
            encoding="utf-8",
        )
        return self.path

    def load(self, value: object | None = None, **kwargs):
        if value is None:
            value = document(account())
        self.write(value)
        return capacity.load_snapshot(self.path, now_s=NOW, **kwargs)

    def error(self, code: str, value: object | None = None, **kwargs) -> None:
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            self.load(value, **kwargs)
        self.assertEqual(code, caught.exception.code)


class CapacityDecisionTests(CacheCase):
    def test_opus_uses_minimum_of_general_windows(self) -> None:
        snapshot = self.load(document(account(five_used=26, week_used=54)))
        result = capacity.decide(
            snapshot, profile="claude-work", model="opus-4.8"
        )
        self.assertTrue(result.allowed)
        self.assertIs(result.reason, capacity.CapacityReason.ADMITTED)
        self.assertIs(result.family, capacity.ModelFamily.OPUS)
        self.assertEqual(Decimal("46"), result.effective_remaining_pct)
        self.assertEqual(("seven_day",), result.limiting_windows)
        self.assertEqual(WEEK_RESET, result.reset_at_s)

    def test_opus_decimal_percentage_is_not_rounded(self) -> None:
        snapshot = self.load(document(account(five_used=10.1, week_used=53.25)))
        result = capacity.decide(
            snapshot, profile="claude-work", model="claude-opus-4.8"
        )
        self.assertEqual(Decimal("46.75"), result.effective_remaining_pct)

    def test_opus_tied_windows_report_both_and_earliest_reset(self) -> None:
        value = account(five_used=40, week_used=40)
        snapshot = self.load(document(value))
        result = capacity.decide(
            snapshot, profile="claude-work", model="opus-4.8"
        )
        self.assertEqual(("five_hour", "seven_day"), result.limiting_windows)
        self.assertEqual(FIVE_RESET, result.reset_at_s)

    def test_fable_uses_scoped_and_both_general_windows(self) -> None:
        snapshot = self.load(
            document(account(five_used=20, week_used=30, fable_used=72))
        )
        result = capacity.decide(
            snapshot, profile="claude-work", model="fable-5"
        )
        self.assertTrue(result.allowed)
        self.assertIs(result.family, capacity.ModelFamily.FABLE)
        self.assertEqual(Decimal("28"), result.effective_remaining_pct)
        self.assertEqual(("fable_week",), result.limiting_windows)
        self.assertEqual(FABLE_RESET, result.reset_at_s)

    def test_fable_exhausted_is_a_nonfatal_stop_with_exact_reset(self) -> None:
        snapshot = self.load(document(account(fable_used=100)))
        result = capacity.decide(
            snapshot, profile="claude-work", model="claude-fable-5"
        )
        self.assertFalse(result.allowed)
        self.assertIs(result.reason, capacity.CapacityReason.FABLE_EXHAUSTED)
        self.assertEqual(Decimal("0"), result.effective_remaining_pct)
        self.assertEqual(FABLE_RESET, result.reset_at_s)

    def test_past_reset_never_locally_reenables_fable(self) -> None:
        value = account(fable_used=100)
        value["Windows"][2]["ResetsAtUnixSeconds"] = NOW - 1
        snapshot = self.load(document(value))
        result = capacity.decide(
            snapshot, profile="claude-work", model="fable-5"
        )
        self.assertFalse(result.allowed)
        self.assertIs(result.reason, capacity.CapacityReason.FABLE_EXHAUSTED)
        self.assertEqual(NOW - 1, result.reset_at_s)

    def test_exhausted_fable_with_unknown_reset_stays_stopped(self) -> None:
        for missing in (None, 0):
            with self.subTest(missing=missing):
                value = account(fable_used=100)
                value["Windows"][2]["ResetsAtUnixSeconds"] = missing
                snapshot = self.load(document(value))
                result = capacity.decide(
                    snapshot, profile="claude-work", model="fable-5"
                )
                self.assertFalse(result.allowed)
                self.assertIsNone(result.reset_at_s)

    def test_unknown_fable_reset_is_not_replaced_by_tied_general_reset(self) -> None:
        value = account(five_used=100, fable_used=100)
        value["Windows"][2]["ResetsAtUnixSeconds"] = None
        snapshot = self.load(document(value))
        result = capacity.decide(
            snapshot, profile="claude-work", model="fable-5"
        )
        self.assertFalse(result.allowed)
        self.assertIs(result.reason, capacity.CapacityReason.FABLE_EXHAUSTED)
        self.assertIsNone(result.reset_at_s)

    def test_fable_reserve_boundary_is_denied_and_above_is_admitted(self) -> None:
        denied = self.load(document(account(fable_used=95)))
        result = capacity.decide(
            denied, profile="claude-work", model="fable-5"
        )
        self.assertIs(result.reason, capacity.CapacityReason.FABLE_RESERVE)
        self.assertFalse(result.allowed)

        admitted = self.load(document(account(fable_used=94.99)))
        result = capacity.decide(
            admitted, profile="claude-work", model="fable-5"
        )
        self.assertTrue(result.allowed)

    def test_general_week_reserve_applies_to_both_families(self) -> None:
        for model in ("fable-5", "opus-4.8"):
            with self.subTest(model=model):
                snapshot = self.load(
                    document(account(week_used=95, fable_used=20))
                )
                result = capacity.decide(
                    snapshot, profile="claude-work", model=model
                )
                self.assertFalse(result.allowed)
                self.assertIs(
                    result.reason, capacity.CapacityReason.GENERAL_WEEK_RESERVE
                )
                self.assertEqual(WEEK_RESET, result.reset_at_s)

    def test_five_hour_reserve_applies_to_both_families(self) -> None:
        for model in ("fable-5", "opus-4.8"):
            with self.subTest(model=model):
                snapshot = self.load(
                    document(account(five_used=90, week_used=20, fable_used=20))
                )
                result = capacity.decide(
                    snapshot, profile="claude-work", model=model
                )
                self.assertFalse(result.allowed)
                self.assertIs(
                    result.reason, capacity.CapacityReason.FIVE_HOUR_RESERVE
                )
                self.assertEqual(FIVE_RESET, result.reset_at_s)

    def test_custom_decimal_reserves_are_exact(self) -> None:
        policy = capacity.QuotaPolicy(
            fable_reserve_pct=Decimal("1.25"),
            general_week_reserve_pct=Decimal("2.5"),
            five_hour_reserve_pct=Decimal("3.75"),
        )
        snapshot = self.load(document(account(fable_used=98.75)), policy=policy)
        result = capacity.decide(
            snapshot, profile="claude-work", model="fable-5", policy=policy
        )
        self.assertFalse(result.allowed)
        self.assertIs(result.reason, capacity.CapacityReason.FABLE_RESERVE)

    def test_exact_public_profile_aliases(self) -> None:
        accounts = [account(cache) for cache in capacity.PROFILE_ALIASES.values()]
        snapshot = self.load(document(*accounts))
        for public in capacity.PROFILE_ALIASES:
            with self.subTest(profile=public):
                result = capacity.decide(
                    snapshot, profile=public, model="opus-4.8"
                )
                self.assertTrue(result.allowed)
                self.assertEqual(public, result.profile)

    def test_unknown_profile_and_model_are_fatal_bindings(self) -> None:
        snapshot = self.load()
        cases = (
            (".claude-work", "opus-4.8", "profile-binding-unknown"),
            ("claude-work", "opus", "model-binding-unknown"),
            ("claude-work", "claude-opus-4.1", "model-binding-unknown"),
            ("claude-Work", "opus-4.8", "profile-binding-unknown"),
        )
        for profile, model, code in cases:
            with self.subTest(profile=profile, model=model):
                with self.assertRaises(capacity.QuotaBindingError) as caught:
                    capacity.decide(snapshot, profile=profile, model=model)
                self.assertEqual(code, caught.exception.code)

    def test_missing_selected_profile_is_fatal_binding(self) -> None:
        snapshot = self.load(document(account(".claude-test1")))
        with self.assertRaises(capacity.QuotaBindingError) as caught:
            capacity.decide(
                snapshot, profile="claude-work", model="opus-4.8"
            )
        self.assertEqual("profile-cache-missing", caught.exception.code)

    def test_opus_does_not_require_fable_specific_window(self) -> None:
        value = account()
        value["Windows"] = value["Windows"][:2]
        snapshot = self.load(document(value))
        self.assertTrue(
            capacity.decide(
                snapshot, profile="claude-work", model="opus-4.8"
            ).allowed
        )
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.decide(
                snapshot, profile="claude-work", model="fable-5"
            )
        self.assertEqual("fable_week-window-missing", caught.exception.code)


class FreshnessAndCollectorTests(CacheCase):
    def decision_error(self, value: dict, code: str, model: str = "opus-4.8") -> None:
        snapshot = self.load(document(value))
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.decide(snapshot, profile="claude-work", model=model)
        self.assertEqual(code, caught.exception.code)

    def test_cache_generated_at_age_boundary(self) -> None:
        self.load(document(account(), generated=NOW - 180))
        self.error("cache-stale", document(account(), generated=NOW - 181))

    def test_cache_future_skew_boundary(self) -> None:
        self.load(document(account(), generated=NOW + 30))
        self.error(
            "cache-generated-in-future",
            document(account(), generated=NOW + 31),
        )

    def test_naive_or_invalid_generated_at_is_rejected(self) -> None:
        value = document(account())
        for generated in ("2033-05-18T03:33:20", "not-a-time", 123):
            with self.subTest(generated=generated):
                copy = deepcopy(value)
                copy["GeneratedAt"] = generated
                self.error("cache-generated-at-invalid", copy)

    def test_file_mtime_cannot_freshen_stale_provider_evidence(self) -> None:
        self.write(document(account(), generated=NOW - 181))
        os.utime(self.path, (NOW + 1000, NOW + 1000))
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(self.path, now_s=NOW)
        self.assertEqual("cache-stale", caught.exception.code)

    def test_account_observation_age_and_future_boundaries(self) -> None:
        self.decision_error(
            account(last_success=NOW - 601), "account-observation-stale"
        )
        self.decision_error(
            account(last_success=NOW + 31), "account-observation-future"
        )
        for value in (NOW - 600, NOW + 30):
            with self.subTest(value=value):
                snapshot = self.load(document(account(last_success=value)))
                self.assertTrue(
                    capacity.decide(
                        snapshot, profile="claude-work", model="opus-4.8"
                    ).allowed
                )

    def test_window_observation_age_and_future_are_fatal(self) -> None:
        value = account()
        value["Windows"][0]["CollectedAtUnixSeconds"] = NOW - 601
        self.decision_error(value, "five_hour-window-observation-stale")
        value = account()
        value["Windows"][1]["CollectedAtUnixSeconds"] = NOW + 31
        self.decision_error(value, "seven_day-window-observation-future")

    def test_account_health_is_exact_and_fail_closed(self) -> None:
        cases = (
            ("AuthValid", False, "account-auth-invalid"),
            ("CollectorSuccess", False, "account-collector-failed"),
            ("FallbackActive", True, "account-fallback-active"),
            ("Source", "statusline", "account-source-invalid"),
        )
        for field, replacement, code in cases:
            with self.subTest(field=field):
                value = account()
                value[field] = replacement
                self.decision_error(value, code)

    def test_required_window_stale_or_non_oauth_is_fatal(self) -> None:
        value = account()
        value["Windows"][0]["Stale"] = True
        self.decision_error(value, "five_hour-window-stale")
        value = account()
        value["Windows"][1]["Source"] = "statusline"
        self.decision_error(value, "seven_day-window-source-invalid")
        value = account()
        value["Windows"][2]["Stale"] = True
        self.decision_error(value, "fable_week-window-stale", model="fable-5")

    def test_snapshot_file_is_read_only_once(self) -> None:
        self.write(document(account()))
        original = capacity._read_cache_bytes
        with mock.patch.object(
            capacity, "_read_cache_bytes", wraps=original
        ) as reader:
            snapshot = capacity.load_snapshot(self.path, now_s=NOW)
            capacity.decide(
                snapshot, profile="claude-work", model="opus-4.8"
            )
            capacity.decide(
                snapshot, profile="claude-work", model="fable-5"
            )
        self.assertEqual(1, reader.call_count)


class StrictSchemaTests(CacheCase):
    def test_top_level_schema_is_closed_and_version_is_exact_int(self) -> None:
        value = document(account())
        value["Unexpected"] = True
        self.error("cache-schema-invalid", value)
        for version in (True, 2, "1"):
            with self.subTest(version=version):
                value = document(account())
                value["SchemaVersion"] = version
                self.error("cache-version-invalid", value)

    def test_unknown_claude_profile_is_ignored_not_aliased(self) -> None:
        unknown = {"Provider": "claude", "Profile": ".claude-test3"}
        snapshot = self.load(document(unknown, account()))
        self.assertEqual({".claude-work"}, set(snapshot.accounts))

    def test_known_account_schema_is_closed(self) -> None:
        value = account()
        value["Credential"] = "must-not-be-consumed"
        self.error("account-schema-invalid", document(value))
        value = account()
        del value["CollectorSuccess"]
        self.error("account-schema-invalid", document(value))

    def test_duplicate_known_account_is_rejected(self) -> None:
        self.error(
            "account-duplicate", document(account(), deepcopy(account()))
        )

    def test_missing_and_duplicate_required_windows(self) -> None:
        value = account()
        value["Windows"] = value["Windows"][1:]
        snapshot = self.load(document(value))
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.decide(
                snapshot, profile="claude-work", model="opus-4.8"
            )
        self.assertEqual("five_hour-window-missing", caught.exception.code)

        value = account()
        value["Windows"].append(deepcopy(value["Windows"][0]))
        self.error("window-duplicate", document(value))

    def test_window_identity_is_exact_not_prefix_matched(self) -> None:
        value = account()
        value["Windows"][2]["Scope"] = "Fable 5"
        snapshot = self.load(document(value))
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.decide(
                snapshot, profile="claude-work", model="fable-5"
            )
        self.assertEqual("fable_week-window-missing", caught.exception.code)

    def test_window_schema_and_exact_types(self) -> None:
        value = account()
        value["Windows"][0]["Extra"] = 1
        self.error("window-schema-invalid", document(value))
        value = account()
        value["Windows"][0]["Active"] = 1
        self.error("window-active-invalid", document(value))
        value = account()
        value["Windows"][0]["Stale"] = 0
        self.error("window-stale-invalid", document(value))
        value = account()
        value["Windows"][0]["WindowDurationMinutes"] = True
        self.error("window-duration-invalid", document(value))

    def test_percent_rejects_bool_string_and_out_of_range(self) -> None:
        for used in (True, "50", -1, 101):
            with self.subTest(used=used):
                self.error(
                    "window-used-percent-invalid",
                    document(account(five_used=used)),
                )

    def test_timestamp_rejects_bool_zero_and_string(self) -> None:
        for timestamp in (True, 0, "123"):
            with self.subTest(timestamp=timestamp):
                value = account()
                value["Windows"][0]["CollectedAtUnixSeconds"] = timestamp
                self.error("window-observed-at-invalid", document(value))

    def test_reset_rejects_negative_bool_and_string(self) -> None:
        for timestamp in (-1, True, "123"):
            with self.subTest(timestamp=timestamp):
                value = account()
                value["Windows"][0]["ResetsAtUnixSeconds"] = timestamp
                self.error("window-reset-invalid", document(value))

    def test_policy_types_and_bounds_are_strict(self) -> None:
        cases = (
            ({"cache_max_age_s": True}, "cache-max-age-invalid"),
            ({"future_skew_s": -1}, "future-skew-invalid"),
            ({"fable_reserve_pct": 5}, "fable-reserve-invalid"),
            (
                {"general_week_reserve_pct": Decimal("100")},
                "general-week-reserve-invalid",
            ),
            (
                {"five_hour_reserve_pct": Decimal("NaN")},
                "five-hour-reserve-invalid",
            ),
        )
        for kwargs, code in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(capacity.QuotaEvidenceError) as caught:
                    capacity.QuotaPolicy(**kwargs)
                self.assertEqual(code, caught.exception.code)


class ParserAndPathTests(CacheCase):
    def raw_error(self, raw: bytes, code: str) -> None:
        self.path.write_bytes(raw)
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(self.path, now_s=NOW)
        self.assertEqual(code, caught.exception.code)

    def test_malformed_json_and_nonobject_are_rejected(self) -> None:
        self.raw_error(b"{", "cache-json-invalid")
        self.raw_error(b"[]", "cache-document-invalid")

    def test_duplicate_json_key_is_rejected_at_any_depth(self) -> None:
        raw = (
            '{"SchemaVersion":1,"GeneratedAt":"%s","Accounts":[],"Accounts":[]}'
            % iso_time(NOW)
        ).encode("utf-8")
        self.raw_error(raw, "cache-duplicate-json-key")
        raw = (
            '{"SchemaVersion":1,"GeneratedAt":"%s","Accounts":'
            '[{"Provider":"claude","Provider":"claude","Profile":".claude-work"}]}'
            % iso_time(NOW)
        ).encode("utf-8")
        self.raw_error(raw, "cache-duplicate-json-key")

    def test_invalid_utf8_and_nonfinite_json_numbers_are_rejected(self) -> None:
        self.raw_error(b"\xff", "cache-utf8-invalid")
        raw = (
            '{"SchemaVersion":1,"GeneratedAt":"%s","Accounts":[],"x":NaN}'
            % iso_time(NOW)
        ).encode("utf-8")
        self.raw_error(raw, "cache-nonfinite-number")

    def test_oversized_file_is_rejected_before_json(self) -> None:
        self.path.write_bytes(b" " * (capacity.MAX_CACHE_BYTES + 1))
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(self.path, now_s=NOW)
        self.assertEqual("cache-too-large", caught.exception.code)

    def test_relative_path_is_rejected(self) -> None:
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(
                Path("ai-quotas-state.json"), now_s=NOW
            )
        self.assertEqual("cache-path-invalid", caught.exception.code)

    def test_missing_and_nonregular_paths_are_rejected(self) -> None:
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(self.root / "missing.json", now_s=NOW)
        self.assertEqual("cache-missing", caught.exception.code)
        directory = self.root / "directory.json"
        directory.mkdir()
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(directory, now_s=NOW)
        self.assertEqual("cache-not-regular", caught.exception.code)

    def test_hardlinked_cache_is_rejected(self) -> None:
        self.write(document(account()))
        second = self.root / "second.json"
        try:
            os.link(self.path, second)
        except OSError as error:
            self.skipTest(f"hard links unavailable: {error}")
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(self.path, now_s=NOW)
        self.assertEqual("cache-hardlink-forbidden", caught.exception.code)

    def test_symlinked_cache_is_rejected_when_supported(self) -> None:
        target = self.root / "target.json"
        target.write_text(
            json.dumps(document(account())), encoding="utf-8"
        )
        link = self.root / "link.json"
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(link, now_s=NOW)
        self.assertEqual("cache-reparse-forbidden", caught.exception.code)

    def test_symlinked_parent_is_rejected_when_supported(self) -> None:
        target_dir = self.root / "real"
        target_dir.mkdir()
        target = target_dir / "state.json"
        target.write_text(json.dumps(document(account())), encoding="utf-8")
        link_dir = self.root / "linked"
        try:
            link_dir.symlink_to(target_dir, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory symlinks unavailable: {error}")
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(link_dir / "state.json", now_s=NOW)
        self.assertEqual("cache-reparse-forbidden", caught.exception.code)

    def test_no_environment_default_is_accepted(self) -> None:
        with self.assertRaises(capacity.QuotaEvidenceError) as caught:
            capacity.load_snapshot(None, now_s=NOW)  # type: ignore[arg-type]
        self.assertEqual("cache-path-invalid", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
