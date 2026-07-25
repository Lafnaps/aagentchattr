"""Security and crash-window tests for one-shot wrapper identity handoff."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import wrapper


PWSH = shutil.which("pwsh.exe") or shutil.which("pwsh")
TOKEN = "a" * 32
IDENTITY_ID = "b" * 32
NONCE = "c" * 32
CANONICAL_FABLE_PROFILES = {
    "claude-fable": "claude-main",
    "claude-work-fable": "claude-work",
    "claude-test1-fable": "claude-test1",
    "claude-test2-fable": "claude-test2",
    "claude-test3-fable": "claude-test3",
}


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


@unittest.skipUnless(os.name == "nt" and PWSH, "Windows DPAPI test")
class WrapperHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name) / "data"
        self.handoff_dir = self.data / "wrapper-handoff"
        self.handoff_dir.mkdir(parents=True)
        self.path = self.handoff_dir / f"handoff-{NONCE}.dpapi"
        self.registry = {
            "instances": {
                "claude-test1": {
                    "name": "claude-test1",
                    "base": "fable-infra",
                    "slot": 1,
                    "identity_id": IDENTITY_ID,
                    "epoch": 7,
                    "token": TOKEN,
                    "state": "active",
                },
                # Same-family Opus sibling: adoption must not touch it.
                "fable-infra-2": {
                    "name": "fable-infra-2",
                    "base": "fable-infra",
                    "slot": 2,
                    "identity_id": "d" * 32,
                    "epoch": 11,
                    "token": "e" * 32,
                    "state": "active",
                },
            }
        }
        self._write_registry()

    def _write_registry(self):
        (self.data / "registry.json").write_text(
            json.dumps(self.registry), encoding="utf-8"
        )

    def _set_registry_identity(self, agent, profile):
        self.registry["instances"][profile] = {
            "name": profile,
            "base": agent,
            "slot": 1,
            "identity_id": IDENTITY_ID,
            "epoch": 7,
            "token": TOKEN,
            "state": "active",
        }
        self._write_registry()

    def _payload(self, **changes):
        payload = {
            "profile": "claude-test1",
            "internal_id": "fable-infra",
            "identity_id": IDENTITY_ID,
            "epoch": 7,
            "token": TOKEN,
            "expiry": int(time.time()) + 120,
            "nonce": NONCE,
        }
        payload.update(changes)
        return payload

    def _protect(self, payload):
        script = r"""
        $ErrorActionPreference = 'Stop'
        $text = [Console]::In.ReadToEnd()
        $plain = [Text.UTF8Encoding]::new($false).GetBytes($text)
        $entropy = [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes('agentchattr-wrapper-handoff-v1')
        )
        try {
            $cipher = [Security.Cryptography.ProtectedData]::Protect(
                $plain, $entropy,
                [Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            [Console]::Out.Write([Convert]::ToBase64String($cipher))
        } finally {
            [Array]::Clear($plain, 0, $plain.Length)
        }
        """
        completed = subprocess.run(
            [PWSH, "-NoLogo", "-NoProfile", "-Command", script],
            input=json.dumps(payload, separators=(",", ":")),
            text=True,
            encoding="utf-8",
            errors="strict",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=True,
        )
        ciphertext = base64.b64decode(completed.stdout, validate=True)
        self.assertNotIn(TOKEN.encode("ascii"), ciphertext)
        self.path.write_bytes(ciphertext)
        return ciphertext

    def _adopt(self, *, agent="fable-infra",
               expected_profile="claude-test1", **kwargs):
        response = {
            "ok": True, "name": expected_profile, "pending": False,
        }
        with mock.patch(
            "urllib.request.urlopen", return_value=_Response(response)
        ):
            return wrapper._adopt_restart_handoff(
                str(self.path), agent=agent, data_dir=self.data,
                server_port=8300, **kwargs,
            )

    def test_valid_handoff_adopts_exact_identity_without_family_mutation(self):
        sibling_before = json.loads(json.dumps(self.registry["instances"]["fable-infra-2"]))
        self._protect(self._payload())

        result = self._adopt()

        self.assertEqual("claude-test1", result["name"])
        self.assertEqual(TOKEN, result["token"])
        self.assertFalse(self.path.exists())
        self.assertFalse(self.path.with_suffix(".consuming").exists())
        self.assertFalse(self.path.with_suffix(".failed").exists())
        on_disk = json.loads((self.data / "registry.json").read_text("utf-8"))
        self.assertEqual(sibling_before, on_disk["instances"]["fable-infra-2"])

    def test_all_canonical_fable_handoffs_adopt_exact_identity(self):
        for agent, profile in CANONICAL_FABLE_PROFILES.items():
            with self.subTest(agent=agent, profile=profile):
                self._set_registry_identity(agent, profile)
                self._protect(self._payload(
                    profile=profile,
                    internal_id=agent,
                ))

                result = self._adopt(
                    agent=agent,
                    expected_profile=profile,
                )

                self.assertEqual(profile, result["name"])
                self.assertEqual(TOKEN, result["token"])
                self.assertFalse(self.path.exists())

    def test_opus_identity_has_no_restart_handoff_authority(self):
        with self.assertRaisesRegex(
            RuntimeError,
            "restart handoff is unavailable for this agent",
        ):
            wrapper._adopt_restart_handoff(
                str(self.path),
                agent="claude-test1-opus",
                data_dir=self.data,
                server_port=8300,
            )

    def test_canonical_identity_rejects_wrong_profile(self):
        self._protect(self._payload(
            profile="claude-work",
            internal_id="claude-test1-fable",
        ))
        with mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "handoff adoption failed"):
                wrapper._adopt_restart_handoff(
                    str(self.path),
                    agent="claude-test1-fable",
                    data_dir=self.data,
                    server_port=8300,
                )
        urlopen.assert_not_called()

    def test_canonical_identity_rejects_legacy_internal_id(self):
        self._protect(self._payload(
            profile="claude-test1",
            internal_id="fable-infra",
        ))
        with mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "handoff adoption failed"):
                wrapper._adopt_restart_handoff(
                    str(self.path),
                    agent="claude-test1-fable",
                    data_dir=self.data,
                    server_port=8300,
                )
        urlopen.assert_not_called()

    def test_legacy_identity_rejects_canonical_internal_id(self):
        self._protect(self._payload(
            profile="claude-test1",
            internal_id="claude-test1-fable",
        ))
        with mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "handoff adoption failed"):
                wrapper._adopt_restart_handoff(
                    str(self.path),
                    agent="fable-infra",
                    data_dir=self.data,
                    server_port=8300,
                )
        urlopen.assert_not_called()

    def test_heartbeat_failure_keeps_only_encrypted_failed_evidence(self):
        ciphertext = self._protect(self._payload())
        with mock.patch("urllib.request.urlopen", side_effect=OSError("offline")):
            with self.assertRaisesRegex(RuntimeError, "handoff adoption failed"):
                wrapper._adopt_restart_handoff(
                    str(self.path), agent="fable-infra", data_dir=self.data,
                    server_port=8300,
                )

        failed = self.path.with_suffix(".failed")
        self.assertFalse(self.path.exists())
        self.assertFalse(self.path.with_suffix(".consuming").exists())
        self.assertTrue(failed.exists())
        self.assertEqual(ciphertext, failed.read_bytes())
        self.assertNotIn(TOKEN.encode("ascii"), failed.read_bytes())

    def test_expired_handoff_is_quarantined_before_heartbeat(self):
        self._protect(self._payload(expiry=int(time.time()) - 1))
        with mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "handoff adoption failed"):
                wrapper._adopt_restart_handoff(
                    str(self.path), agent="fable-infra", data_dir=self.data,
                    server_port=8300,
                )
        urlopen.assert_not_called()
        self.assertTrue(self.path.with_suffix(".failed").exists())

    def test_strict_schema_rejects_extra_field_and_quarantines(self):
        self._protect(self._payload(extra="not admitted"))
        with mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "handoff adoption failed"):
                wrapper._adopt_restart_handoff(
                    str(self.path), agent="fable-infra", data_dir=self.data,
                    server_port=8300,
                )
        urlopen.assert_not_called()
        self.assertTrue(self.path.with_suffix(".failed").exists())

    def test_registry_epoch_mismatch_fails_before_heartbeat(self):
        self._protect(self._payload(epoch=8))
        with mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "handoff adoption failed"):
                wrapper._adopt_restart_handoff(
                    str(self.path), agent="fable-infra", data_dir=self.data,
                    server_port=8300,
                )
        urlopen.assert_not_called()
        self.assertTrue(self.path.with_suffix(".failed").exists())

    def test_corrupt_dpapi_blob_is_quarantined_without_plaintext_output(self):
        self.path.write_bytes(os.urandom(64))
        with mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "handoff adoption failed") as caught:
                wrapper._adopt_restart_handoff(
                    str(self.path), agent="fable-infra", data_dir=self.data,
                    server_port=8300,
                )
        urlopen.assert_not_called()
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertTrue(self.path.with_suffix(".failed").exists())

    def test_one_shot_success_cannot_be_replayed(self):
        self._protect(self._payload())
        self._adopt()
        with self.assertRaisesRegex(RuntimeError, "handoff claim failed"):
            self._adopt()


class WrapperHandoffSourceTests(unittest.TestCase):
    def test_main_adoption_branch_does_not_call_register(self):
        source = (ROOT / "wrapper.py").read_text("utf-8")
        branch = source[source.index("if args.handoff_file:") : source.index("assigned_name =")]
        self.assertIn("_adopt_restart_handoff", branch)
        self.assertIn("else:\n            registration = _register_instance", branch)


if __name__ == "__main__":
    unittest.main()
