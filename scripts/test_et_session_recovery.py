#!/usr/bin/env python3

import contextlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("et-session-recovery.py")
SPEC = importlib.util.spec_from_file_location("et_session_recovery", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


CLIENT_ID = "AbC1234567890123"
PASSKEY = "pAsskey0123456789012345678901234"
BOOTSTRAP_ID = "XXX1234567890123"
BOOTSTRAP_KEY = "bOoTstrap01234567890123456789012"


class SessionRecoveryTest(unittest.TestCase):
    def test_root_failure_diagnostics_do_not_echo_exception_text(self) -> None:
        source = SCRIPT.with_name("et-session-recovery-root.py")
        spec = importlib.util.spec_from_file_location("et_root_audit", source)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        try:
            raise RuntimeError(f"private source: {CLIENT_ID}/{PASSKEY}")
        except RuntimeError as error:
            report = helper.safe_failure(error)
        serialized = json.dumps(report)
        self.assertEqual(report["exception_type"], "RuntimeError")
        self.assertFalse(CLIENT_ID in serialized, "client ID leaked")
        self.assertFalse(PASSKEY in serialized, "passkey leaked")
        self.assertFalse(report["raw_diagnostics_recorded"])

    def test_available_service_state_is_reported_without_raw_output(self) -> None:
        audit = AUDIT.Audit()
        with mock.patch.object(
            AUDIT,
            "_run_capture",
            return_value=(b"ActiveState=active\nSubState=running\n", "read"),
        ):
            AUDIT._scan_services(audit)
        self.assertEqual(len(audit.service_checks), 2)
        for check in audit.service_checks:
            self.assertEqual(check["status"], "available")
            self.assertEqual(check["active_state"], "active")
            self.assertEqual(check["sub_state"], "running")

    def make_home(self, root: Path) -> Path:
        home = root / "home"
        sessions = home / ".et" / "sessions"
        sessions.mkdir(parents=True, mode=0o700)
        os.chmod(home / ".et", 0o700)
        os.chmod(sessions, 0o700)
        return home

    def write_session(self, home: Path, name: str = "saved") -> Path:
        record = home / ".et" / "sessions" / name
        record.write_text(
            "version=1\n"
            f"name={name}\n"
            "host=nas\n"
            "port=2022\n"
            f"id={CLIENT_ID}\n"
            f"passkey={PASSKEY}\n"
            "savedat=1700000000\n"
            "title=terminal\n",
            encoding="utf-8",
        )
        os.chmod(record, 0o600)
        return record

    def test_report_redacts_pairs_and_associates_terminal_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = self.make_home(root)
            self.write_session(home)
            temp_logs = root / "tmp"
            temp_logs.mkdir(mode=0o700)
            log = temp_logs / f"etterminal-eric-{CLIENT_ID}-1700000000.log"
            log.write_text(f"IDPASSKEY:{CLIENT_ID}/{PASSKEY}\n", encoding="utf-8")
            os.chmod(log, 0o600)

            with mock.patch.dict(os.environ, {"TMPDIR": str(temp_logs)}):
                audit = AUDIT.scan_local(
                    home, include_processes=False, include_services=False
                )
            report = audit.public()
            serialized = json.dumps(report, sort_keys=True)
            rendered = AUDIT._render_text(report)

            self.assertNotIn(CLIENT_ID, serialized)
            self.assertNotIn(PASSKEY, serialized)
            self.assertNotIn(CLIENT_ID, rendered)
            self.assertNotIn(PASSKEY, rendered)
            self.assertEqual(report["summary"]["complete_pairs"], 1)
            candidate = report["candidates"][0]
            self.assertTrue(candidate["complete"])
            self.assertTrue(candidate["eligible_for_import"])
            self.assertGreater(candidate["matched_id_only_evidence"], 0)
            self.assertIn("local_session_store", candidate["sources"])
            self.assertIn("etterminal_log", candidate["sources"])

    def test_bootstrap_pair_is_complete_but_unverified(self) -> None:
        audit = AUDIT.Audit()
        audit.ingest_text(
            f"echo '{BOOTSTRAP_ID}/{BOOTSTRAP_KEY}_xterm-256color'",
            "shell_history",
            "history_command",
        )
        report = audit.public()
        serialized = json.dumps(report, sort_keys=True)

        self.assertNotIn(BOOTSTRAP_ID, serialized)
        self.assertNotIn(BOOTSTRAP_KEY, serialized)
        self.assertEqual(report["summary"]["bootstrap_unverified_pairs"], 1)
        self.assertFalse(report["candidates"][0]["eligible_for_import"])

    def test_symlink_and_fifo_are_not_opened(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = self.make_home(root)
            real = self.write_session(home)
            link = home / ".et" / "sessions" / "etterminal-secret-link"
            link.symlink_to(real)
            fifo = home / ".et" / "sessions" / "etserver-secret-fifo"
            os.mkfifo(fifo, 0o600)

            audit = AUDIT.Audit()
            AUDIT._scan_session_store(Path(os.path.realpath(home)), audit)
            report = audit.public()
            source = report["sources"]["local_session_store"]

            self.assertEqual(report["summary"]["complete_pairs"], 1)
            self.assertGreaterEqual(source["skipped"], 2)
            self.assertNotIn("secret", json.dumps(report))

    def test_import_requires_confirmation_and_writes_private_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recovery = root / "recovery-home"
            audit = AUDIT.Audit()
            audit.add_pair(CLIENT_ID, PASSKEY, "local_session_store", "session_store")
            label = audit.public()["candidates"][0]["label"]

            with self.assertRaises(AUDIT.AuditError):
                AUDIT.import_candidate(
                    audit,
                    label,
                    "recovered",
                    "nas",
                    2022,
                    str(recovery),
                    confirm=lambda _prompt: "no",
                )
            self.assertFalse(recovery.exists())

            AUDIT.import_candidate(
                audit,
                label,
                "recovered",
                "nas",
                2022,
                str(recovery),
                confirm=lambda _prompt: f"IMPORT {label}",
            )
            record = recovery / ".et" / "sessions" / "recovered"
            self.assertTrue(record.is_file())
            self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((recovery / ".et").stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((recovery / ".et" / "sessions").stat().st_mode), 0o700
            )
            contents = record.read_text(encoding="utf-8")
            self.assertIn(f"id={CLIENT_ID}", contents)
            self.assertIn(f"passkey={PASSKEY}", contents)
            backup = recovery / ".et" / "recovery-backups" / "recovered"
            self.assertEqual(backup.read_bytes(), record.read_bytes())
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(backup.parent.stat().st_mode), 0o700)
            self.assertNotEqual(backup.stat().st_ino, record.stat().st_ino)
            record.unlink()
            self.assertTrue(backup.is_file())

    def test_import_rejects_unverified_bootstrap_without_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            audit = AUDIT.Audit()
            audit.add_pair(BOOTSTRAP_ID, BOOTSTRAP_KEY, "shell_history")
            label = audit.public()["candidates"][0]["label"]
            with self.assertRaises(AUDIT.AuditError):
                AUDIT.import_candidate(
                    audit,
                    label,
                    "recovered",
                    "nas",
                    2022,
                    str(Path(temporary) / "recovery"),
                    confirm=lambda _prompt: f"IMPORT {label}",
                )

    def test_remote_result_is_sanitized_json_and_uses_stdin_source(self) -> None:
        remote_report = AUDIT.Audit("local").public()
        completed = mock.Mock(
            returncode=0, stdout=json.dumps(remote_report).encode(), stderr=b""
        )
        with mock.patch.object(AUDIT.subprocess, "run", return_value=completed) as run:
            result = AUDIT._remote_audit("nas", ["-oBatchMode=yes"])
        self.assertEqual(result["scope"], "remote")
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["ssh", "-oBatchMode=yes"])
        self.assertEqual(command[-3:], ["python3", "-", "--remote-child"])
        self.assertIsInstance(run.call_args.kwargs["input"], bytes)

    def test_remote_raw_pair_is_rejected_before_rendering(self) -> None:
        remote_report = AUDIT.Audit("local").public()
        remote_report["unexpected"] = f"{CLIENT_ID}/{PASSKEY}"
        completed = mock.Mock(
            returncode=0,
            stdout=json.dumps(remote_report).encode(),
            stderr=b"",
        )
        with mock.patch.object(AUDIT.subprocess, "run", return_value=completed):
            with self.assertRaises(AUDIT.AuditError):
                AUDIT._remote_audit("nas", [])

    def test_remote_split_secrets_and_free_text_are_rejected(self) -> None:
        for extra in (
            {"identifier": CLIENT_ID, "secret_value": PASSKEY},
            {"warnings": [PASSKEY]},
            {"sources": {PASSKEY: {"files_read": 1}}},
        ):
            report = AUDIT.Audit().public()
            report.update(extra)
            self.assertTrue(AUDIT._report_has_sensitive_fields(report))

    def test_import_rejects_a_parent_writable_by_other_accounts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve() / "shared"
            parent.mkdir(mode=0o777)
            parent.chmod(0o777)
            recovery = parent / "new-home"
            with self.assertRaises(AUDIT.AuditError):
                AUDIT._write_private_record(
                    recovery, "recovered", "nas", 2022, CLIENT_ID, PASSKEY
                )
            self.assertFalse(recovery.exists())

    def test_cli_error_does_not_echo_secret(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = AUDIT.main(["--write-recovery-record"])
        self.assertEqual(result, 2)
        self.assertNotIn(PASSKEY, output.getvalue() + errors.getvalue())
        self.assertNotIn(CLIENT_ID, output.getvalue() + errors.getvalue())


if __name__ == "__main__":
    unittest.main()
