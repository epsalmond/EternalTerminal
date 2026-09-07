#!/usr/bin/env python3
"""Run the read-only NAS audit as root and publish only its redacted report."""

import importlib.util
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile

STAGE = "initialization"


def safe_failure(error):
    frames = []
    traceback = error.__traceback__
    while traceback is not None:
        filename = Path(traceback.tb_frame.f_code.co_filename).name
        label = (
            filename
            if filename in {"et-session-recovery.py", "et-session-recovery-root.py"}
            else "library"
        )
        frames.append({"code": label, "line": traceback.tb_lineno})
        traceback = traceback.tb_next
    return {
        "status": "failed",
        "stage": STAGE,
        "exception_type": type(error).__name__,
        "frames": frames,
        "raw_diagnostics_recorded": False,
    }


def main():
    global STAGE
    if os.geteuid() != 0:
        print("Run this script as root.", file=sys.stderr)
        return 2
    account = pwd.getpwnam("eric")
    try:
        STAGE = "load scanner"
        source = Path(__file__).with_name("et-session-recovery.py")
        spec = importlib.util.spec_from_file_location("et_recovery_audit", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Read only regular artifacts and process metadata, never process memory.
        STAGE = "scan sources"
        report = module.scan_local(home=Path(account.pw_dir)).public()
        report["status"] = "complete"
    except Exception as error:
        report = safe_failure(error)
    report["scope"] = "nas_root_read_only"
    report["effective_uid"] = os.geteuid()
    encoded = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()

    # A fresh directory avoids overwriting any previous report. Keep it private
    # throughout creation, then give the requested reader access to the report.
    STAGE = "write redacted report"
    directory = Path(tempfile.mkdtemp(prefix="et-root-audit-", dir="/var/tmp"))
    output = directory / "report.json"
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchown(stream.fileno(), account.pw_uid, account.pw_gid)
        os.fchmod(stream.fileno(), 0o600)
    os.chown(directory, account.pw_uid, account.pw_gid)
    os.chmod(directory, 0o700)
    print(f"Redacted report: {output}")
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps(safe_failure(error)), file=sys.stderr)
        raise SystemExit(2)
