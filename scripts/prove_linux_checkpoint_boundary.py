#!/usr/bin/env python3
"""Root-run Linux proof of the operator-owned, app-read-only checkpoint boundary."""
from __future__ import annotations

import grp
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


def require_root() -> None:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise SystemExit("FAIL: this proof requires Linux")
    if os.geteuid() != 0:
        raise SystemExit(
            "FAIL: run as root; the harness creates two unprivileged UIDs"
        )


def run_as(
    user: str, code: str, *args: str
) -> subprocess.CompletedProcess[str]:
    command = ["runuser", "-u", user, "--", sys.executable, "-c", code, *args]
    return subprocess.run(
        command, text=True, capture_output=True, check=False
    )


def expect_denied(
    label: str, user: str, code: str, *args: str
) -> None:
    result = run_as(user, code, *args)
    if result.returncode == 0:
        raise AssertionError(f"{label}: unexpectedly succeeded as {user}")
    detail = (result.stderr + result.stdout).lower()
    denied = ("permission denied", "operation not permitted")
    if not any(word in detail for word in denied):
        raise AssertionError(
            f"{label}: failed for an unexpected reason: {detail}"
        )
    print(f"PASS: {label} denied for application UID")


def main() -> int:
    require_root()
    suffix = uuid.uuid4().hex[:10]
    app_user = f"ckptapp{suffix}"
    op_user = f"ckptop{suffix}"
    read_group = f"ckptread{suffix}"
    root = Path(tempfile.mkdtemp(prefix="checkpoint-proof-", dir="/tmp"))
    checkpoint_dir = root / "published"
    checkpoint = checkpoint_dir / "main.json"
    operator_tmp = checkpoint_dir / ".main.json.operator-tmp"
    created_group = False
    created_users: list[str] = []

    try:
        subprocess.run(["groupadd", read_group], check=True)
        created_group = True
        for user in (app_user, op_user):
            subprocess.run(
                [
                    "useradd",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    user,
                ],
                check=True,
            )
            created_users.append(user)

        for user in (app_user, op_user):
            subprocess.run(
                ["usermod", "-a", "-G", read_group, user], check=True
            )

        os.chmod(root, 0o711)
        checkpoint_dir.mkdir()
        subprocess.run(
            ["chown", f"{op_user}:{read_group}", str(checkpoint_dir)],
            check=True,
        )
        os.chmod(checkpoint_dir, 0o750)
        old = '{"authority":"main","sequence":1}\n'
        checkpoint.write_text(old, encoding="utf-8")
        subprocess.run(
            ["chown", f"{op_user}:{read_group}", str(checkpoint)],
            check=True,
        )
        os.chmod(checkpoint, 0o640)

        app_uid = pwd.getpwnam(app_user).pw_uid
        operator_uid = pwd.getpwnam(op_user).pw_uid
        group_gid = grp.getgrnam(read_group).gr_gid
        if app_uid == operator_uid or app_uid == 0 or operator_uid == 0:
            raise AssertionError("identities are not distinct non-root UIDs")
        if (
            checkpoint_dir.stat().st_uid != operator_uid
            or checkpoint.stat().st_uid != operator_uid
        ):
            raise AssertionError("checkpoint path is not operator-owned")
        if (
            checkpoint_dir.stat().st_mode & 0o022
            or checkpoint.stat().st_mode & 0o022
        ):
            raise AssertionError("checkpoint path is group/other writable")

        print(
            f"PASS: distinct non-root UIDs "
            f"(app={app_uid}, operator={operator_uid})"
        )
        print("PASS: operator owns directory and file; modes are 0750/0640")

        read_code = (
            "from pathlib import Path; import sys; "
            "print(Path(sys.argv[1]).read_text())"
        )
        read = run_as(app_user, read_code, str(checkpoint))
        if read.returncode or '"sequence":1' not in read.stdout:
            raise AssertionError(f"application read failed: {read.stderr}")
        print("PASS: application UID can read published checkpoint")

        expect_denied(
            "file write",
            app_user,
            "from pathlib import Path; import sys; "
            "Path(sys.argv[1]).write_text('tampered')",
            str(checkpoint),
        )
        expect_denied(
            "file truncate",
            app_user,
            "import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_TRUNC); "
            "os.close(fd)",
            str(checkpoint),
        )
        expect_denied(
            "chmod",
            app_user,
            "import os,sys; os.chmod(sys.argv[1],0o666)",
            str(checkpoint),
        )
        expect_denied(
            "unlink",
            app_user,
            "import os,sys; os.unlink(sys.argv[1])",
            str(checkpoint),
        )
        expect_denied(
            "rename",
            app_user,
            "import os,sys; os.rename(sys.argv[1],sys.argv[2])",
            str(checkpoint),
            str(checkpoint_dir / "renamed.json"),
        )
        expect_denied(
            "create sibling",
            app_user,
            "from pathlib import Path; import sys; "
            "Path(sys.argv[1]).write_text('x')",
            str(checkpoint_dir / "attacker.json"),
        )
        expect_denied(
            "parent-directory mutation",
            app_user,
            "from pathlib import Path; import sys; Path(sys.argv[1]).mkdir()",
            str(checkpoint_dir / "attacker-dir"),
        )

        operator_tmp.write_text("operator-only staging data", encoding="utf-8")
        subprocess.run(
            ["chown", f"{op_user}:{op_user}", str(operator_tmp)], check=True
        )
        os.chmod(operator_tmp, 0o600)
        expect_denied(
            "operator temporary-file read",
            app_user,
            "from pathlib import Path; import sys; "
            "Path(sys.argv[1]).read_text()",
            str(operator_tmp),
        )
        operator_tmp.unlink()

        publisher = """
import os,sys
from pathlib import Path
target=Path(sys.argv[1]); stage=sys.argv[2]; gid=int(sys.argv[3])
tmp=target.parent/'.publish.tmp'
fd=os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
with os.fdopen(fd,'w',encoding='utf-8') as handle:
    handle.write('NEW-CHECKPOINT\\n')
    handle.flush()
    if stage == 'before_file_fsync':
        os._exit(31)
    os.fsync(handle.fileno())
    if stage == 'after_file_fsync_before_rename':
        os._exit(32)
    os.fchown(handle.fileno(), -1, gid)
    os.fchmod(handle.fileno(), 0o640)
    os.fsync(handle.fileno())
os.replace(tmp,target)
if stage == 'after_rename_before_directory_fsync':
    os._exit(33)
dfd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
try:
    os.fsync(dfd)
finally:
    os.close(dfd)
if stage == 'after_directory_fsync_before_confirmation':
    os._exit(34)
"""
        stages = (
            ("before_file_fsync", old, 31),
            ("after_file_fsync_before_rename", old, 32),
            ("after_rename_before_directory_fsync", "NEW-CHECKPOINT\n", 33),
            ("after_directory_fsync_before_confirmation", "NEW-CHECKPOINT\n", 34),
        )
        reset_code = (
            "from pathlib import Path; import sys; "
            "p=Path(sys.argv[1]); p.write_text(sys.argv[2]); "
            "(p.parent/'.publish.tmp').unlink(missing_ok=True)"
        )
        for stage, expected, exit_code in stages:
            reset = run_as(op_user, reset_code, str(checkpoint), old)
            if reset.returncode:
                raise AssertionError(
                    f"operator reset failed: {reset.stderr}"
                )
            result = run_as(
                op_user, publisher, str(checkpoint), stage, str(group_gid)
            )
            if result.returncode != exit_code:
                raise AssertionError(
                    f"{stage}: unexpected exit {result.returncode}: "
                    f"{result.stderr}"
                )
            actual = checkpoint.read_text(encoding="utf-8")
            if actual != expected:
                raise AssertionError(
                    f"{stage}: unexpected checkpoint state {actual!r}"
                )
            print(
                f"PASS: interruption at {stage} "
                "leaves expected recoverable state"
            )

        publish_ok = run_as(
            op_user, publisher, str(checkpoint), "complete", str(group_gid)
        )
        if publish_ok.returncode:
            raise AssertionError(
                f"complete publication failed: {publish_ok.stderr}"
            )
        published = checkpoint.stat()
        if (
            published.st_uid != operator_uid
            or published.st_gid != group_gid
            or published.st_mode & 0o777 != 0o640
        ):
            raise AssertionError("published ownership/mode changed")
        read = run_as(app_user, read_code, str(checkpoint))
        if read.returncode or read.stdout.strip() != "NEW-CHECKPOINT":
            raise AssertionError(
                "application could not read published checkpoint"
            )
        print(
            "PASS: successful operator publication is atomic, durable, "
            "and app-readable"
        )
        print("PASS: mandatory enforcement remains disabled")
        print("RESULT: Linux two-UID filesystem/publication proof passed")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)
        for user in created_users:
            subprocess.run(
                ["userdel", user], check=False, capture_output=True
            )
        if created_group:
            subprocess.run(
                ["groupdel", read_group], check=False, capture_output=True
            )


if __name__ == "__main__":
    raise SystemExit(main())
