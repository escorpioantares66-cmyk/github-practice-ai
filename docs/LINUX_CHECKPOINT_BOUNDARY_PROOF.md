# Linux two-UID checkpoint boundary proof

## Purpose and limits

This proof runs on Linux as root only to provision two distinct, non-root
system identities. The application identity is placed in a read-only group;
the operator identity owns the checkpoint directory and checkpoint file.

It proves the filesystem boundary and atomic-publication interruption states
on the CI runner's Linux filesystem. It does **not** prove the future
production host's configuration, either audit-chain verifier, checkpoint
freshness/rollback policy, or end-to-end approval enforcement. Those remain
separate gates. No project audit data is touched.

## Run

On a disposable Linux host with useradd, usermod, userdel, groupadd, groupdel,
and runuser available, execute:

    sudo python scripts/prove_linux_checkpoint_boundary.py

The script creates temporary users/groups and a temporary directory, then
removes them. Do not run it on Termux or a non-Linux host; a same-UID
simulation is explicitly rejected.

## Assertions

- Application and operator are distinct, non-root UIDs.
- Operator owns the published directory and checkpoint; modes are 0750/0640.
- Application can read the checkpoint.
- Application cannot write, truncate, chmod, unlink, rename, create siblings,
  mutate the checkpoint directory, or read an operator-only staging file.
- Operator publication uses a same-directory temporary file, file fsync,
  atomic replace, and directory fsync.
- Interruption before rename preserves the previous checkpoint.
- Interruption after rename but before directory fsync exposes the new complete
  file but is treated as durability-uncertain; the harness does not claim
  publication was durably confirmed.
- A complete publication remains operator-owned and app-readable.

## Still required before any enforcement decision

1. Run this proof on the actual intended Linux host and inspect its filesystem,
   mount options, ACLs, supplementary groups, and ancestor permissions.
2. Add authority-specific checkpoint envelope validation and verifier
   integration tests for both main and sandbox audit chains.
3. Define freshness and maximum unanchored-suffix policy.
4. Add tamper, stale/regression, restore-old-checkpoint, cross-authority,
   symlink/hard-link, and trusted-checkpoint-loss recovery tests.
5. Review all evidence and approve any future runtime enforcement separately.

Mandatory checkpoint enforcement remains disabled. This harness does not
change application behavior, audit rotation, retention, deployment, or the
Cloudflare prototype.
