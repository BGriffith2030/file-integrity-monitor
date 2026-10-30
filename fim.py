#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
----------------------------
Watches a folder the way a security team watches a server: take a trusted
snapshot (a baseline) of every file's SHA-256 hash, then check later scans
against it and report exactly what changed.

  baseline   record the current state of a folder into a JSON file
  check      compare the folder against the baseline and report
             NEW files, MODIFIED files, and DELETED files

Usage:
    python fim.py baseline ./demo_files
    python fim.py check ./demo_files
    python fim.py baseline C:\\inetpub\\wwwroot --baseline-file web.json
    python fim.py check C:\\inetpub\\wwwroot --baseline-file web.json

Exit codes (so the tool can be scheduled or scripted):
    0 = no changes found, 1 = changes found, 2 = error

Only the Python standard library is used.
"""

import argparse
import hashlib
import json
import os
import sys

CHUNK_SIZE = 65536  # read files in 64 KB pieces so big files stay cheap


def hash_file(path):
    """Return the SHA-256 hash of one file, read in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def scan_folder(folder):
    """Walk a folder and return {relative_path: {sha256, size}} for every file."""
    state = {}
    for root, _dirs, files in os.walk(folder):
        for name in sorted(files):
            full_path = os.path.join(root, name)
            relative = os.path.relpath(full_path, folder)
            try:
                state[relative] = {
                    "sha256": hash_file(full_path),
                    "size": os.path.getsize(full_path),
                }
            except OSError as error:
                print(f"  Warning: could not read {relative}: {error}", file=sys.stderr)
    return state


def do_baseline(args):
    """Create (or overwrite) the baseline snapshot."""
    if not os.path.isdir(args.folder):
        sys.exit(f"Folder not found: {args.folder}")
    state = scan_folder(args.folder)
    with open(args.baseline_file, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    print(f"Baseline saved to {args.baseline_file}: {len(state)} files recorded.")
    for path in sorted(state):
        print(f"  {state[path]['sha256'][:16]}...  {path}")
    return 0


def do_check(args):
    """Compare the folder's current state with the saved baseline."""
    if not os.path.isdir(args.folder):
        sys.exit(f"Folder not found: {args.folder}")
    try:
        with open(args.baseline_file, encoding="utf-8") as handle:
            baseline = json.load(handle)
    except FileNotFoundError:
        sys.exit(f"Baseline not found: {args.baseline_file}. Run the baseline command first.")

    current = scan_folder(args.folder)

    new_files = sorted(set(current) - set(baseline))
    deleted_files = sorted(set(baseline) - set(current))
    modified_files = sorted(
        path for path in set(current) & set(baseline)
        if current[path]["sha256"] != baseline[path]["sha256"]
    )

    print(f"Checked {len(current)} files against baseline of {len(baseline)} files.")
    if not (new_files or modified_files or deleted_files):
        print("No changes detected. The folder matches the baseline.")
        return 0

    print("CHANGES DETECTED:")
    for path in new_files:
        print(f"  [NEW]      {path}")
    for path in modified_files:
        print(f"  [MODIFIED] {path}")
        print(f"             baseline hash: {baseline[path]['sha256']}")
        print(f"             current hash : {current[path]['sha256']}")
    for path in deleted_files:
        print(f"  [DELETED]  {path}")
    print(f"Summary: {len(new_files)} new, {len(modified_files)} modified, "
          f"{len(deleted_files)} deleted.")
    return 1


def main():
    parser = argparse.ArgumentParser(
        description="File integrity monitor: baseline a folder, then detect changes."
    )
    parser.add_argument("command", choices=["baseline", "check"],
                        help="baseline creates the snapshot; check compares against it")
    parser.add_argument("folder", help="Folder to watch")
    parser.add_argument("--baseline-file", default="baseline.json",
                        help="Where the baseline snapshot lives (default: baseline.json)")
    args = parser.parse_args()

    if args.command == "baseline":
        sys.exit(do_baseline(args))
    else:
        sys.exit(do_check(args))


if __name__ == "__main__":
    main()
