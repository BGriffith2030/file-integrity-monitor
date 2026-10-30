# File Integrity Monitor

A small defensive tool with a serious job: prove that the files on a system are the files that are supposed to be there. It takes a trusted snapshot of a folder (a baseline of SHA-256 hashes), then compares later scans against that snapshot and reports exactly what was added, changed, or removed.

File integrity monitoring is how teams catch the quiet part of an intrusion: the edited configuration, the replaced web page, the dropped script. Antivirus looks for known bad files. A FIM does not care what a file is; it cares that the file is different, and different demands an explanation.

## How it works

1. **Baseline.** The tool walks a folder and records every file's SHA-256 hash and size into a JSON snapshot. A hash is a fingerprint: the same bytes always produce the same hash, and changing even one character produces a completely different one.
2. **Check.** Later scans rehash the folder and diff against the baseline. The report names every NEW, MODIFIED, and DELETED file, and for modified files shows the before and after hashes as evidence.
3. **Exit codes.** 0 means clean, 1 means changes found, 2 means error, so the tool can run from a scheduler or a script and alert on change without a human watching it.

## What is in this repository

| File | Purpose |
| --- | --- |
| `fim.py` | The monitor. Standard library only: hashlib, os, json, argparse. |
| `demo_files/` | Three small files (a config, a notes file, a web page) so the demo runs right after cloning. |
| `LICENSE` | MIT license. |

## Run the demo

```bash
python fim.py baseline ./demo_files
```

Output:

```text
Baseline saved to baseline.json: 3 files recorded.
  ecb63329af09aed0...  config.txt
  0b3c9187c92dd0a1...  notes.txt
  2971c2bed1725f25...  welcome.html
```

Now change something. Append a line to config.txt, add a new file, delete notes.txt, then:

```bash
python fim.py check ./demo_files
```

Output from a real run of exactly that test:

```text
Checked 3 files against baseline of 3 files.
CHANGES DETECTED:
  [NEW]      backdoor.txt
  [MODIFIED] config.txt
             baseline hash: ecb63329af09aed0b7d8c2d6a1a53a10f7adebc17979dadee3f4f06631744ae8
             current hash : d80905f96210a79212c8328ebda34832b8b773b3d8976bf1a2ba30e014a31a52
  [DELETED]  notes.txt
Summary: 1 new, 1 modified, 1 deleted.
```

One appended line changed config.txt's hash completely. That is the avalanche effect of SHA-256, and it is why a hash comparison catches edits that a file size or date check would wave through.

## Using it for real

Point it at something that should not change quietly:

```bash
python fim.py baseline C:\inetpub\wwwroot --baseline-file webroot.json
python fim.py check C:\inetpub\wwwroot --baseline-file webroot.json
```

Good candidates: web roots, configuration directories, script folders, and the system folders an incident responder checks first. The discipline matters more than the tool: take the baseline from a known good state, store the baseline somewhere the monitored machine cannot rewrite, and treat every unexplained change as a question that needs an owner.

## Honest limits

- A FIM detects change; it does not judge it. Legitimate patching changes files too, which is why baselines get refreshed after approved changes, inside change control.
- If an attacker controls the machine deeply enough, they can tamper with the tool or the baseline. Real deployments (Tripwire, OSSEC, Wazuh's FIM module) protect against this with off machine storage and alerting, which is the production version of the same idea this lab teaches.

## Skills demonstrated

- Python: hashing with hashlib, directory traversal, JSON state files, command line design with argparse, exit code discipline
- Security concepts: integrity monitoring, SHA-256 and the avalanche effect, baseline discipline, detection versus prevention
- Professional framing: how a lab tool maps to enterprise tooling (Tripwire, OSSEC, Wazuh) and to controls like CIS v8 Control 3 and PCI DSS requirement 11.5

## How this maps to the job

Integrity monitoring shows up everywhere in security operations: web defacement detection, compliance checks, and the first question of many investigations, "what changed on this box?" Being able to build the simple version, and to explain where the enterprise version hardens it, is exactly the kind of answer that lands in a SOC interview.
