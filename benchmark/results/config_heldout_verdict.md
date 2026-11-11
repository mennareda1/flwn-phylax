# Configuration-file secrets scanner: held-out verdict

- Cases fingerprint: `046d0b1e5d2d` (pinned `046d0b1e5d2d`)
- Detector file `security_service/core/config_secrets.py` sha256 prefix: `0aef261b4c00378c`
- Gate (fixed before the run): at least 16 of 20 vulnerable files found, at most 1 false alarm among 20 safe files, no evidence line equal to its raw line
- **Vulnerable files found: 17 of 20** (Wilson 95%: 64% to 95%)
- **False alarms on safe files: 1 of 20** (Wilson 95%: 1% to 24%)
- Evidence lines that leak the raw line: 0
- Scan time for all 40 files: 0.01 s
- **Gate: PASSED**

## Missed vulnerable files

- `hc-commented-old-password`: an old password left in a comment, still a leaked credential
- `hc-limit-abbreviated-key`: DESIGN LIMIT: the key is the abbreviation pw, which is not in the credential-name list
- `hc-limit-dictionary-passphrase`: DESIGN LIMIT: a pure dictionary passphrase has no digit or symbol, so it is not probable by the careful test

## False alarms

- `hs-package-json`: scripts and dependencies that mention tokens; reported at [(10, 'SECRET-CONFIG')]

## Limits of this measurement

- The author of the detector also wrote the cases. They are held out from tuning, not from the author's idea of what a secret looks like.
- Whole files, 40 of them: the intervals are wide. This is evidence the detector behaves sensibly on realistic files, not an accuracy figure.
- Two vulnerable files are outside the design on purpose (abbreviated key name, pure dictionary passphrase); they are expected misses and are counted as misses.
- Only hardcoded secrets are measured. Nothing else about a configuration file is judged by Phylax.

## Addendum: what changed after this run (2026-11-11)

This verdict is for the detector as frozen (`0aef261b4c00378c`). The run found two real defects, and both were fixed afterwards:

1. **False alarm on dependency version ranges** (`"jsonwebtoken": "^9.0.2"` in `package.json`): a range with `^`, `~`, `>=` or `workspace:*` was not recognised as a version.
2. **Missed a commented-out credential with words before the key** (`# old password: Hunter2!Prod2023`): a comment marker was only allowed directly before the key.

Both fixes are covered by regression cases in `security_service/core/config_secrets.py`. **These 40 files are now development data**: the fixed detector scores 18 of 20 and 0 of 20 false alarms on them,
but that is not a held-out result and must not be quoted as one. Any future claim about the configuration scanner needs a new held-out set, written without running the detector on it.
The two designed limits remain: a key abbreviated to `pw`, and a pure dictionary passphrase.
