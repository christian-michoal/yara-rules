# YARA rules

Detection rules from my malware analysis work. Each folder covers one campaign or malware family and has its own README explaining what the rules match, how they were tested, and their limits.

## Rules

| Platform | Campaign / family | Folder | Added |
|---|---|---|---|
| macOS | Macfinger ClickFix / DownTheDRAIN stealer | [rules/macos/macfinger-clickfix](rules/macos/macfinger-clickfix) | 2026-11-16 |

## Usage

Scan a file or directory with one campaign's rules:

```bash
yara -r rules/macos/macfinger-clickfix/macfinger_clickfix.yar /path/to/scan
```

Or with every rule in the repo:

```bash
find rules -name '*.yar' -exec yara -r {} /path/to/scan \;
```

Test against your own environment before alerting on any rule.

## Layout

```
rules/<platform>/<campaign-or-family>/
    <campaign_or_family>.yar
    README.md
scripts/check_rules.py    compiles every rule; run by CI on each push
```

Platforms: `windows`, `macos`, `linux`, `multi` (cross-platform or document/script based).

## Conventions

- One folder per campaign or family, lowercase with hyphens.
- Rule names are `Family_Description`, for example `Macfinger_Go_Stealer_Payload`. Private helper rules are also prefixed with the family name so rule names never collide across files.
- Every public rule has `description`, `author`, `date`, `reference`, `platform` and `confidence` in its meta.
- Prefer behavior and structure (embedded strings, config keys, file layout) over indicators like hashes, IPs, domains or wallet addresses, which go stale quickly.
- Each folder's README lists what the rules were tested against, including false-positive checks.

## Checks

`scripts/check_rules.py` compiles every `.yar` file individually and all of them together, and checks the required meta fields. It runs on every push and pull request.

```bash
pip install yara-python
python scripts/check_rules.py
```

## License

[MIT](LICENSE)
