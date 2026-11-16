# Macfinger ClickFix (macOS)

YARA rules for the Macfinger ClickFix campaign on macOS (named by SANS ISC), which installs the DownTheDRAIN stealer. A fake "I'm not a robot" check tells the visitor to paste a command into Terminal. That command fetches a bash script, which downloads and starts an obfuscated Go program that steals credentials, browser data, files and crypto wallets.

Plain-language guide: [Don't paste that](https://christian-michoal.github.io/dont-paste-that/)

## Rules

| Rule | Matches | Notes |
|---|---|---|
| `Macfinger_Go_Stealer_Payload` | The Go Mach-O stealer | Needs wallet-injection labels or config keys, plus keychain and privacy-check strings left in the clear by the obfuscator |
| `Macfinger_ClickFix_Paste_Command` | The command the victim pastes, in a file, log or clipboard capture | Needs a script piped into a shell (`base64 -D \| bash`, `--decode \| zsh`, `curl … \| sh`) plus fake CAPTCHA wording ("not a robot", "verification ID/code"). The encoded block changes per victim, but this campaign's always starts with `ZXhwb3J0IFNSQ19VUkw9` (`export SRC_URL=`), which counts as a lure signal on its own |
| `Macfinger_Bash_Stager` | The bash download script | Matched on its step-by-step reporting events plus its quarantine-removal and self-signing steps |

The rules match on behavior and structure, not on server addresses, hashes or wallet addresses, because those change every few days.

## Testing

Tested in an offline lab:

- The stealer rule matches the arm64 program recovered from the capture below.
- The stager rule matches the download script from the same capture.
- The paste rule matches the campaign's paste line and variants with different encoded content, different lure wording, `zsh`, and `curl … | bash`. It does not match a bare `base64 -d | bash` or `curl … | bash` without lure wording, or lure wording without a shell pipe.
- No matches against an unrelated macOS stealer (AMOS) or against `/usr/bin`, `/usr/lib` and `/opt` on a Linux analysis VM. That clean set is small, so test against your own environment before alerting on these.

## Behaviors worth alerting on

These don't need YARA and should hold even if the strings change:

- Terminal running `base64 -D | bash` or `curl … | bash` right after a browser copy
- A hidden script in `/tmp` run in the background, with the last shell history line removed
- `xattr -d com.apple.quarantine` followed by `codesign --force --sign -` on a file in a temp directory
- A new LaunchAgent with a `com.apple.*` label whose program lives in `~/Library/Caches`
- Anything other than a wallet app's own updater writing to its `app.asar`

## Sources

- Infection capture and campaign write-up: Brad Duncan, SANS ISC ([malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)), October 2026
