/*
   ClickFix on macOS: Macfinger campaign (SANS ISC) delivering the
   DownTheDRAIN stealer. Covers the pasted command, the bash
   download script, and the Go Mach-O stealer / wallet drainer it installs.
*/

private rule Macfinger_MachO
{
    condition:
        uint32(0) == 0xFEEDFACF or
        (uint32be(0) == 0xCAFEBABE and uint32be(4) > 0 and uint32be(4) < 0x10)
}

rule Macfinger_Go_Stealer_Payload
{
    meta:
        description = "Macfinger/DownTheDRAIN Go stealer: wallet-app injection, keychain cgo helpers, file-grabber config"
        confidence  = "high (family)"
        author      = "christian-michoal"
        date        = "2026-11-16"
        reference   = "https://github.com/christian-michoal/yara-rules/tree/main/rules/macos/macfinger-clickfix"
        platform    = "macOS"
    strings:
        $inj1 = "walletpatch_seed" ascii
        $inj2 = "ExodusSeedEncrypted.txt" ascii
        $inj3 = "AtomicPassword.txt" ascii
        $inj4 = "LedgerSeed.txt" ascii
        $inj5 = "TrezorSeed.txt" ascii
        $cfg1 = "\"replace_addresses\"" ascii
        $cfg2 = "\"seed_file_keywords\"" ascii
        $cfg3 = "\"persistence_delay_minutes\"" ascii
        $cfg4 = "\"binary_hide_path\"" ascii
        $go1  = "FileGrabberPayload" ascii
        $go2  = "enumerate_keychain_services" ascii
        $go3  = "unlock_keychain" ascii
        $go4  = "permission_limited" ascii
        $go5  = "tcc_denied" ascii
    condition:
        Macfinger_MachO and filesize > 5MB and
        (2 of ($inj*) or 3 of ($cfg*)) and 2 of ($go*)
}

rule Macfinger_ClickFix_Paste_Command
{
    meta:
        description = "ClickFix paste command for macOS: fake CAPTCHA wording combined with an encoded or downloaded script piped into a shell"
        confidence  = "high"
        author      = "christian-michoal"
        date        = "2026-11-16"
        reference   = "https://github.com/christian-michoal/yara-rules/tree/main/rules/macos/macfinger-clickfix"
        platform    = "macOS"
    strings:
        // Shell execution: decode-and-run or download-and-run
        $run_b64  = /base64\s+(-D|-d|--decode)\s*\|\s*(ba|z)?sh\b/ ascii
        $run_curl = /curl\s[^\n|]{1,400}\|\s*(ba|z)?sh\b/ ascii
        // Lure wording shown to the victim
        $robot    = "not a robot" ascii nocase
        $verify   = /(verification|captcha)\s+(id|code)/ ascii nocase
        // Optional campaign marker: base64 of the hidden script's first line, "export SRC_URL="
        $src_url  = "ZXhwb3J0IFNSQ19VUkw9" ascii
    condition:
        filesize < 200KB and
        1 of ($run_*) and
        ($robot or $verify or $src_url)
}

rule Macfinger_Bash_Stager
{
    meta:
        description = "Macfinger bash download script: reports each step to the C2, strips quarantine, ad-hoc signs and launches the payload"
        confidence  = "high"
        author      = "christian-michoal"
        date        = "2026-11-16"
        reference   = "https://github.com/christian-michoal/yara-rules/tree/main/rules/macos/macfinger-clickfix"
        platform    = "macOS"
    strings:
        $st1 = "\"e\":\"loader_start\"" ascii
        $st2 = "\"e\":\"download_ok\"" ascii
        $st3 = "\"e\":\"exec_start\"" ascii
        $st4 = "\"e\":\"exec_fail\"" ascii
        $st5 = "?force=1" ascii
        $st6 = "codesign --force --sign -" ascii
        $st7 = "xattr -d com.apple.quarantine" ascii
        $st8 = "com.apple.update" ascii
    condition:
        filesize < 200KB and uint16(0) == 0x2123 and
        3 of ($st1, $st2, $st3, $st4) and 2 of ($st5, $st6, $st7, $st8)
}
