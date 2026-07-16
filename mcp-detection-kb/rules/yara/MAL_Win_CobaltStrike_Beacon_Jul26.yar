/*
    Cobalt Strike Beacon detection rules.

    Two independent detection strategies, kept as separate rules so each
    can be tuned/disabled without affecting the other:

      1. MAL_Win_CobaltStrike_Beacon_XORConfig
         Targets the beacon *configuration block* itself. This is the most
         reliable of the two: the config block is a fixed-size (historically
         4096-byte) structure that is mostly zero-padded, obfuscated with a
         single-byte XOR key (commonly 0x2E or 0x69 across observed
         samples). XORing long runs of 0x00 padding with a single-byte key
         produces long runs of that key byte repeated -- a strong, stable
         artifact that survives most Malleable C2 customization because
         operators rarely change the config encoding routine itself.
         Public prior art: Didier Stevens' beacon config parser/rules
         (1768.py / 1768.yar) use this same repeated-byte-run technique.

      2. MAL_Win_CobaltStrike_Beacon_DefaultArtifacts
         Targets default-template artifacts (internal PE name, legacy SMB
         pipe naming pattern) that show up when an operator has NOT
         customized the Artifact Kit / Malleable C2 profile. These are
         WEAKER signals -- fully defeated by a customized build -- so this
         rule requires multiple corroborating hits and should be treated as
         medium-confidence, not a standalone verdict.

    Neither rule alone is sufficient for high-confidence attribution;
    combine with process/network behavioral detections (e.g. the Sigma
    rules in rules/credential_access/ for the credential-theft follow-on
    activity beacons are frequently used to stage).
*/

rule MAL_Win_CobaltStrike_Beacon_XORConfig
{
    meta:
        description = "Detects Cobalt Strike Beacon configuration blocks via long runs of a single-byte XOR key (0x2E or 0x69) produced when the mostly-zero-padded config buffer is obfuscated"
        author = "detection-engineering-kb"
        reference = "https://github.com/DidierStevens/DidierStevensSuite (1768.py / 1768.yar beacon config parser); https://attack.mitre.org/software/S0154/"
        date = "2026-07-16"
        malware_family = "CobaltStrike"

    strings:
        // 32+ consecutive 0x2E bytes: XOR(0x00, 0x2E) repeated -- the
        // "legacy" default single-byte config key observed in the wild.
        $xor_key_2e = { 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E
                         2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E }

        // 32+ consecutive 0x69 bytes: XOR(0x00, 0x69) repeated -- the
        // other commonly observed single-byte config key.
        $xor_key_69 = { 69 69 69 69 69 69 69 69 69 69 69 69 69 69 69 69
                         69 69 69 69 69 69 69 69 69 69 69 69 69 69 69 69 }

    condition:
        filesize < 20MB and
        (
            #xor_key_2e >= 1 or
            #xor_key_69 >= 1
        )
}

rule MAL_Win_CobaltStrike_Beacon_DefaultArtifacts
{
    meta:
        description = "Detects Cobalt Strike Beacon loader/DLL artifacts left behind when an operator uses default Artifact Kit templates rather than a customized build; requires multiple corroborating indicators to reduce false positives from customized or unrelated samples"
        author = "detection-engineering-kb"
        reference = "https://attack.mitre.org/software/S0154/; https://www.cobaltstrike.com/help-artifact-kit"
        date = "2026-07-16"
        malware_family = "CobaltStrike"

    strings:
        // Default internal PE name baked in by the unmodified Artifact
        // Kit / stageless beacon build templates.
        $internal_name_x86 = "beacon.dll" ascii nocase
        $internal_name_x64 = "beacon.x64.dll" ascii nocase

        // Reflective loader export name, inherited from Stephen Fewer's
        // reflective DLL injection technique that Beacon's loader is
        // built on; present in unstripped/unmodified builds.
        $reflective_loader = "ReflectiveLoader" ascii

        // Legacy default SMB Beacon named-pipe naming pattern used prior
        // to routine pipe-name randomization; only fires against builds
        // that did not override the pipename in the Malleable C2 profile.
        $legacy_pipe_pattern = /\\\\\.\\pipe\\MSSE-[0-9]{2,4}-server/ ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            ($reflective_loader and 1 of ($internal_name_*)) or
            $legacy_pipe_pattern
        )
}
