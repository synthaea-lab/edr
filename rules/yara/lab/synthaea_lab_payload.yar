// Lab-only marker rule: the benign payloads dropped by lab/scenarios embed this
// marker so YARA detection can be validated end to end without real malware.
// Category `lab` ships to lab/dev agents only once per-ring content targeting exists.
rule synthaea_lab_payload {
    meta:
        description = "Benign lab payload marker (scenario validation)"
        technique = "T1105"
        severity = "low"
        falsepositives = "none known — the marker string is synthetic and only appears in lab scenario payloads"
    strings:
        $marker = "SYNTHAEA-LAB-PAYLOAD"
    condition:
        $marker
}
