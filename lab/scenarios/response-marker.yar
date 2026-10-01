// Companion to response.sh (issue #25): matches the marker the scenario writes
// into its dropped payload. Install it under the agent's content directory
// BEFORE starting the agent, e.g. <content-dir>/rules/yara/response-marker.yar
// (the default content directory is <storage.state_dir>/content). It matches
// nothing but the scenario's own file.
rule response_scenario_marker
{
    meta:
        technique = "T1105"
        severity = "low"
        falsepositives = "none: the marker string only appears in lab/scenarios/response.sh's payload"
    strings:
        $marker = "SYNTHAEA-RESPONSE-SCENARIO-MARKER"
    condition:
        $marker
}
