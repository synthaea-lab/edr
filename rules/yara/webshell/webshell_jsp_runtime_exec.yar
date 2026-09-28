// T1505.003 — Server Software Component: Web Shell (issue #478, Level 1).
// The JSP sibling of webshell_php_superglobal_exec: a java.lang.Runtime exec
// fed directly from an HTTP request parameter, the classic minimal JSP
// backdoor one-liner — not a shape ordinary JSP application code has a reason
// to produce.
//
// Patterns below are hex byte sequences, not literal strings — see
// webshell_php_superglobal_exec.yar's doc for why (this rule's sibling was
// flagged by Windows Defender as a real backdoor when written as plain text,
// 2026-09-28; same bytes, same match at scan time, just not spelled out on
// disk). Plain-text form commented alongside each pattern.
rule webshell_jsp_runtime_exec {
    meta:
        description = "JSP Runtime.exec() fed directly from a request parameter - minimal webshell backdoor shape"
        technique = "T1505.003"
    strings:
        $jsp = { 3C 25 } // "<%"
        $sink = { 52 75 6E 74 69 6D 65 2E 67 65 74 52 75 6E 74 69 6D 65 28 29 2E 65 78 65 63 28 72 65 71 75 65 73 74 2E 67 65 74 50 61 72 61 6D 65 74 65 72 } // Runtime.getRuntime().exec(request.getParameter
    condition:
        $jsp and $sink
}
