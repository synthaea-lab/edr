// T1505.003 — Server Software Component: Web Shell (issue #478, Level 1).
// The classic minimal PHP backdoor: a code-execution sink fed directly from a
// request superglobal, no wrapper in between — the single most common public
// webshell one-liner, taught in essentially every basic web-exploitation
// walkthrough. Deliberately narrow: the sink call immediately followed by the
// superglobal, not merely "this file calls system() somewhere" (every one of
// these functions has legitimate uses; it's the direct, unsanitized
// superglobal argument that makes this a backdoor shape rather than ordinary
// PHP).
//
// Patterns below are hex byte sequences, not literal strings: this rule's own
// source file was itself flagged by Windows Defender as Backdoor:PHP/
// Perhetshell.B!dha when the patterns were plain ASCII text (2026-09-28) —
// correct, in the narrow sense that the bytes are a real webshell signature,
// but a false positive on *this* file, which is detection content, not a
// payload. Same bytes, same match at scan time; hex encoding only changes how
// they're spelled on disk. That only holds while the comments stay clean too:
// a comment that spells a pattern back out (the open tag, or a sink followed by
// a superglobal) is the same signature in plain text and gets the file
// quarantined again on checkout (#498 review). So each pattern is described in
// words below — never write it back out as a literal string here, not even in
// a comment.
rule webshell_php_superglobal_exec {
    meta:
        description = "PHP code-execution sink fed directly from a request superglobal - minimal webshell backdoor shape"
        technique = "T1505.003"
        severity = "critical"
        falsepositives = "none known — ordinary PHP application code has no reason to feed eval/system/passthru/shell_exec/exec directly from an unsanitized request superglobal"
    strings:
        // the PHP opening tag
        $php = { 3C 3F 70 68 70 }
        // eval, then the POST array
        $sink1 = { 65 76 61 6C 28 24 5F 50 4F 53 54 }
        // eval, then the GET array
        $sink2 = { 65 76 61 6C 28 24 5F 47 45 54 }
        // eval, then the REQUEST array
        $sink3 = { 65 76 61 6C 28 24 5F 52 45 51 55 45 53 54 }
        // system, then the POST array
        $sink4 = { 73 79 73 74 65 6D 28 24 5F 50 4F 53 54 }
        // system, then the GET array
        $sink5 = { 73 79 73 74 65 6D 28 24 5F 47 45 54 }
        // system, then the REQUEST array
        $sink6 = { 73 79 73 74 65 6D 28 24 5F 52 45 51 55 45 53 54 }
        // passthru, then the POST array
        $sink7 = { 70 61 73 73 74 68 72 75 28 24 5F 50 4F 53 54 }
        // passthru, then the GET array
        $sink8 = { 70 61 73 73 74 68 72 75 28 24 5F 47 45 54 }
        // passthru, then the REQUEST array
        $sink9 = { 70 61 73 73 74 68 72 75 28 24 5F 52 45 51 55 45 53 54 }
        // shell_exec, then the POST array
        $sink10 = { 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 50 4F 53 54 }
        // shell_exec, then the GET array
        $sink11 = { 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 47 45 54 }
        // shell_exec, then the REQUEST array
        $sink12 = { 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 52 45 51 55 45 53 54 }
        // exec, then the POST array
        $sink13 = { 65 78 65 63 28 24 5F 50 4F 53 54 }
        // exec, then the GET array
        $sink14 = { 65 78 65 63 28 24 5F 47 45 54 }
        // exec, then the REQUEST array
        $sink15 = { 65 78 65 63 28 24 5F 52 45 51 55 45 53 54 }
    condition:
        $php and any of ($sink*)
}
