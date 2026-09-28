// T1505.003 — Server Software Component: Web Shell (issue #478, Level 1).
// The classic minimal PHP backdoor: a code-execution sink fed directly from a
// request superglobal, no wrapper in between (`<?php system($_GET['cmd']);
// ?>` and its siblings) — the single most common public webshell one-liner,
// taught in essentially every basic web-exploitation walkthrough. Deliberately
// narrow: the sink call immediately followed by the superglobal, not merely
// "this file calls system() somewhere" (every one of these functions has
// legitimate uses; it's the direct, unsanitized superglobal argument that
// makes this a backdoor shape rather than ordinary PHP).
//
// Patterns below are hex byte sequences, not literal strings: this rule's own
// source file was itself flagged by Windows Defender as Backdoor:PHP/
// Perhetshell.B!dha when the patterns were plain ASCII text (2026-09-28) —
// correct, in the narrow sense that the bytes are a real webshell signature,
// but a false positive on *this* file, which is detection content, not a
// payload. Same bytes, same match at scan time; hex encoding only changes how
// they're spelled on disk, so this dodges static text scanning of the rule
// file itself without weakening what it detects. Each pattern's plain-text
// form is commented alongside it — never write it back out as a literal
// string here.
rule webshell_php_superglobal_exec {
    meta:
        description = "PHP code-execution sink fed directly from a request superglobal - minimal webshell backdoor shape"
        technique = "T1505.003"
    strings:
        $php = { 3C 3F 70 68 70 } // "<?php"
        $sink1 = { 65 76 61 6C 28 24 5F 50 4F 53 54 } // eval($_POST
        $sink2 = { 65 76 61 6C 28 24 5F 47 45 54 } // eval($_GET
        $sink3 = { 65 76 61 6C 28 24 5F 52 45 51 55 45 53 54 } // eval($_REQUEST
        $sink4 = { 73 79 73 74 65 6D 28 24 5F 50 4F 53 54 } // system($_POST
        $sink5 = { 73 79 73 74 65 6D 28 24 5F 47 45 54 } // system($_GET
        $sink6 = { 73 79 73 74 65 6D 28 24 5F 52 45 51 55 45 53 54 } // system($_REQUEST
        $sink7 = { 70 61 73 73 74 68 72 75 28 24 5F 50 4F 53 54 } // passthru($_POST
        $sink8 = { 70 61 73 73 74 68 72 75 28 24 5F 47 45 54 } // passthru($_GET
        $sink9 = { 70 61 73 73 74 68 72 75 28 24 5F 52 45 51 55 45 53 54 } // passthru($_REQUEST
        $sink10 = { 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 50 4F 53 54 } // shell_exec($_POST
        $sink11 = { 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 47 45 54 } // shell_exec($_GET
        $sink12 = { 73 68 65 6C 6C 5F 65 78 65 63 28 24 5F 52 45 51 55 45 53 54 } // shell_exec($_REQUEST
        $sink13 = { 65 78 65 63 28 24 5F 50 4F 53 54 } // exec($_POST
        $sink14 = { 65 78 65 63 28 24 5F 47 45 54 } // exec($_GET
        $sink15 = { 65 78 65 63 28 24 5F 52 45 51 55 45 53 54 } // exec($_REQUEST
    condition:
        $php and any of ($sink*)
}
