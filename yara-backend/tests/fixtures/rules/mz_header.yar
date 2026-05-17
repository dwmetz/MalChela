// Matches MalChela mzhash / mismatchminer inline rule. Detects the
// MZ header at offset 0 (Windows executables).
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
