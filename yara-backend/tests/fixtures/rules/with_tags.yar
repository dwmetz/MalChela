// Exercises tags and metadata. The wrapper must surface both lists
// for any caller that wants them later.
rule tagged_marker : alpha beta gamma {
    meta:
        author = "yara-backend tests"
        severity = 5
        stable = true
    strings:
        $a = "tagged-marker"
    condition:
        $a
}
