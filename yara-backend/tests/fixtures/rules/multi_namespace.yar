// Two rules in one file. yara-x compiles them under the same
// namespace (the default) when loaded via load_from_dir; that
// mirrors libyara's behaviour when no namespace is set.
rule rule_one {
    strings:
        $a = "marker-one"
    condition:
        $a
}

rule rule_two {
    strings:
        $b = "marker-two"
    condition:
        $b
}
