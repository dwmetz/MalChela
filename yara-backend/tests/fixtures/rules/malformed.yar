// Deliberately broken. Used by audit and compile error path tests.
rule incomplete {
    strings:
        $a = "missing_closing_brace
