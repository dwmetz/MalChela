// Matches MalChela mzcount / xmzhash inline rules. Detects MZ, PDF,
// and ZIP magic numbers at offset 0.
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule pdf_header {
    meta:
        description = "Matches files with PDF header"
    strings:
        $pdf = { 25 50 44 46 }
    condition:
        $pdf at 0
}

rule zip_header {
    meta:
        description = "Matches files with ZIP header"
    strings:
        $zip = { 50 4B 03 04 }
    condition:
        $zip at 0
}
