rule malchela-test {
	meta:
		author = "doug metz"
		description = "test rule"
		hash = "unknown"

	strings:
		$s1 = "Malware"
		$s2 = "Sample"
		$s3 = "Badness"
		$s4 = "Really bad things"
		$s5 = "Other stuff"

	condition:
		all of them
}
