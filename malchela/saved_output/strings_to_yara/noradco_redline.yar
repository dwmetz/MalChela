rule noradco_redline {
	meta:
		author = "Doug Metz"
		description = "NoradCo Malware Incident"
		hash = "d0a2035c0431796c138a26d1c9a75142b613c5417dc96a9200723870d0b3a687"
	strings:
		$s1 = "https://invoice-050923.s3.amazonaws.com/invoice.exe"
		$s2 = "yee9mbi69cm7.exe"
		$s3 = "4usfliof.exe"
		$s4 = "Setup.bat"
		$s5 = "Sfxrar.exe"
		$s6 = "regsvcs.exe"

	condition:
		all of them
}
