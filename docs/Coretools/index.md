
| Program  | Function |
| :-------------------  | ----------: |
| Combine YARA	| Point it at a directory of YARA files and it will output one combined rule|
| Extract Samples | Point it at a directory of password protected malware files to extract all|
| File Analyzer | Get the hash, entropy, packing, PE info, YARA and VT match status for a file |
| Hash It | Point it to a file and get the MD5, SHA1 and SHA256 hash|
| Mismatch Miner | Hunts for exes disguised as other formats|
| mStrings | Analyzes files with Sigma rules (YAML), extracts strings, matches ReGex |
| MZMD5 | Recurse a directory, for files with MZ header, create hash list|
| MZcount | Recurse a directory, uses YARA to count MZ, Zip, PDF, other| 
| NSRL Query | Query a MD5 or SHA1 hash against NSRL|
| Strings to YARA | Prompts for metadata and strings (text file) to create a YARA rule|
| Malware Hash Lookup | Query a hash value against VirusTotal & Malware Bazaar*|
| XMZMD5 | Recurse a directory, for files without MZ, Zip or PDF header, create hash list|

**The Malware Hash Lookup requires an api key for Virus Total and Malware Bazaar.  If unidentified , MalChela will prompt you to create them the first time you run the malware lookup function.*