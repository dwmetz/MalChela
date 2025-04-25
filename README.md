<div align="center">
 <img style="padding:0;vertical-align:bottom;" height="350" width="450" src="/images/malchela.png"/>
 <p>
  <h1>
   Malchela
  </h1>
  <h4>
      A YARA & Malware Analysis Toolkit written in Rust.
   </h4>
<p>
<p>
 </div>
<div align="center">
  <img style="padding:0;vertical-align:bottom;" height="381" width="554" src="/images/malchela_featured.png"/>
  <div align="left">
  <h3>
   Features:
  </h3>

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


<h3>
   About:
   </h3>

> **mal** — malware</p>
> **chela** — “crab hand”</p>
> A chela on a crab is the scientific term for a claw or pincer. It’s a specialized appendage, typically found on the first pair of legs, used for grasping, defense, and manipulating things;  just like these programs.

<h3>
Dependencies:
</h3>

```
sudo apt install openssl libssl-dev clang yara libyara-dev pkg-config build-essential
```

<h3>
Installation:
</h3>

Install Rust - https://rustup.rs/</p>

```
git clone https://github.com/dwmetz/MalChela.git
cd MalChela
cargo build
```

<h3>
Run:
</h3>

```
cargo run -p malchela
```

Caveat Emptor:
Successfully tested on MacOS on Silicon and Ubuntu. Even though it's Rust (cross-platform), Windows is problematic based on different requirements for YARA64.exe. Works on Windows in WSL! Testers (and contributors) appreciated.
