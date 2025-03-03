<div align="center">
 <img style="padding:0;vertical-align:bottom;" height="400" width="400" src="/images/malchela.png"/>
 <p>
  <h2>
   Malchela
  </h2>
  <h4>
      A YARA & Malware Analysis Toolkit written in Rust.
   </h4>
<p>
<p>
 </div>
<div align="center">
  <img style="padding:0;vertical-align:bottom;" height="545" width="792" src="/images/malchela_screenshot.png"/>
  <div align="left">
  <h3>
   Features:
  </h3>

>- Combine YARA	:: Point it at a directory of YARA files and it will output one combined rule
>- Extract Samples :: Point it at a directory of password protected malware files to extract all
>- Hash It :: Point it to a file and get the MD5, SHA1 and SHA256 hash
>- Measure YARA :: Calculate the speed of YARA searches using a single rule or a directory of rules
>- MZMD5 :: Recurse a directory, for files with MZ header, create hash list
>- MZcount :: Recurse a directory, uses YARA to count MZ, Zip, PDF, other 
>- NSRL MD5 Lookup :: Query a MD5 hash against NSRL
>- NSRL SHA1 Lookup :: Query a SHA1hash against NSRL 
>- Strings to YARA :: Prompts for metadata and strings (text file) to create a YARA rule
>- Malware Hash Lookup :: Query a hash value against VirusTotal & Malware Bazaar*
>- XMZMD5 :: Recurse a directory, for files without MZ, Zip or PDF header, create hash list


*The Malware Hash Lookup requires an api key for Virus Total and Malware Bazaar.  If unidentified , MalChela will prompt you to create them the first time you run the malware lookup function.


<h5>
   About:
   </h5>

> mal — malware</p>
> chela — “crab hand”

>- A chela on a crab is the scientific term for a claw or pincer. It’s a specialized appendage, typically found on the first pair of legs, used for grasping, defense, and manipulating things;  just like these programs.

<h5>
Installation:
</h5>

- Install Rust - https://rustup.rs/
- Git clone https://github.com/dwmetz/MalChela.git
- cd MalChela
- cargo build

<h5>
   Run:
</h5>

- cargo run -p malchela

