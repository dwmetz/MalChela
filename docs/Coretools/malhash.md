MalHash queries malware intelligence sources using a provided hash. It checks VirusTotal and MalwareBazaar for file metadata, threat labels, antivirus detections, and known associations. A quick way to enrich an unknown sample or confirm if a hash is already known and classified in the wild.

<figure>
  <img src="/images/malhash.png" alt="Malware Hash Lookup">
  <figcaption><strong>Figure 1:</strong> Malware Hash Lookup</figcaption>
</figure>

The first time you run MalHash, you’ll be prompted to [configure API keys](/configuration/api-configuration) for VirusTotal and MalwareBazaar if they’re not already set.

