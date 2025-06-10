import csv
import datetime
import subprocess
import zipfile
from pathlib import Path

def run_tshark(pcap_path, raw_csv_path):
    tshark_command = [
        "tshark", "-r", str(pcap_path), "-T", "fields",
        "-e", "frame.time_epoch", "-e", "_ws.col.Protocol",
        "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "frame.protocols", "-e", "frame.len", "-e", "tcp.flags",
        "-e", "http.request.method", "-e", "http.request.uri",
        "-e", "http.request.full_uri", "-e", "http.user_agent",
        "-e", "tls.handshake.extensions_server_name", "-e", "dns.qry.name",
        "-E", "separator=,", "-E", "quote=d", "-E", "header=y"
    ]
    with open(raw_csv_path, "w", encoding="utf-8") as out_file:
        subprocess.run(tshark_command, stdout=out_file, check=True)

def convert_timestamps(raw_csv_path, final_csv_path):
    with open(raw_csv_path, "r", newline="", encoding="utf-8") as infile,          open(final_csv_path, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        headers = next(reader)
        headers[0] = "frame.time"
        writer.writerow(headers)

        for row in reader:
            try:
                ts = float(row[0])
                dt = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")
                row[0] = dt
            except Exception:
                row[0] = "INVALID_TIMESTAMP"
            writer.writerow(row)

def zip_csv(output_csv_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(output_csv_path, arcname=Path(output_csv_path).name)

def main():
    import os
    import sys

    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
        print(f"📁 Using provided PCAP path: {pcap_path}")
    else:
        pcap_path = input("Enter the full path to the PCAP file: ").strip()

    if not Path(pcap_path).exists():
        print("❌ Error: File not found.")
        return

    raw_csv_path = "output_raw.csv"
    final_csv_path = "output_final.csv"
    zip_path = "output_final.zip"

    print("🔍 Running TShark...")
    run_tshark(pcap_path, raw_csv_path)

    print("🕒 Converting timestamps...")
    convert_timestamps(raw_csv_path, final_csv_path)

    print("📦 Zipping final CSV...")
    zip_csv(final_csv_path, zip_path)

    print(f"✅ Done! Zipped file created: {zip_path}")
    print(f"📁 Saved to: {Path(zip_path).resolve()}")

if __name__ == "__main__":
    main()
