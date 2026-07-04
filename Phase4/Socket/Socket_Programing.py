import sys
import os
import shutil
import subprocess
from pathlib import Path


def find_tshark():
    env_path = os.environ.get("TSHARK_PATH")
    if env_path and Path(env_path).exists():
        return env_path

    path = shutil.which("tshark")
    if path:
        return path

    common_path = r"C:\Program Files\Wireshark\tshark.exe"
    if Path(common_path).exists():
        return common_path

    print("ERROR: tshark.exe پیدا نشد.")
    print("Wireshark را نصب کن یا مسیر tshark.exe را در متغیر TSHARK_PATH قرار بده.")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("  python http_pcap_summary.py <capture_file.pcapng>")
        print()
        print("Example:")
        print("  python http_pcap_summary.py phase1_example_capture.pcapng")
        sys.exit(1)

    pcap_file = Path(sys.argv[1])

    if not pcap_file.exists():
        print(f"ERROR: فایل پیدا نشد: {pcap_file}")
        sys.exit(1)

    tshark = find_tshark()

    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.response.code",
        "http.response.phrase",
    ]

    cmd = [
        tshark,
        "-r", str(pcap_file),
        "-Y", "http",
        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",
    ]

    for field in fields:
        cmd.extend(["-e", field])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        print("ERROR while running tshark:")
        print(result.stderr)
        sys.exit(1)

    lines = result.stdout.strip().splitlines()

    if not lines:
        print("هیچ پکت HTTP در فایل پیدا نشد.")
        print("مطمئن شو فایل phase1_example_capture.pcapng را دادی، نه فایل HTTPS.")
        sys.exit(0)

    print("=" * 70)
    print("HTTP PCAP SUMMARY")
    print("=" * 70)

    requests = []
    responses = []

    for line in lines:
        parts = line.split("|")
        parts += [""] * (10 - len(parts))

        frame_no = parts[0]
        ip_src = parts[1]
        ip_dst = parts[2]
        tcp_srcport = parts[3]
        tcp_dstport = parts[4]
        method = parts[5]
        host = parts[6]
        uri = parts[7]
        status_code = parts[8]
        response_phrase = parts[9]

        if method:
            requests.append({
                "frame": frame_no,
                "src": ip_src,
                "dst": ip_dst,
                "srcport": tcp_srcport,
                "dstport": tcp_dstport,
                "method": method,
                "host": host,
                "uri": uri,
            })

        if status_code:
            responses.append({
                "frame": frame_no,
                "src": ip_src,
                "dst": ip_dst,
                "srcport": tcp_srcport,
                "dstport": tcp_dstport,
                "code": status_code,
                "phrase": response_phrase,
            })

    print("\nHTTP Requests:")
    print("-" * 70)

    for req in requests:
        print(
            f"Frame {req['frame']} | "
            f"{req['src']}:{req['srcport']} -> {req['dst']}:{req['dstport']} | "
            f"{req['method']} http://{req['host']}{req['uri']}"
        )

    print("\nHTTP Responses:")
    print("-" * 70)

    for res in responses:
        print(
            f"Frame {res['frame']} | "
            f"{res['src']}:{res['srcport']} -> {res['dst']}:{res['dstport']} | "
            f"Status: {res['code']} {res['phrase']}"
        )

    print("\nDone.")


if __name__ == "__main__":
    main()