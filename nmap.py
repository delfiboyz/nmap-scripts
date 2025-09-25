import subprocess
import shlex
import sys
import os
import csv
import tempfile
from datetime import datetime
import traceback

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

ROOT = is_root()

SCAN_OPTIONS = {
    "1": ("Ping scan (only discover hosts)", "-sn"),
    "2": ("TCP connect scan (default, no root required)", "-sT"),
    "3": ("SYN stealth scan (requires root)", "-sS"),
    "4": ("UDP scan (requires root, may be slow)", "-sU"),
    "5": ("Version detection + OS detection (aggressive)", "-sV -O -A"),
    "6": ("Fast scan (top ports)", "-F"),
    "7": ("Full TCP scan (top 65535 ports)", "-p- -sS"),
    "8": ("Custom ports (you provide port list)", None),
    "9": ("Script scan (default scripts)", "-sC"),
    "10": ("Basic scan (common ports + service detection, non-root)", "-sT -sV -T4 -F --open"),
    "b": ("Basic scan (alias)", "-sT -sV -T4 -F --open"),
    "0": ("Exit", None),
}

def print_banner():
    """
    Banner ASCII yang lebih bagus: mata devil di bagian atas,
    diikuti tulisan besar 'DELFI BOYZ' di bawahnya.
    Baris kosong ditambahkan di paling atas sesuai permintaan.
    """
   
    print("")


    big_text = r'''

     (         (    (    (              )     )    )  
 )\ )      )\ ) )\ ) )\ )     (  ( /(  ( /( ( /(  
(()/(  (  (()/((()/((()/(   ( )\ )\()) )\()))\()) 
 /(_)) )\  /(_))/(_))/(_))  )((_|(_)\ ((_)\((_)\  
(_))_ ((_)(_)) (_))_(_))   ((_)_  ((_)_ ((_)_((_) 
 |   \| __| |  | |_ |_ _|   | _ )/ _ \ \ / /_  /  
 | |) | _|| |__| __| | |    | _ \ (_) \ V / / /   
 |___/|___|____|_|  |___|   |___/\___/ |_| /___|  
                                                  
'''

  
    for line in big_text.splitlines():
        print(line.center(80))
    print("")  

def build_command(target, option_flag, ports=None, extra_args="", out_gnmap=None, out_xml=None, out_txt=None):
    cmd = ["nmap"]
    if option_flag:
        cmd += shlex.split(option_flag)
    if ports:
        cmd += ["-p", ports]
    if extra_args:
        cmd += shlex.split(extra_args)
    if out_xml:
        cmd += ["-oX", out_xml]
    if out_gnmap:
        cmd += ["-oG", out_gnmap]
    if out_txt:
        cmd += ["-oN", out_txt]
    cmd += [target]
    return cmd

def run_subprocess(cmd):
    print("\n[+] Menjalankan: " + " ".join(shlex.quote(p) for p in cmd))
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        print("ERROR: 'nmap' tidak ditemukan. Pastikan nmap sudah terpasang.")
        sys.exit(1)
    except Exception as e:
        print("[!] Exception saat menjalankan nmap:")
        traceback.print_exc()
        return "", str(e), 1
    return proc.stdout, proc.stderr, proc.returncode

def parse_gnmap_to_list(gnmap_path):
    results = []
    if not os.path.exists(gnmap_path):
        return results
    try:
        with open(gnmap_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "Ports:" in line:
                    host_part = line.split("Ports:")[0]
                    ip = ""
                    if "Host:" in host_part:
                        try:
                            ip = host_part.split("Host:")[1].split()[0].strip()
                        except Exception:
                            ip = ""
                    rest = line.split("Ports:")[1]
                    rest = rest.split("Ignored State:")[0]
                    ports_field = rest.strip()
                    ports_entries = [p.strip() for p in ports_field.split(",") if p.strip()]
                    for pe in ports_entries:
                        seg = pe.split("/")
                        port = seg[0] if len(seg) > 0 else ""
                        state = seg[1] if len(seg) > 1 else ""
                        proto = seg[2] if len(seg) > 2 else ""
                        service = seg[4] if len(seg) > 4 else (seg[3] if len(seg) > 3 else "")
                        results.append({
                            "target": ip,
                            "ip": ip,
                            "port": port,
                            "protocol": proto,
                            "state": state,
                            "service": service
                        })
    except Exception:
        traceback.print_exc()
    return results

def save_csv(records, csv_path):
    if not records:
        print("[!] Tidak ada record untuk disimpan ke CSV.")
        return
    fieldnames = ["target", "ip", "port", "protocol", "state", "service"]
    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            if r.get("state", "").lower() == "open":
                writer.writerow(r)
    print(f"[+] CSV disimpan: {csv_path}")

def menu():
    print("#" * 72)
    print("AUTO NMAP - Pilih jenis scan (ketik nomor atau 'b' untuk Basic)")
    print("#" * 72)
    keys_sorted = sorted(SCAN_OPTIONS.keys(), key=lambda x: (0 if x.isdigit() else 1, int(x) if x.isdigit() else x))
    for k in keys_sorted:
        print(f"{k}. {SCAN_OPTIONS[k][0]}")
    print("#" * 72)

def main():
    try:
        while True:
            print_banner()
            menu()
            choice = input("Pilih (0 exit): ").strip()
            if choice not in SCAN_OPTIONS:
                print("Pilihan tidak valid. Coba lagi.")
                continue
            if choice == "0":
                print("Keluar.")
                break

            desc, flag = SCAN_OPTIONS[choice]
            target = input("Masukkan target (IP atau domain): ").strip()
            if not target:
                print("Target kosong, kembali ke menu.")
                continue

            ports = None
            extra = ""
            if choice == "8":
                ports = input("Masukkan daftar port (contoh: 22,80,443 atau 1-65535): ").strip()
                if not ports:
                    print("Port kosong, kembali ke menu.")
                    continue
            else:
                p = input("Ingin spesifik port? (kosong untuk default): ").strip()
                if p:
                    ports = p

            if choice in ("10", "b"):
                if ROOT:
                    if "-sT" in flag:
                        flag = flag.replace("-sT", "-sS")
                    else:
                        flag = "-sS " + flag
                    print("[*] Mode root terdeteksi -> Basic scan akan menggunakan -sS (SYN stealth).")
                else:
                    print("[*] Tidak menjalankan sebagai root -> Basic scan menggunakan -sT (TCP connect).")

            saveans = input("Simpan hasil ke file (txt/xml/gnmap)? (y/N): ").strip().lower()
            save = saveans == "y"
            out_prefix = None
            if save:
                out_prefix = input("Masukkan prefix nama file output (default: nmap_result): ").strip() or "nmap_result"

            ex = input("Tambahan flag nmap (mis. -Pn, --reason) atau tekan enter: ").strip()
            if ex:
                extra = ex

            extract_csv_ans = input("Ekstrak port terbuka ke CSV setelah scan? (y/N): ").strip().lower()
            extract_csv = extract_csv_ans == "y"

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            gnmap_tmp = None
            xml_file = None
            txt_file = None
            csv_file = None

            if save or extract_csv:
                gnmap_tmp = f"{out_prefix}_{ts}.gnmap" if out_prefix else f"nmap_{ts}.gnmap"
                xml_file = f"{out_prefix}_{ts}.xml" if out_prefix else f"nmap_{ts}.xml"
                txt_file = f"{out_prefix}_{ts}.txt" if out_prefix else f"nmap_{ts}.txt"
                csv_file = f"{out_prefix}_{ts}.csv" if out_prefix else f"nmap_{ts}.csv"

            cmd = build_command(target, flag, ports, extra_args=extra, out_gnmap=gnmap_tmp, out_xml=xml_file, out_txt=txt_file)
            stdout, stderr, rc = run_subprocess(cmd)

            if stderr:
                print("[nmap stderr]:")
                print(stderr)

            print("\n[nmap output preview]:\n")
            print(stdout)

            if extract_csv:
                if gnmap_tmp and os.path.exists(gnmap_tmp):
                    records = parse_gnmap_to_list(gnmap_tmp)
                    if records:
                        save_csv(records, csv_file)
                    else:
                        print("[!] Tidak menemukan record pada GNMAP untuk diekstrak.")
                else:
                    print("[*] GNMAP tidak ditemukan, mencoba menjalankan ulang nmap singkat dengan -oG untuk ekstraksi CSV...")
                    with tempfile.NamedTemporaryFile(prefix="nmap_gnmap_", suffix=".gnmap", delete=False) as t:
                        tmp_gnmap = t.name
                    rerun_cmd = build_command(target, flag, ports, extra_args=extra, out_gnmap=tmp_gnmap)
                    run_subprocess(rerun_cmd)
                    if os.path.exists(tmp_gnmap):
                        records = parse_gnmap_to_list(tmp_gnmap)
                        if records:
                            save_csv(records, csv_file)
                        else:
                            print("[!] Setelah rerun, tidak ditemukan port terbuka untuk diekstrak.")
                        try:
                            os.remove(tmp_gnmap)
                        except Exception:
                            pass
                    else:
                        print("[!] Gagal membuat GNMAP untuk ekstraksi.")

            if save and out_prefix:
                print(f"[+] Jika nmap mendukung, file output biasanya: {txt_file} {xml_file} {gnmap_tmp}")

            cont = input("\nKembali ke menu? (Y/n): ").strip().lower()
            if cont == "n":
                print("Selesai.")
                break
    except KeyboardInterrupt:
        print("\nDibatalkan oleh user.")
    except Exception:
        print("[!] Terjadi exception tak terduga:")
        traceback.print_exc()

if __name__ == "__main__":
    main()
