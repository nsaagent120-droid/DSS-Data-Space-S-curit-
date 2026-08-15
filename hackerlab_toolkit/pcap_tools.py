"""
=============================================================================
  Module Réseau & Analyse PCAP - HackerLab Toolkit
=============================================================================
  Description : Analyseur léger de captures réseau PCAP en pur Python
                (extraction DNS, flux HTTP, identifiants en clair et flags).
=============================================================================
"""

import struct
import socket
import re

class PCAPAnalyzer:
    @staticmethod
    def parse_pcap(file_bytes):
        """Parse les paquets d'une capture PCAP standard."""
        if len(file_bytes) < 24:
            return {"error": "Fichier trop court pour un format PCAP"}

        magic = file_bytes[:4]
        if magic in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"]:
            endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        else:
            return {"error": "Format PCAP non reconnu (ou format PCAP-NG)"}

        offset = 24 # Header global PCAP (24 bytes)
        packets = []
        protocols_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "HTTP": 0, "Autres": 0}
        dns_queries = []
        http_requests = []
        credentials = []
        flags = []

        pkt_index = 0
        while offset + 16 <= len(file_bytes):
            pkt_index += 1
            # Header du paquet (16 bytes : ts_sec, ts_usec, incl_len, orig_len)
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", file_bytes[offset:offset+16])
            offset += 16

            if offset + incl_len > len(file_bytes):
                break

            packet_data = file_bytes[offset:offset+incl_len]
            offset += incl_len

            # Analyse Ethernet + IP
            if len(packet_data) > 34 and packet_data[12:14] == b"\x08\x00": # IPv4
                ip_header = packet_data[14:34]
                proto = ip_header[9]
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dst_ip = socket.inet_ntoa(ip_header[16:20])

                payload = b""
                if proto == 6: # TCP
                    protocols_count["TCP"] += 1
                    tcp_header_len = ((packet_data[46] >> 4) & 0x0f) * 4
                    payload = packet_data[14 + 20 + tcp_header_len:]
                elif proto == 17: # UDP
                    protocols_count["UDP"] += 1
                    payload = packet_data[42:]
                elif proto == 1: # ICMP
                    protocols_count["ICMP"] += 1
                else:
                    protocols_count["Autres"] += 1

                # Analyse DNS (Port 53)
                if proto == 17 and len(packet_data) > 42:
                    src_port, dst_port = struct.unpack("!HH", packet_data[34:38])
                    if src_port == 53 or dst_port == 53:
                        protocols_count["DNS"] += 1
                        # Extraction de nom de domaine simplifiée
                        dns_payload = packet_data[42:]
                        for m in re.finditer(b"[\x03-\x15]([a-zA-Z0-9\-]{2,30})", dns_payload):
                            d_str = m.group(1).decode(errors="ignore")
                            if "." not in d_str and len(d_str) > 3 and d_str not in dns_queries:
                                dns_queries.append(d_str)

                # Analyse HTTP & Identifiants
                if payload:
                    try:
                        text = payload.decode("latin-1")
                        # HTTP Requests
                        if text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
                            protocols_count["HTTP"] += 1
                            first_line = text.split("\r\n")[0]
                            http_requests.append(f"{src_ip} -> {dst_ip}: {first_line}")

                        # Identifiants FTP en clair
                        if text.startswith("USER "):
                            credentials.append(f"FTP User ({src_ip}): {text.strip()}")
                        elif text.startswith("PASS "):
                            credentials.append(f"FTP Pass ({src_ip}): {text.strip()}")

                        # HTTP Basic Auth
                        if "Authorization: Basic " in text:
                            m = re.search(r"Authorization: Basic ([A-Za-z0-9+/=]+)", text)
                            if m:
                                import base64
                                try:
                                    decoded_auth = base64.b64decode(m.group(1)).decode()
                                    credentials.append(f"HTTP Basic Auth ({src_ip}): {decoded_auth}")
                                except Exception:
                                    pass

                        # Flags CTF
                        flag_matches = re.findall(r"(flag\{[^\}\n]{3,80}\}|HL\{[^\}\n]{3,80}\}|CTF\{[^\}\n]{3,80}\})", text, re.IGNORECASE)
                        for fl in flag_matches:
                            if fl not in flags:
                                flags.append(fl)
                    except Exception:
                        pass

        return {
            "total_packets": pkt_index,
            "protocols": protocols_count,
            "dns_queries": dns_queries[:15],
            "http_requests": http_requests[:15],
            "credentials_found": credentials,
            "flags_found": flags
        }
