#!/usr/bin/env python3
"""
codequantum - Post-Quantum Compatibility Scanner

Audit a host, IP or a whole list of them and pinpoint exactly which key
exchanges, certificates, signatures and protocols break when a
cryptographically-relevant quantum computer arrives -- then rank the findings
into a migration timeline you can actually action.

The scanner separates two very different clocks:

  HNDL  (harvest-now-decrypt-later)  traffic recorded TODAY is decrypted later.
                                     Classical-only key exchange. Urgent now.
  Q-DAY (signature / identity break)  only fails when the quantum computer
                                     exists. Schedulable against cert expiry.

Usage examples:
    python3 codequantum.py example.com
    python3 codequantum.py 192.168.1.10 --ports 443,22,8443
    python3 codequantum.py -f targets.txt --json report.json -o report.txt
    python3 codequantum.py --self-test
"""

import argparse
import concurrent.futures
import datetime
import io
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import warnings

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        dsa, ec, ed448, ed25519, rsa, x448, x25519,
    )
except ImportError:
    sys.exit("codequantum requires 'cryptography'. Install with:  pip install cryptography")

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ----------------------------------------------------------------------------
# Colors
# ----------------------------------------------------------------------------
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Stacked chrome lettering, Back to the Future style: small word above,
# big word below, lit from the top so it reads as polished metal.
BANNER_ROWS = [
    r"                 ██████╗ ██████╗ ██████╗ ███████╗",
    r"                ██╔════╝██╔═══██╗██╔══██╗██╔════╝",
    r"                ██║     ██║   ██║██║  ██║█████╗  ",
    r"                ██║     ██║   ██║██║  ██║██╔══╝  ",
    r"                ╚██████╗╚██████╔╝██████╔╝███████╗",
    r"                 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝",
    r" ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗",
    r"██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║",
    r"██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║",
    r"██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║",
    r"╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║",
    r" ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝",
]

# Light at the top, deep blue at the bottom -- the chrome gradient.
BANNER_GRADIENT = [189, 147, 111, 75, 39, 27]


def print_banner(color=True):
    print()
    for i, row in enumerate(BANNER_ROWS):
        if color:
            shade = BANNER_GRADIENT[i % len(BANNER_GRADIENT)]
            print(f"\033[1;38;5;{shade}m{row}\033[0m")
        else:
            print(row)
    print()


# ----------------------------------------------------------------------------
# Timeline anchors  (NIST IR 8547 initial public draft, Nov 2024)
# ----------------------------------------------------------------------------
DEPRECATED_AFTER = 2030   # quantum-vulnerable public key: no new deployments
DISALLOWED_AFTER = 2035   # quantum-vulnerable public key: disallowed outright

TIMELINE_NOTE = (
    "NIST IR 8547 (initial public draft): RSA / ECDSA / ECDH / finite-field DH "
    "are DEPRECATED after 2030 and DISALLOWED after 2035. Hybrid modes pairing "
    "an approved PQC algorithm with a classical one are not caught by the 2035 "
    "disallowance."
)

DEFAULT_PORTS = [443, 22, 25, 465, 587, 993, 995, 8443]
STARTTLS_PORTS = {25: "smtp", 587: "smtp", 110: "pop3", 143: "imap", 21: "ftp"}

# ----------------------------------------------------------------------------
# Severity model
# ----------------------------------------------------------------------------
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
SEV_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": BLUE,
    "INFO": DIM,
    "UNKNOWN": MAGENTA,
}

# clock: HNDL = recorded now, broken later.  QDAY = only breaks on Q-day.
# CLASSICAL = already broken without any quantum computer at all.


def finding(sev, clock, target, where, title, detail, fix, deadline=None):
    return {
        "severity": sev,
        "clock": clock,
        "target": target,
        "where": where,
        "title": title,
        "detail": detail,
        "remediation": fix,
        "deadline": deadline,
    }


# ----------------------------------------------------------------------------
# Local capability probe
#
# This is the part most PQ scanners get wrong. If the local OpenSSL cannot
# OFFER an ML-KEM hybrid group, then every server on earth looks "not PQ"
# -- the scanner is measuring its own plumbing, not the target. So we probe
# ourselves first and downgrade those verdicts to UNDETERMINED.
# ----------------------------------------------------------------------------
PQ_TLS_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "X25519Kyber768Draft00"]


class LocalCapability:
    def __init__(self):
        self.openssl_version = "unknown"
        self.pq_groups = []
        self.legacy_tls = {}
        self.probe()

    def probe(self):
        try:
            out = subprocess.run(["openssl", "version"], capture_output=True,
                                 text=True, timeout=10)
            self.openssl_version = out.stdout.strip() or "unknown"
        except Exception:
            pass

        # Can our OpenSSL even name a hybrid PQ group?
        for g in PQ_TLS_GROUPS:
            try:
                r = subprocess.run(
                    ["openssl", "s_client", "-groups", g, "-connect", "127.0.0.1:1"],
                    capture_output=True, text=True, timeout=10,
                )
                blob = (r.stdout + r.stderr)
                # "cannot be set" == our OpenSSL does not know this group at all.
                if "cannot be set" not in blob and "SSL_CONF_cmd" not in blob:
                    self.pq_groups.append(g)
            except Exception:
                pass

        # Can we offer legacy TLS locally? (openssl.cnf MinProtocol often blocks
        # the CLI, but a Python SSLContext can override it.)
        for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1),
                           ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                           ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
                           ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
            self.legacy_tls[label] = self._can_offer(ver)

    @staticmethod
    def _can_offer(ver):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            return True
        except Exception:
            return False

    @property
    def can_test_pq_kex(self):
        return bool(self.pq_groups)

    def report(self):
        lines = []
        lines.append(f"{DIM}local openssl : {self.openssl_version}{RESET}")
        if self.can_test_pq_kex:
            lines.append(f"{GREEN}PQ KEX probing: ENABLED "
                         f"({', '.join(self.pq_groups)}){RESET}")
        else:
            lines.append(
                f"{MAGENTA}PQ KEX probing: UNAVAILABLE{RESET} "
                f"{DIM}- this OpenSSL cannot offer ML-KEM hybrid groups "
                f"(needs >= 3.5, or oqs-provider). TLS post-quantum readiness "
                f"will be reported UNDETERMINED, never as 'not supported'.{RESET}"
            )
        blocked = [k for k, v in self.legacy_tls.items() if not v]
        if blocked:
            lines.append(f"{MAGENTA}legacy TLS offer blocked locally: "
                         f"{', '.join(blocked)}{RESET}")
        return "\n".join(lines)


# ----------------------------------------------------------------------------
# Network helpers
# ----------------------------------------------------------------------------
def is_ip(host):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            continue
    return False


def port_open(host, port, timeout=4.0):
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except Exception:
        return False


def normalize_target(raw):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None, None
    port = None
    if "://" in raw:
        m = re.match(r"^\w+://([^/]+)", raw)
        raw = m.group(1) if m else raw
    raw = raw.split("/")[0]
    m = re.match(r"^\[(.+)\](?::(\d+))?$", raw)          # [v6]:port
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else None
    if raw.count(":") == 1 and not is_ip(raw):
        host, p = raw.rsplit(":", 1)
        if p.isdigit():
            return host, int(p)
    return raw, port


# ----------------------------------------------------------------------------
# TLS probing
# ----------------------------------------------------------------------------
TLS_VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


def _starttls(sock, proto, host):
    """Drive the plaintext preamble so we can hand back a socket ready to wrap."""
    def rd():
        return sock.recv(4096).decode(errors="replace")

    if proto == "smtp":
        rd()
        sock.sendall(b"EHLO codequantum.local\r\n")
        banner = rd()
        if "STARTTLS" not in banner.upper():
            raise ssl.SSLError("server does not advertise STARTTLS")
        sock.sendall(b"STARTTLS\r\n")
        if not rd().startswith("220"):
            raise ssl.SSLError("STARTTLS refused")
    elif proto == "imap":
        rd()
        sock.sendall(b"a1 STARTTLS\r\n")
        if "OK" not in rd():
            raise ssl.SSLError("STARTTLS refused")
    elif proto == "pop3":
        rd()
        sock.sendall(b"STLS\r\n")
        if not rd().startswith("+OK"):
            raise ssl.SSLError("STLS refused")
    elif proto == "ftp":
        rd()
        sock.sendall(b"AUTH TLS\r\n")
        if not rd().startswith("234"):
            raise ssl.SSLError("AUTH TLS refused")
    return sock


def tls_handshake(host, port, version, sni, timeout=6.0, starttls=None):
    """Return (status, info). status is one of ok / refused / local / error.

    'local' means WE could not even offer that version -- never a server verdict.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except Exception as e:
        return "local", str(e)

    try:
        raw = socket.create_connection((host, port), timeout)
    except Exception as e:
        return "error", str(e)

    try:
        if starttls:
            _starttls(raw, starttls, host)
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            info = {
                "cipher": s.cipher(),
                "version": s.version(),
                "chain": [],
            }
            try:
                # Python 3.13+ only; falls back to the leaf, and full_chain()
                # backfills the intermediates via s_client -showcerts.
                info["chain"] = [bytes(d) for d in s.get_unverified_chain()]
            except AttributeError:
                der = s.getpeercert(binary_form=True)
                if der:
                    info["chain"] = [der]
            return "ok", info
    except ssl.SSLError as e:
        return "refused", str(e)
    except Exception as e:
        return "error", str(e)
    finally:
        try:
            raw.close()
        except Exception:
            pass


PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def full_chain(host, port, sni, starttls=None, timeout=15):
    """Collect the FULL presented chain via s_client -showcerts.

    SSLSocket.get_unverified_chain() only exists on Python 3.13+, and
    getpeercert(binary_form=True) returns the leaf alone -- which silently
    drops intermediate CAs. Intermediates are usually long-lived RSA-2048,
    exactly what a 'which certificates break' inventory must surface.
    """
    import base64
    cmd = ["openssl", "s_client", "-showcerts", "-connect", f"{host}:{port}"]
    if sni and not is_ip(sni):
        cmd += ["-servername", sni]
    if starttls:
        cmd += ["-starttls", starttls]
    try:
        r = subprocess.run(cmd, input="", capture_output=True, text=True,
                           timeout=timeout)
    except Exception:
        return []
    ders = []
    for pem in PEM_RE.findall(r.stdout + r.stderr):
        body = "".join(l for l in pem.splitlines() if "-----" not in l)
        try:
            ders.append(base64.b64decode(body))
        except Exception:
            pass
    return ders


def server_temp_key(host, port, sni, timeout=12):
    """Ask s_client for the negotiated key-exchange group. This is the ONLY
    place the actual KEX group is visible -- Python's ssl module never exposes
    it."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}"]
    if sni and not is_ip(sni):
        cmd += ["-servername", sni]
    try:
        r = subprocess.run(cmd, input="", capture_output=True, text=True,
                           timeout=timeout)
    except Exception:
        return None, None
    blob = r.stdout + r.stderr
    temp = None
    m = re.search(r"Server Temp Key:\s*(.+)", blob)
    if m:
        temp = m.group(1).strip()
    group = None
    m = re.search(r"Negotiated TLS1\.3 group:\s*(.+)", blob)
    if m:
        group = m.group(1).strip()
    return temp, group


def pq_kex_probe(host, port, sni, cap, timeout=12):
    """Offer ONLY hybrid PQ groups. If the handshake completes, the server
    genuinely speaks post-quantum key exchange."""
    if not cap.can_test_pq_kex:
        return "UNDETERMINED", ("local OpenSSL cannot offer ML-KEM hybrid groups "
                                "(needs >= 3.5 or oqs-provider)")
    cmd = ["openssl", "s_client", "-groups", ":".join(cap.pq_groups),
           "-connect", f"{host}:{port}"]
    if sni and not is_ip(sni):
        cmd += ["-servername", sni]
    try:
        r = subprocess.run(cmd, input="", capture_output=True, text=True,
                           timeout=timeout)
    except Exception as e:
        return "UNDETERMINED", str(e)
    blob = r.stdout + r.stderr
    m = re.search(r"Server Temp Key:.*(MLKEM|Kyber).*", blob, re.I)
    if m:
        m2 = re.search(r"Server Temp Key:\s*(.+)", blob)
        return "SUPPORTED", m2.group(1).strip()
    m = re.search(r"Negotiated TLS1\.3 group:.*(MLKEM|Kyber).*", blob, re.I)
    if m:
        m2 = re.search(r"Negotiated TLS1\.3 group:\s*(.+)", blob)
        return "SUPPORTED", m2.group(1).strip()
    # Some OpenSSL/oqs-provider combos (e.g. 3.0.x CLI + oqs-provider) never
    # print "Server Temp Key" for a provider-defined hybrid group -- the
    # negotiation still happened, the CLI just can't name it. Since ONLY
    # hybrid PQ groups were offered, a completed handshake is still proof:
    # a non-PQ-capable server would have had nothing to agree on and the
    # handshake would fail outright (verified: offering a lone unsupported
    # PQ group against a real server yields an explicit alert, not a silent
    # success).
    if re.search(r"alert handshake failure|no shared cipher|no suitable key share|"
                 r"cannot be set|SSL_CONF_cmd|connect:errno|connection refused",
                 blob, re.I):
        return "NOT_SUPPORTED", "server refused every hybrid PQ group offered"
    if "Cipher is" in blob and "Verify return code" in blob:
        return "SUPPORTED", ("hybrid PQ group (name not printed by this OpenSSL/"
                             "oqs-provider combo; inferred -- only PQ groups were "
                             "offered and the handshake completed)")
    return "UNDETERMINED", "handshake did not complete"


# ----------------------------------------------------------------------------
# Certificate analysis
# ----------------------------------------------------------------------------
def analyse_cert(der):
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        alg, bits, quantum = "RSA", pub.key_size, "BROKEN_BY_SHOR"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        alg, bits, quantum = f"ECDSA-{pub.curve.name}", pub.curve.key_size, "BROKEN_BY_SHOR"
    elif isinstance(pub, dsa.DSAPublicKey):
        alg, bits, quantum = "DSA", pub.key_size, "BROKEN_BY_SHOR"
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        alg, bits, quantum = "EdDSA", 256, "BROKEN_BY_SHOR"
    elif isinstance(pub, (x25519.X25519PublicKey, x448.X448PublicKey)):
        alg, bits, quantum = "X25519/X448", 256, "BROKEN_BY_SHOR"
    else:
        alg, bits, quantum = type(pub).__name__, None, "UNKNOWN"

    try:
        sig = cert.signature_algorithm_oid._name
    except Exception:
        sig = "unknown"

    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    def name(n):
        try:
            return n.rfc4514_string()
        except Exception:
            return str(n)

    try:
        sans = [g.value for g in
                cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value
                .get_values_for_type(x509.DNSName)]
    except Exception:
        sans = []

    return {
        "subject": name(cert.subject),
        "issuer": name(cert.issuer),
        "self_signed": cert.subject == cert.issuer,
        "key_algorithm": alg,
        "key_bits": bits,
        "quantum_status": quantum,
        "signature_algorithm": sig,
        "not_after": not_after.isoformat(),
        "not_after_year": not_after.year,
        "days_remaining": (not_after - datetime.datetime.now(datetime.timezone.utc)).days,
        "sans": sans[:12],
    }


WEAK_SIG = re.compile(r"md5|sha1", re.I)
WEAK_CIPHER = re.compile(r"RC4|DES|3DES|NULL|EXPORT|MD5|anon", re.I)


# ----------------------------------------------------------------------------
# SSH probing -- raw KEXINIT, no paramiko.
# This is the one place we get a TRUE post-quantum positive on this box.
# ----------------------------------------------------------------------------
PQ_SSH_KEX = re.compile(r"sntrup|mlkem|kyber", re.I)


def ssh_probe(host, port=22, timeout=6.0):
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(timeout)
    except Exception as e:
        return {"error": str(e)}
    try:
        banner = b""
        while b"\r\n" not in banner and len(banner) < 1024:
            chunk = s.recv(256)
            if not chunk:
                break
            banner += chunk
        if not banner.startswith(b"SSH-"):
            return {"error": "not an SSH service"}
        s.sendall(b"SSH-2.0-codequantum_scan\r\n")

        data = b""
        while len(data) < 4:
            data += s.recv(4096)
        plen = struct.unpack(">I", data[:4])[0]
        while len(data) < 4 + plen:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk

        payload = data[5:4 + plen]
        if not payload or payload[0] != 20:          # SSH_MSG_KEXINIT
            return {"error": "no KEXINIT received"}
        b = io.BytesIO(payload[17:])                 # skip msg type + 16b cookie

        def namelist():
            raw = b.read(4)
            if len(raw) < 4:
                return []
            n = struct.unpack(">I", raw)[0]
            return [x for x in b.read(n).decode(errors="replace").split(",") if x]

        return {
            "banner": banner.decode(errors="replace").strip(),
            "kex": namelist(),
            "host_key": namelist(),
            "cipher_c2s": namelist(),
            "cipher_s2c": namelist(),
            "mac_c2s": namelist(),
            "mac_s2c": namelist(),
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        try:
            s.close()
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Classification
# ----------------------------------------------------------------------------
def classify_tls(tgt, port, res, cap, findings):
    where = f"{tgt}:{port}/tls"

    # --- protocol versions -------------------------------------------------
    for label, status, info in res["versions"]:
        if status == "ok":
            if label in ("TLSv1.0", "TLSv1.1"):
                findings.append(finding(
                    "HIGH", "CLASSICAL", tgt, where,
                    f"{label} enabled",
                    f"Server completed a {label} handshake "
                    f"(negotiated {info.get('version')}). This is broken today, "
                    "without any quantum computer, and it can never carry a "
                    "post-quantum key exchange.",
                    "Disable TLS 1.0/1.1. TLS 1.3 only is the PQ migration path; "
                    "hybrid ML-KEM groups exist only in TLS 1.3.",
                ))
        elif status == "local":
            findings.append(finding(
                "UNKNOWN", "N/A", tgt, where,
                f"{label} UNDETERMINED",
                f"The scanner could not offer {label} locally ({info}). "
                "This is a limitation of this machine, not a server verdict.",
                "Re-run from a host whose OpenSSL permits the legacy protocol, "
                "or treat this line as untested.",
            ))

    if not res["tls13"]:
        findings.append(finding(
            "HIGH", "HNDL", tgt, where,
            "No TLS 1.3",
            "The server did not negotiate TLS 1.3. Hybrid post-quantum key "
            "exchange (X25519MLKEM768) is defined for TLS 1.3 only, so this "
            "endpoint has no migration path at all in its current config.",
            "Enable TLS 1.3. It is the prerequisite for every PQ option.",
            deadline=f"before {DEPRECATED_AFTER}",
        ))

    # --- key exchange: the HNDL clock --------------------------------------
    pq_status, pq_detail = res["pq_kex"]
    if pq_status == "SUPPORTED":
        findings.append(finding(
            "INFO", "HNDL", tgt, where,
            "Post-quantum key exchange SUPPORTED",
            f"Server negotiated a hybrid PQ group ({pq_detail}). Traffic "
            "recorded today is not retroactively decryptable by a future "
            "quantum computer.",
            "No action. Keep the hybrid group enabled through the transition.",
        ))
    elif pq_status == "NOT_SUPPORTED":
        findings.append(finding(
            "CRITICAL", "HNDL", tgt, where,
            "Classical-only key exchange (harvest-now-decrypt-later)",
            f"Server refused every hybrid PQ group offered. Negotiated key "
            f"exchange: {res['temp_key'] or 'classical'}. Any traffic an "
            "adversary records TODAY can be decrypted retroactively once a "
            "CRQC exists. This clock is already running.",
            "Enable X25519MLKEM768 (OpenSSL >= 3.5, BoringSSL, Go 1.24+, "
            "nginx/Apache linked against a PQ-capable TLS library). Hybrid is "
            "safe to deploy now -- it falls back cleanly.",
            deadline="NOW - recorded traffic is already exposed",
        ))
    else:
        findings.append(finding(
            "UNKNOWN", "HNDL", tgt, where,
            "Post-quantum key exchange UNDETERMINED",
            f"Could not test: {pq_detail}. Negotiated key exchange was "
            f"{res['temp_key'] or 'unknown'}. This is NOT evidence the server "
            "lacks PQ support -- the scanner could not ask the question.",
            "Upgrade local OpenSSL to >= 3.5 (or install oqs-provider) and "
            "re-run, then treat the result as authoritative.",
        ))

    # Preference-order check. This is only meaningful when we can actually
    # OFFER a PQ group -- otherwise the server picks a classical group because
    # we gave it no other choice, and the observation says nothing about the
    # server. Same logic as the SSH first-preference check below.
    if (cap.can_test_pq_kex and pq_status == "SUPPORTED" and res["temp_key"]
            and not re.search(r"MLKEM|Kyber", res["temp_key"], re.I)):
        findings.append(finding(
            "HIGH", "HNDL", tgt, where,
            f"PQ supported but not preferred (default: {res['temp_key']})",
            "The server negotiates a hybrid PQ group when forced, but with a "
            "normal client offer it selects a classical group. Real clients "
            "are therefore not getting post-quantum protection by default.",
            "Move the hybrid PQ group to the front of the server's group "
            "preference list.",
            deadline="NOW",
        ))

    # --- ciphers ------------------------------------------------------------
    for label, status, info in res["versions"]:
        if status != "ok":
            continue
        cipher = (info.get("cipher") or ("", "", 0))
        cname, _, cbits = cipher
        if cname and WEAK_CIPHER.search(cname):
            findings.append(finding(
                "CRITICAL", "CLASSICAL", tgt, where,
                f"Broken cipher offered: {cname}",
                f"Negotiated under {label}. This is broken by classical "
                "cryptanalysis today; quantum is not the issue here.",
                "Remove immediately. Restrict to AEAD suites.",
                deadline="NOW",
            ))
        elif cbits and cbits < 256:
            findings.append(finding(
                "LOW", "QDAY", tgt, where,
                f"{cbits}-bit symmetric cipher ({cname})",
                "Grover's algorithm halves the effective security margin of "
                f"symmetric ciphers, taking {cbits}-bit to ~{cbits // 2}-bit. "
                "This is a WEAKENING, not a break -- Grover parallelizes very "
                "poorly and AES-128 is still considered defensible. Prefer "
                "AES-256 for data with a long confidentiality lifetime.",
                "Prefer AES-256-GCM / ChaCha20-Poly1305 for long-lived secrets.",
                deadline=f"by {DISALLOWED_AFTER}",
            ))

    # --- certificates: the Q-day clock -------------------------------------
    now_year = datetime.datetime.now(datetime.timezone.utc).year
    for i, c in enumerate(res["certs"]):
        role = "leaf" if i == 0 else f"chain[{i}]"
        cw = f"{where}/cert/{role}"

        if WEAK_SIG.search(c["signature_algorithm"]):
            findings.append(finding(
                "CRITICAL", "CLASSICAL", tgt, cw,
                f"Weak certificate signature: {c['signature_algorithm']}",
                f"{role} '{c['subject']}' is signed with a hash that is "
                "already broken classically.",
                "Re-issue with SHA-256 or better.",
                deadline="NOW",
            ))

        if c["quantum_status"] == "BROKEN_BY_SHOR":
            sev = "MEDIUM"
            dl = f"deprecated after {DEPRECATED_AFTER}"
            extra = ""
            if c["not_after_year"] > DISALLOWED_AFTER:
                sev, dl = "HIGH", f"cert outlives the {DISALLOWED_AFTER} disallow date"
                extra = (f" This certificate is valid until {c['not_after'][:10]}, "
                         f"past the NIST disallow date of {DISALLOWED_AFTER}.")
            elif c["not_after_year"] > DEPRECATED_AFTER:
                sev, dl = "HIGH", f"cert outlives the {DEPRECATED_AFTER} deprecation date"
                extra = (f" This certificate is valid until {c['not_after'][:10]}, "
                         f"past the NIST deprecation date of {DEPRECATED_AFTER}.")
            keydesc = c["key_algorithm"] + (f"-{c['key_bits']}" if c["key_bits"] else "")
            findings.append(finding(
                sev, "QDAY", tgt, cw,
                f"Quantum-vulnerable certificate key: {keydesc}",
                f"{role} '{c['subject']}' uses {keydesc}, which Shor's "
                "algorithm breaks outright. Unlike key exchange this only "
                "fails ON Q-day -- recorded traffic is not at risk from the "
                "signature, so this is schedulable rather than urgent." + extra,
                "Plan re-issuance onto ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) "
                "once your CA offers them. Shorten cert lifetimes now so the "
                "swap is routine rather than a migration project.",
                deadline=dl,
            ))

        if c["key_algorithm"] == "RSA" and c["key_bits"] and c["key_bits"] < 2048:
            findings.append(finding(
                "CRITICAL", "CLASSICAL", tgt, cw,
                f"RSA key below 2048 bits ({c['key_bits']})",
                "Weak against classical factoring, never mind quantum.",
                "Re-issue at RSA-3072 minimum, or move to ECDSA P-256 now and "
                "ML-DSA later.",
                deadline="NOW",
            ))

        if i == 0:
            if c["days_remaining"] < 0:
                findings.append(finding(
                    "CRITICAL", "CLASSICAL", tgt, cw, "Certificate EXPIRED",
                    f"Expired {abs(c['days_remaining'])} days ago "
                    f"({c['not_after'][:10]}).",
                    "Renew immediately.", deadline="NOW"))
            elif c["days_remaining"] < 30:
                findings.append(finding(
                    "MEDIUM", "CLASSICAL", tgt, cw, "Certificate expiring soon",
                    f"Expires in {c['days_remaining']} days.",
                    "Renew / check automation.", deadline="NOW"))
            if c["self_signed"]:
                findings.append(finding(
                    "LOW", "CLASSICAL", tgt, cw, "Self-signed certificate",
                    "Leaf is self-signed; no external trust path.",
                    "Fine for internal services; note it is invisible to "
                    "CA-driven PQ migration tooling."))

    if res["hostname_mismatch"]:
        findings.append(finding(
            "MEDIUM", "CLASSICAL", tgt, where, "Certificate does not match host",
            res["hostname_mismatch"],
            "Correct the SAN list, or scan by the name the cert actually "
            "presents. (The scan itself continued with verification off.)"))


PQ_SSH_ADVICE = ("Enable sntrup761x25519-sha512@openssh.com (OpenSSH 8.5+, "
                 "default since 9.0) or mlkem768x25519-sha256 (OpenSSH 9.9+) "
                 "and put it first in KexAlgorithms.")


def classify_ssh(tgt, port, info, findings):
    where = f"{tgt}:{port}/ssh"
    if "error" in info:
        return
    kex = info.get("kex", [])
    pq = [k for k in kex if PQ_SSH_KEX.search(k)]

    if pq:
        first_is_pq = bool(kex and PQ_SSH_KEX.search(kex[0]))
        findings.append(finding(
            "INFO" if first_is_pq else "MEDIUM", "HNDL", tgt, where,
            "Post-quantum SSH key exchange " +
            ("SUPPORTED and preferred" if first_is_pq else "supported but NOT preferred"),
            f"Server offers {', '.join(pq)}." +
            ("" if first_is_pq else
             f" However its first preference is '{kex[0]}', which is classical "
             "-- clients that follow server preference get no PQ protection."),
            "No action." if first_is_pq else
            "Move the PQ algorithm to the front of KexAlgorithms.",
        ))
    else:
        findings.append(finding(
            "CRITICAL", "HNDL", tgt, where,
            "SSH key exchange is classical-only (harvest-now-decrypt-later)",
            f"No PQ key exchange offered. Server advertises: "
            f"{', '.join(kex[:6])}. Recorded SSH sessions -- which typically "
            "carry credentials, keys and admin traffic -- are retroactively "
            "decryptable once a CRQC exists. SSH sessions are exactly the "
            "long-lived-secret traffic worth harvesting.",
            PQ_SSH_ADVICE,
            deadline="NOW - recorded sessions are already exposed",
        ))

    for hk in info.get("host_key", []):
        if hk.startswith("ssh-rsa"):
            findings.append(finding(
                "HIGH", "CLASSICAL", tgt, where,
                "SSH host key algorithm 'ssh-rsa' (SHA-1) offered",
                "ssh-rsa uses SHA-1 signatures, deprecated and disabled by "
                "default in OpenSSH 8.8+.",
                "Remove ssh-rsa from HostKeyAlgorithms; keep rsa-sha2-*.",
                deadline="NOW"))

    hostkeys = info.get("host_key", [])
    if hostkeys:
        findings.append(finding(
            "MEDIUM", "QDAY", tgt, where,
            "SSH host keys are quantum-vulnerable",
            f"Host key algorithms ({', '.join(hostkeys[:4])}) all rely on "
            "RSA/ECDSA/Ed25519, every one of which Shor breaks. On Q-day host "
            "identity becomes forgeable, enabling MITM. No PQ SSH host key "
            "algorithm is standardised yet, so this is a watch item.",
            "Track OpenSSH releases for PQ host key support. Meanwhile keep "
            "known_hosts pinning tight and prefer certificate-based host auth.",
            deadline=f"before {DISALLOWED_AFTER}"))

    weak_macs = [m for m in info.get("mac_c2s", []) if re.search(r"md5|sha1|-96", m, re.I)]
    if weak_macs:
        findings.append(finding(
            "MEDIUM", "CLASSICAL", tgt, where,
            "Weak SSH MAC algorithms offered",
            f"Offered: {', '.join(weak_macs)}.",
            "Restrict MACs to hmac-sha2-256/512-etm@openssh.com.",
            deadline="NOW"))


# ----------------------------------------------------------------------------
# Scan driver
# ----------------------------------------------------------------------------
def scan_target(raw, cap, ports=None, timeout=6.0, quiet=False):
    host, inline_port = normalize_target(raw)
    if not host:
        return None

    result = {"target": host, "raw": raw, "resolved": None,
              "is_ip": is_ip(host), "services": {}, "findings": []}

    if not result["is_ip"]:
        try:
            result["resolved"] = socket.gethostbyname(host)
        except Exception as e:
            result["error"] = f"DNS resolution failed: {e}"
            if not quiet:
                print(f"{RED}[!] {host}: {result['error']}{RESET}")
            return result

    scan_ports = [inline_port] if inline_port else (ports or DEFAULT_PORTS)

    if not quiet:
        shown = result["resolved"] or host
        print(f"\n{BOLD}{CYAN}== {host}{RESET}{DIM}"
              f"{'  (' + shown + ')' if result['resolved'] else ''}"
              f"  ports: {','.join(map(str, scan_ports))}{RESET}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(port_open, host, p, timeout): p for p in scan_ports}
        open_ports = sorted(p for f, p in futs.items() if f.result())

    if not open_ports:
        result["error"] = "no scanned port is open"
        if not quiet:
            print(f"{DIM}    no open ports among {scan_ports}{RESET}")
        return result

    if not quiet:
        print(f"{DIM}    open: {', '.join(map(str, open_ports))}{RESET}")

    for port in open_ports:
        if port == 22:
            if not quiet:
                print(f"{DIM}    probing ssh/{port} ...{RESET}")
            info = ssh_probe(host, port, timeout)
            result["services"][str(port)] = {"protocol": "ssh", "ssh": info}
            if "error" not in info:
                classify_ssh(host, port, info, result["findings"])
            continue

        if not quiet:
            print(f"{DIM}    probing tls/{port} ...{RESET}")
        starttls = STARTTLS_PORTS.get(port)
        sni = None if is_ip(host) else host

        versions, certs, tls13 = [], [], False
        for label, ver in TLS_VERSIONS:
            status, info = tls_handshake(host, port, ver, sni, timeout, starttls)
            versions.append((label, status, info))
            if status == "ok":
                if label == "TLSv1.3":
                    tls13 = True
                if not certs and isinstance(info, dict) and info.get("chain"):
                    for der in info["chain"]:
                        try:
                            certs.append(analyse_cert(der))
                        except Exception:
                            pass

        if not any(s == "ok" for _, s, _ in versions):
            result["services"][str(port)] = {
                "protocol": "unknown",
                "note": "port open but no TLS handshake succeeded",
            }
            result["findings"].append(finding(
                "INFO", "N/A", host, f"{host}:{port}",
                "Open port with no TLS",
                "Port is open but did not complete a TLS handshake on any "
                "version. If it carries data, it may be plaintext -- which is "
                "the worst case for harvest-now-decrypt-later.",
                "Identify the service. Plaintext protocols need TLS before any "
                "PQ discussion is meaningful."))
            continue

        temp, group = server_temp_key(host, port, sni)
        pq = pq_kex_probe(host, port, sni, cap)

        # Backfill intermediates the Python handshake could not expose.
        ders = full_chain(host, port, sni, starttls)
        if len(ders) > len(certs):
            parsed = []
            for der in ders:
                try:
                    parsed.append(analyse_cert(der))
                except Exception:
                    pass
            if len(parsed) > len(certs):
                certs = parsed

        # hostname sanity, reported separately rather than aborting the scan
        mismatch = None
        if sni and certs:
            names = set(certs[0]["sans"])
            if names and sni not in names and not any(
                n.startswith("*.") and sni.endswith(n[1:]) for n in names
            ):
                mismatch = (f"Presented cert covers {sorted(names)[:5]}, "
                            f"which does not include '{sni}'.")

        svc = {
            "protocol": "tls" + (f"/starttls-{starttls}" if starttls else ""),
            "tls13": tls13,
            "temp_key": temp or group,
            "pq_kex": pq,
            "certs": certs,
            "hostname_mismatch": mismatch,
            "versions": [(l, s, (i if isinstance(i, str) else
                                 {"cipher": i.get("cipher"),
                                  "version": i.get("version")}))
                         for l, s, i in versions],
        }
        result["services"][str(port)] = svc
        classify_tls(host, port, {**svc, "versions": versions}, cap,
                     result["findings"])

    result["findings"].sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    return result


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
CLOCK_LABEL = {
    "HNDL": f"{RED}[HNDL]{RESET}",
    "QDAY": f"{YELLOW}[Q-DAY]{RESET}",
    "CLASSICAL": f"{MAGENTA}[BROKEN NOW]{RESET}",
    "N/A": f"{DIM}[--]{RESET}",
}


def render(results, cap, color=True):
    out = []

    def w(s=""):
        out.append(s if color else re.sub(r"\033\[[0-9;]*m", "", s))

    all_f = [f for r in results if r for f in r["findings"]]
    counts = {}
    for f in all_f:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    w()
    w(f"{BOLD}{'=' * 74}{RESET}")
    w(f"{BOLD}  POST-QUANTUM EXPOSURE REPORT{RESET}")
    w(f"{BOLD}{'=' * 74}{RESET}")
    w()
    summary = "  ".join(
        f"{SEV_COLOR[s]}{s}: {counts.get(s, 0)}{RESET}"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
        if counts.get(s)
    )
    w(f"  targets: {len([r for r in results if r])}    {summary or 'no findings'}")
    w()

    # --- P1: the harvest-now clock -----------------------------------------
    hndl = [f for f in all_f if f["clock"] == "HNDL"
            and f["severity"] in ("CRITICAL", "HIGH")]
    w(f"{RED}{BOLD}  P1 - HARVEST NOW, DECRYPT LATER  ({len(hndl)} findings){RESET}")
    w(f"{DIM}  Traffic recorded today is decrypted retroactively on Q-day.")
    w(f"  This clock is ALREADY RUNNING. Fix these first.{RESET}")
    w()
    if not hndl:
        w(f"{GREEN}    none - no confirmed classical-only key exchange.{RESET}")
    for f in hndl:
        w(f"    {SEV_COLOR[f['severity']]}{f['severity']:<8}{RESET} "
          f"{f['where']}  {f['title']}")
        w(f"{DIM}             -> {f['remediation']}{RESET}")
    w()

    # --- P2: already broken -------------------------------------------------
    classical = [f for f in all_f if f["clock"] == "CLASSICAL"
                 and f["severity"] in ("CRITICAL", "HIGH")]
    w(f"{MAGENTA}{BOLD}  P2 - ALREADY BROKEN (no quantum computer required)  "
      f"({len(classical)}){RESET}")
    w()
    if not classical:
        w(f"{GREEN}    none.{RESET}")
    for f in classical:
        w(f"    {SEV_COLOR[f['severity']]}{f['severity']:<8}{RESET} "
          f"{f['where']}  {f['title']}")
        w(f"{DIM}             -> {f['remediation']}{RESET}")
    w()

    # --- P3: Q-day, schedulable --------------------------------------------
    qday = [f for f in all_f if f["clock"] == "QDAY"]
    w(f"{YELLOW}{BOLD}  P3 - Q-DAY / SCHEDULABLE  ({len(qday)}){RESET}")
    w(f"{DIM}  Signatures and identity. Fails only when the machine exists;")
    w(f"  plan against certificate expiry, do not panic.{RESET}")
    w()
    if not qday:
        w(f"{GREEN}    none.{RESET}")
    for f in qday:
        dl = f" {DIM}({f['deadline']}){RESET}" if f["deadline"] else ""
        w(f"    {SEV_COLOR[f['severity']]}{f['severity']:<8}{RESET} "
          f"{f['where']}  {f['title']}{dl}")
    w()

    # --- undetermined -------------------------------------------------------
    unk = [f for f in all_f if f["severity"] == "UNKNOWN"]
    if unk:
        w(f"{MAGENTA}{BOLD}  UNDETERMINED - not tested, NOT a clean bill of health "
          f"({len(unk)}){RESET}")
        w()
        for f in unk:
            w(f"    {MAGENTA}?{RESET}        {f['where']}  {f['title']}")
            w(f"{DIM}             {f['detail']}{RESET}")
        w()

    # --- per-target detail --------------------------------------------------
    w(f"{BOLD}{'-' * 74}{RESET}")
    w(f"{BOLD}  DETAIL{RESET}")
    w(f"{BOLD}{'-' * 74}{RESET}")
    for r in results:
        if not r:
            continue
        w()
        w(f"{CYAN}{BOLD}  {r['target']}{RESET}"
          f"{DIM}{'  (' + r['resolved'] + ')' if r.get('resolved') else ''}{RESET}")
        if r.get("error"):
            w(f"    {RED}{r['error']}{RESET}")
            continue
        for port, svc in sorted(r["services"].items(), key=lambda x: int(x[0])):
            w(f"    {BOLD}port {port}{RESET} {DIM}({svc.get('protocol')}){RESET}")
            if svc.get("protocol") == "ssh":
                info = svc["ssh"]
                if "error" in info:
                    w(f"      {DIM}{info['error']}{RESET}")
                    continue
                w(f"      banner   : {info.get('banner', '')}")
                kex = info.get("kex", [])
                pqk = [k for k in kex if PQ_SSH_KEX.search(k)]
                mark = f"{GREEN}PQ{RESET}" if pqk else f"{RED}classical only{RESET}"
                w(f"      kex      : {mark}  {DIM}{', '.join(kex[:4])}{RESET}")
                w(f"      host key : {DIM}{', '.join(info.get('host_key', [])[:4])}{RESET}")
                continue
            if svc.get("note"):
                w(f"      {DIM}{svc['note']}{RESET}")
                continue
            for label, status, info in svc.get("versions", []):
                if status == "ok":
                    c = info.get("cipher") if isinstance(info, dict) else None
                    mark = f"{RED}yes{RESET}" if label in ("TLSv1.0", "TLSv1.1") \
                        else f"{GREEN}yes{RESET}"
                    w(f"      {label:<8}: {mark} {DIM}{c[0] if c else ''}{RESET}")
                elif status == "local":
                    w(f"      {label:<8}: {MAGENTA}UNDETERMINED{RESET} "
                      f"{DIM}(local limitation){RESET}")
                else:
                    w(f"      {label:<8}: {DIM}no{RESET}")
            w(f"      kex group: {svc.get('temp_key') or DIM + 'unknown' + RESET}")
            st, det = svc.get("pq_kex", ("UNDETERMINED", ""))
            col = {"SUPPORTED": GREEN, "NOT_SUPPORTED": RED}.get(st, MAGENTA)
            w(f"      PQ ready : {col}{st}{RESET} {DIM}{det}{RESET}")
            for i, c in enumerate(svc.get("certs", [])):
                role = "leaf" if i == 0 else f"ca[{i}]"
                kd = c["key_algorithm"] + (f"-{c['key_bits']}" if c["key_bits"] else "")
                flag = ""
                if c["not_after_year"] > DEPRECATED_AFTER:
                    flag = f" {RED}<- outlives {DEPRECATED_AFTER}{RESET}"
                w(f"      {role:<9}: {kd} / {c['signature_algorithm']} "
                  f"{DIM}exp {c['not_after'][:10]}{RESET}{flag}")

    # --- timeline -----------------------------------------------------------
    w()
    w(f"{BOLD}{'-' * 74}{RESET}")
    w(f"{BOLD}  MIGRATION TIMELINE{RESET}")
    w(f"{BOLD}{'-' * 74}{RESET}")
    w()
    w(f"  {RED}{BOLD}NOW{RESET}         Enable hybrid PQ key exchange everywhere "
      f"({len(hndl)} endpoints).")
    w(f"              {DIM}X25519MLKEM768 for TLS 1.3, "
      f"sntrup761x25519 / mlkem768x25519 for SSH.")
    w(f"              Hybrid is backwards compatible -- deploy it before you "
      f"finish{RESET}")
    w(f"              {DIM}the inventory. Also fix the {len(classical)} "
      f"already-broken items.{RESET}")
    w()
    w(f"  {YELLOW}{BOLD}2026-2028{RESET}   Inventory every certificate and its "
      f"lifetime. Shorten cert")
    w(f"              {DIM}lifetimes so the eventual algorithm swap is routine. "
      f"Ask your")
    w(f"              CA for its ML-DSA (FIPS 204) roadmap.{RESET}")
    w()
    w(f"  {YELLOW}{BOLD}by {DEPRECATED_AFTER}{RESET}     "
      f"RSA / ECDSA / ECDH DEPRECATED (NIST IR 8547 draft).")
    certs_past = sum(
        1 for r in results if r for s in r["services"].values()
        for c in s.get("certs", []) if c["not_after_year"] > DEPRECATED_AFTER)
    w(f"              {DIM}{certs_past} scanned certificate(s) are valid past "
      f"this date.{RESET}")
    w()
    w(f"  {MAGENTA}{BOLD}by {DISALLOWED_AFTER}{RESET}     "
      f"RSA / ECDSA / ECDH DISALLOWED, legacy systems included.")
    w(f"              {DIM}Pure-classical signatures must be gone. Hybrid modes "
      f"survive.{RESET}")
    w()
    w(f"{DIM}  {TIMELINE_NOTE}{RESET}")
    w()
    w(f"{BOLD}{'-' * 74}{RESET}")
    w(f"{DIM}  scanner capability at run time:{RESET}")
    for line in cap.report().split("\n"):
        w("  " + line)
    w()
    return "\n".join(out)


# ----------------------------------------------------------------------------
# Self test -- the only way to trust an output
# ----------------------------------------------------------------------------
def self_test(cap):
    print(f"{BOLD}Self-test: can this scanner actually discriminate?{RESET}\n")
    print(cap.report())
    print()

    ok = True

    print(f"{BOLD}[1] SSH post-quantum discrimination{RESET}")
    pos = ssh_probe("github.com", 22, 8)
    if "error" in pos:
        print(f"    {MAGENTA}SKIP{RESET} github.com:22 unreachable ({pos['error']})")
    else:
        has = any(PQ_SSH_KEX.search(k) for k in pos.get("kex", []))
        print(f"    github.com:22 PQ kex detected: "
              f"{GREEN + 'YES' + RESET if has else RED + 'NO' + RESET}")
        if not has:
            print(f"    {RED}FAIL{RESET} expected a PQ kex on a modern OpenSSH.")
            ok = False
        else:
            print(f"    {GREEN}PASS{RESET} true positive on a known PQ-capable host.")

    print(f"\n{BOLD}[2] TLS post-quantum probing{RESET}")
    st, detail = pq_kex_probe("cloudflare.com", 443, "cloudflare.com", cap)
    print(f"    cloudflare.com:443 -> {st} ({detail})")
    if not cap.can_test_pq_kex:
        if st == "UNDETERMINED":
            print(f"    {GREEN}PASS{RESET} correctly reports UNDETERMINED rather "
                  f"than a false 'not supported'.")
            print(f"    {DIM}Cloudflare DOES support hybrid PQ. A scanner that "
                  f"printed 'not supported'\n         here would be measuring "
                  f"its own OpenSSL, not the server.{RESET}")
        else:
            print(f"    {RED}FAIL{RESET} claimed a verdict it cannot support.")
            ok = False
    else:
        if st == "SUPPORTED":
            print(f"    {GREEN}PASS{RESET} true positive against a known PQ host.")
        else:
            print(f"    {RED}FAIL{RESET} expected SUPPORTED from Cloudflare.")
            ok = False

    # Positive and negative controls. github.com refuses TLS 1.0; badssl.com's
    # tls-v1-0 endpoint refuses TLS 1.3. If we report the same answer for both,
    # we are reading our own stack instead of the server.
    print(f"\n{BOLD}[3] Legacy TLS discrimination (positive + negative control){RESET}")
    controls = [
        ("github.com", 443, "TLSv1.0", ssl.TLSVersion.TLSv1, "refused"),
        ("badssl.com", 443, "TLSv1.0", ssl.TLSVersion.TLSv1, "ok"),
        ("github.com", 443, "TLSv1.3", ssl.TLSVersion.TLSv1_3, "ok"),
        ("badssl.com", 443, "TLSv1.3", ssl.TLSVersion.TLSv1_3, "refused"),
    ]
    seen = []
    for host, port, label, ver, expect in controls:
        status, _ = tls_handshake(host, port, ver, host, 8)
        seen.append(status)
        if status == "local":
            print(f"    {MAGENTA}SKIP{RESET} {host} {label}: local stack cannot "
                  f"offer it (reported UNDETERMINED, not 'unsupported')")
            continue
        if status == "error":
            print(f"    {MAGENTA}SKIP{RESET} {host} {label}: unreachable")
            continue
        good = status == expect
        print(f"    {host:<14} {label:<8} -> {status:<8} "
              f"(expected {expect})  "
              f"{GREEN + 'PASS' + RESET if good else RED + 'FAIL' + RESET}")
        if not good:
            ok = False

    real = [s for s in seen if s in ("ok", "refused")]
    if real and len(set(real)) == 1:
        print(f"    {RED}FAIL{RESET} every control returned '{real[0]}' -- the "
              f"scanner is reporting its own\n         stack, not the servers.")
        ok = False
    elif real:
        print(f"    {GREEN}PASS{RESET} controls diverge, so the probe genuinely "
              f"reads the remote server.")

    # End-to-end guard on the core invariant. The probe returning UNDETERMINED
    # is not enough -- the CLASSIFIER must also refuse to emit a PQ verdict.
    # cloudflare.com genuinely supports hybrid PQ, so any P1 HNDL finding
    # against it on a box that cannot offer ML-KEM is a false positive.
    print(f"\n{BOLD}[4] Classifier does not invent PQ verdicts (end-to-end){RESET}")
    r = scan_target("cloudflare.com", cap, [443], 8.0, quiet=True)
    if not r or r.get("error"):
        print(f"    {MAGENTA}SKIP{RESET} cloudflare.com unreachable")
    else:
        bad = [f for f in r["findings"] if f["clock"] == "HNDL"
               and f["severity"] in ("CRITICAL", "HIGH")]
        undet = [f for f in r["findings"] if f["severity"] == "UNKNOWN"]
        if not cap.can_test_pq_kex:
            if bad:
                print(f"    {RED}FAIL{RESET} emitted {len(bad)} P1 HNDL finding(s) "
                      f"against a known PQ-capable host:")
                for f in bad:
                    print(f"           - {f['title']}")
                ok = False
            else:
                print(f"    {GREEN}PASS{RESET} no P1 HNDL findings invented; "
                      f"{len(undet)} correctly bucketed UNDETERMINED.")
        else:
            print(f"    {DIM}local stack can offer PQ groups; verdicts are "
                  f"authoritative here ({len(bad)} P1 HNDL).{RESET}")

        chain = r["services"].get("443", {}).get("certs", [])
        print(f"    chain depth collected: {len(chain)} cert(s) "
              f"{DIM}({', '.join(c['key_algorithm'] for c in chain)}){RESET}")
        if len(chain) < 2:
            print(f"    {MAGENTA}WARN{RESET} only the leaf was collected -- "
                  f"intermediate CA keys are missing from the inventory.")

    print(f"\n{BOLD}{'PASS' if ok else 'FAIL'}{RESET} overall\n")
    return 0 if ok else 1


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        prog="codequantum",
        description="Post-quantum compatibility scanner for hosts, IPs and websites.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  codequantum example.com
  codequantum 192.168.1.10 --ports 443,22,8443
  codequantum -f targets.txt --json report.json
  codequantum --self-test
""")
    ap.add_argument("targets", nargs="*", help="hostname, IP, URL or host:port")
    ap.add_argument("-f", "--file", help="file with one target per line")
    ap.add_argument("-p", "--ports", help="comma separated ports "
                    f"(default: {','.join(map(str, DEFAULT_PORTS))})")
    ap.add_argument("-t", "--timeout", type=float, default=6.0,
                    help="per-connection timeout in seconds (default 6)")
    ap.add_argument("-j", "--json", metavar="FILE", help="write JSON report")
    ap.add_argument("-o", "--output", metavar="FILE", help="write text report")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress progress")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--self-test", action="store_true",
                    help="verify the scanner can actually discriminate")
    args = ap.parse_args()

    if args.no_color:
        for k in ("YELLOW GREEN CYAN RED MAGENTA BLUE BOLD DIM RESET").split():
            globals()[k] = ""
        for k in SEV_COLOR:
            SEV_COLOR[k] = ""
        for k in CLOCK_LABEL:
            CLOCK_LABEL[k] = f"[{k}]"

    if not args.no_banner and not args.quiet:
        print_banner(color=not args.no_color)

    cap = LocalCapability()

    if args.self_test:
        sys.exit(self_test(cap))

    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file) as fh:
                targets += [l.strip() for l in fh if l.strip()
                            and not l.startswith("#")]
        except OSError as e:
            sys.exit(f"{RED}cannot read {args.file}: {e}{RESET}")

    if not targets:
        ap.print_help()
        sys.exit(1)

    ports = None
    if args.ports:
        try:
            ports = [int(p) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            sys.exit(f"{RED}--ports must be a comma separated list of numbers{RESET}")

    if not args.quiet:
        print(cap.report())

    results = []
    try:
        for t in targets:
            results.append(scan_target(t, cap, ports, args.timeout, args.quiet))
    except KeyboardInterrupt:
        print(f"\n{YELLOW}interrupted - reporting partial results{RESET}")

    text = render(results, cap, color=not args.no_color)
    print(text)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(re.sub(r"\033\[[0-9;]*m", "", text))
            print(f"{GREEN}[+] text report -> {args.output}{RESET}")
        except OSError as e:
            print(f"{RED}[!] cannot write {args.output}: {e}{RESET}")

    if args.json:
        payload = {
            "scanner": "codequantum",
            "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scanner_capability": {
                "openssl": cap.openssl_version,
                "pq_groups_offerable": cap.pq_groups,
                "can_test_pq_kex": cap.can_test_pq_kex,
                "legacy_tls_offerable": cap.legacy_tls,
            },
            "timeline_reference": {
                "source": "NIST IR 8547 (initial public draft)",
                "deprecated_after": DEPRECATED_AFTER,
                "disallowed_after": DISALLOWED_AFTER,
            },
            "results": [r for r in results if r],
        }
        try:
            with open(args.json, "w") as fh:
                json.dump(payload, fh, indent=2, default=str)
            print(f"{GREEN}[+] json report -> {args.json}{RESET}")
        except OSError as e:
            print(f"{RED}[!] cannot write {args.json}: {e}{RESET}")

    worst = min((SEV_ORDER.get(f["severity"], 9)
                 for r in results if r for f in r["findings"]), default=9)
    sys.exit(2 if worst == 0 else (1 if worst == 1 else 0))


if __name__ == "__main__":
    main()
