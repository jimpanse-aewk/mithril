#!/usr/bin/env python3
"""Regenerate the leaked/default public-key corpus from the vendored public keys.

Reads data/keycorpus/ (PUBLIC keys only — never private keys) and emits
src/keycorpus_corpus.inc: the compiled-in table keycorpus.cpp matches against.
The corpus is baked into the binary (mithril makes no network call and reads no
external table at scan time); this generator runs only at authoring time to keep
the table reproducible and auditable from source.

Pure standard library (hashlib + a base64/SSH-wire walk); needs no openssl.

Sources (all public):
  ssh-badkeys/{host,authorized}/*.pub  rapid7/ssh-badkeys (MIT) — hardcoded SSH
                         host/authorized keys shipped in appliances and firmware.
                         The repo ships the .pub (public) halves; the matching
                         private keys are public in the same repo.
  vagrant/vagrant.pub    HashiCorp Vagrant insecure key (private key published
                         in the vagrant repo); shipped as an authorized key on
                         countless dev boxes and some appliances.
  emudhra/*.crt          Real public CT-logged eMudhra intermediate CA certs whose
                         P-384 keys were generated with a broken RNG (tiny private
                         scalars 4..237, recoverable); the Oct 2026 CA compromise.
                         Fingerprinted by fp_der (SHA-256[0:32] of the cert DER).

Two fingerprints per key (see keycorpus.hpp):
  fp_ssh   SHA-256[0:32] of the raw OpenSSH public-key blob (exact-key match).
  fp_modn  SHA-256[0:32] of the RSA modulus, big-endian, leading zeros stripped
           (cross-container: the same key seen as a cert/SPKI still matches).

Usage: python3 tools/gen_keycorpus.py           # writes src/keycorpus_corpus.inc
       python3 tools/gen_keycorpus.py --check    # verify the .inc is up to date
"""
import base64
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data", "keycorpus")
OUT = os.path.join(ROOT, "src", "keycorpus_corpus.inc")

FP_LEN = 32  # first 32 lowercase hex chars of SHA-256 (matches keycorpus.cpp)


def fp(data):
    return hashlib.sha256(data).hexdigest()[:FP_LEN]


def ssh_fields(blob):
    """Yield each length-prefixed field of an SSH wire blob."""
    i = 0
    while i + 4 <= len(blob):
        n = int.from_bytes(blob[i:i + 4], "big")
        i += 4
        if i + n > len(blob):
            break
        yield blob[i:i + n]
        i += n


def parse_pub(text):
    """(blob, algo, modulus_be) from an OpenSSH public-key line; modulus for RSA."""
    parts = text.split()
    if len(parts) < 2 or not parts[1]:
        return None
    try:
        blob = base64.b64decode(parts[1])
    except Exception:
        return None
    fields = list(ssh_fields(blob))
    if not fields:
        return None
    algo = fields[0].decode("latin1", "replace")
    modn = None
    if algo == "ssh-rsa" and len(fields) >= 3:
        modn = fields[2].lstrip(b"\x00")  # mpint n, strip DER/mpint sign padding
    return blob, algo, modn


def pretty(name):
    return name.replace("_", " ").replace("-", " ").strip()


def yml_meta(path):
    """(cve, user) pulled from the sibling .yml (tiny hand parse, no yaml dep)."""
    cve = user = ""
    if os.path.exists(path):
        txt = open(path, encoding="latin1").read()
        m = re.search(r":cve:\s*([0-9-]+)", txt)
        if m:
            cve = "CVE-" + m.group(1)
        m = re.search(r":user:\s*(\S+)", txt)
        if m:
            user = m.group(1)
    return cve, user


def collect():
    entries = []  # (fp, label, ref, key_use)
    seen = set()

    def add(f, label, ref, use):
        if f and f not in seen:
            seen.add(f)
            entries.append((f, label, ref, use))

    # rapid7/ssh-badkeys
    sb = os.path.join(DATA, "ssh-badkeys")
    for sub, use, kind in (("host", "host", "SSH host key"),
                           ("authorized", "authorized", "authorized SSH key")):
        d = os.path.join(sb, sub)
        for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if not name.endswith(".pub"):
                continue
            base = name[:-4]
            p = parse_pub(open(os.path.join(d, name), encoding="latin1").read())
            if not p:
                continue
            blob, algo, modn = p
            alg = {"ssh-rsa": "RSA", "ssh-dss": "DSA"}.get(algo, algo)
            cve, user = yml_meta(os.path.join(d, base + ".yml"))
            label = "%s hardcoded %s (%s)" % (pretty(base), kind, alg)
            ref = "rapid7/ssh-badkeys" + (("; " + cve) if cve else "")
            add(fp(blob), label, ref, use)
            if modn:
                add(fp(modn), label + " [modulus]", ref, use)

    # eMudhra intermediate CAs with compromised keys (October 2026). These P-384
    # certificates were generated with a broken RNG that produced tiny private
    # scalars (4..237), so the private key is trivially recoverable from the public
    # cert. The vendored .crt files are the real, public CT-logged certificates
    # (SHA-256 fingerprints verified against Mozilla bug 2083449). Fingerprinted by
    # fp_der (SHA-256[0:32] of the cert DER) so an exact match on a bundled trust
    # store is named here; the general ec-small-scalar check catches the key in any
    # cert wrapper (e.g. the Sectigo cross-signs) independently.
    EMUDHRA_CN = {
        "EMEVTLSCAG3B": "EM EV TLS CA - G3B", "EMOVTLSCAG3B": "EM OV TLS CA - G3B",
        "EMDVTLSCAG3B": "EM DV TLS CA - G3B", "EMEVTLSCAG3C": "EM EV TLS CA - G3C",
        "EMOVTLSCAG3C": "EM OV TLS CA - G3C", "EMDVTLSCAG3C": "EM DV TLS CA - G3C",
        "EMOVCSCAG3B": "EM OV CS CA - G3B", "EMOVCSCAG3C": "EM OV CS CA - G3C",
    }
    ed = os.path.join(DATA, "emudhra")
    for name in sorted(os.listdir(ed)) if os.path.isdir(ed) else []:
        if not name.endswith(".crt"):
            continue
        der = open(os.path.join(ed, name), "rb").read()
        cn = EMUDHRA_CN.get(name[:-4], name[:-4])
        label = "eMudhra %s intermediate (compromised; recoverable P-384 key)" % cn
        add(fp(der), label, "Oct 2026 eMudhra CA compromise; Mozilla bug 2083449", "")

    # Vagrant insecure key (authorized)
    vd = os.path.join(DATA, "vagrant")
    for name in sorted(os.listdir(vd)) if os.path.isdir(vd) else []:
        if not name.endswith(".pub"):
            continue
        p = parse_pub(open(os.path.join(vd, name), encoding="latin1").read())
        if not p:
            continue
        blob, algo, modn = p
        label = "Vagrant insecure key (default authorized key)"
        ref = "hashicorp/vagrant keys/vagrant (private key published in-repo)"
        add(fp(blob), label, ref, "authorized")
        if modn:
            add(fp(modn), label + " [modulus]", ref, "authorized")

    entries.sort(key=lambda e: (e[3], e[1], e[0]))
    return entries


def emit(entries):
    def esc(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')
    o = "// GENERATED by tools/gen_keycorpus.py from data/keycorpus/ — do not edit by hand.\n"
    o += "// Compiled-in corpus of public keys whose private half is public.\n"
    o += "// Regenerate after changing the vendored sources.\n\n"
    o += "inline constexpr KnownLeakedKey kLeakedKeys[] = {\n"
    for f, label, ref, use in entries:
        o += '    {"%s", "%s", "%s", "%s"},\n' % (f, esc(label), esc(ref), use)
    o += "};\n"
    return o


def main():
    entries = collect()
    text = emit(entries)
    if "--check" in sys.argv:
        cur = open(OUT).read() if os.path.exists(OUT) else ""
        if cur != text:
            print("keycorpus_corpus.inc is STALE; run tools/gen_keycorpus.py", file=sys.stderr)
            return 1
        print("keycorpus_corpus.inc is up to date (%d entries)" % len(entries))
        return 0
    with open(OUT, "w") as f:
        f.write(text)
    print("wrote %s (%d entries)" % (OUT, len(entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
