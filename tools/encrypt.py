#!/usr/bin/env python3
"""Password-protect a worksheet HTML file for GitHub Pages.

Encrypts the whole page with AES-256-GCM using a key derived from a
passphrase (PBKDF2-HMAC-SHA256). The output is a small HTML page that asks
for the password and decrypts in the browser with WebCrypto. The passphrase
is never written anywhere; only the ciphertext, salt and IV are published.

Usage:
    python3 tools/encrypt.py src/school_for_woodland_creatures.html woodland.html

You are prompted for the passphrase twice (input is hidden).
For automated tests only: --password-stdin reads one line from stdin.
"""
import argparse
import base64
import getpass
import html
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>__TITLE__</title>
<style>
  :root { --bg:#f6f3ea; --card:#fff; --ink:#2b2b2b; --muted:#6b6b6b; --accent:#2f6b3a; --err:#a23b2a; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#1d1f1c; --card:#2a2d29; --ink:#ececec; --muted:#a9a9a9; --accent:#7fc28c; --err:#ef8a78; }
  }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; padding:16px;
         background:var(--bg); color:var(--ink); font:17px/1.5 system-ui, sans-serif; }
  form { background:var(--card); padding:28px; border-radius:14px; width:100%; max-width:380px;
         box-shadow:0 4px 18px rgba(0,0,0,.12); }
  h1 { font-size:1.3rem; margin:0 0 6px; }
  p { margin:0 0 18px; color:var(--muted); }
  input, button { width:100%; font:inherit; padding:12px; border-radius:8px; }
  input { border:1px solid var(--muted); background:transparent; color:var(--ink); margin-bottom:12px; }
  button { border:0; background:var(--accent); color:#fff; font-weight:600; cursor:pointer; }
  button:disabled { opacity:.6; cursor:wait; }
  #msg { color:var(--err); min-height:1.5em; margin:10px 0 0; }
</style>
</head>
<body>
<form id="f">
  <h1>__TITLE__</h1>
  <p>Enter the password your parent gave you.</p>
  <input id="pw" type="password" autocomplete="current-password" aria-label="Password" required autofocus>
  <button id="go" type="submit">Open worksheet</button>
  <div id="msg" role="alert"></div>
</form>
<script>
const DATA = { salt: "__SALT__", iv: "__IV__", ct: "__CT__", iter: __ITER__ };
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
document.getElementById('f').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = document.getElementById('go'), msg = document.getElementById('msg');
  if (!window.crypto || !crypto.subtle) { msg.textContent = 'This browser cannot open the worksheet. Try Chrome, Edge, Firefox or Safari.'; return; }
  btn.disabled = true; msg.textContent = '';
  try {
    const pw = new TextEncoder().encode(document.getElementById('pw').value);
    const base = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64(DATA.salt), iterations: DATA.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(DATA.iv) }, key, b64(DATA.ct));
    const page = new TextDecoder().decode(plain);
    document.open(); document.write(page); document.close();
  } catch (err) {
    msg.textContent = 'That password did not work. Please try again.';
    btn.disabled = false;
  }
});
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("output")
    ap.add_argument("--password-stdin", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    with open(args.source, "rb") as fh:
        plaintext = fh.read()
    m = re.search(rb"<title>(.*?)</title>", plaintext, re.S)
    title = html.escape(m.group(1).decode("utf-8").strip()) if m else "Worksheet"

    if args.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("Passphrase: ")
        if pw != getpass.getpass("Repeat passphrase: "):
            sys.exit("Passphrases do not match. Nothing written.")
    if len(pw) < 8:
        sys.exit("Use at least 8 characters. Nothing written.")

    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(pw.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    del pw, key

    enc = lambda b: base64.b64encode(b).decode("ascii")
    out = (TEMPLATE.replace("__TITLE__", title)
           .replace("__SALT__", enc(salt)).replace("__IV__", enc(iv))
           .replace("__ITER__", str(ITERATIONS)).replace("__CT__", enc(ct)))
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"Wrote {args.output} ({len(out):,} bytes).")


if __name__ == "__main__":
    main()
