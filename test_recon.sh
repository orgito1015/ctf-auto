#!/usr/bin/env bash
# Minimal self-check for the no-AI additions in ctf-recon.sh.
# Crypto + flag-hunt always run; archive cracking only if the tools exist.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
OUT="$T/out"

# --- fixtures: an RSA public key, a known hash, and a flag ------------------
openssl genrsa 2048 2>/dev/null | openssl rsa -pubout -out "$T/key.pub" 2>/dev/null
# md5("abc"), and a flag for the hunter to find
printf '900150983cd24fb0d6963f7d28e17f72\nCTF{self_test}\n' > "$T/notes.txt"

OUT="$OUT" QUIET=1 ./ctf-recon.sh "$T/key.pub" "$T/notes.txt" >/dev/null

grep -q 'RSA public params' "$OUT"/*/crypto.txt 2>/dev/null \
  || { echo "FAIL: RSA public key not triaged"; exit 1; }
grep -q 'hash candidates' "$OUT"/*/crypto.txt 2>/dev/null \
  || { echo "FAIL: hash candidate not detected"; exit 1; }
grep -q 'CTF{self_test}' "$OUT/FLAGS.txt" \
  || { echo "FAIL: flag not hunted"; exit 1; }
echo "ok: crypto triage + flag hunt"

# --- archive cracking (skips cleanly if zip/zip2john/john/rockyou missing) --
WL=/usr/share/wordlists/rockyou.txt
if command -v zip >/dev/null && command -v zip2john >/dev/null \
   && command -v john >/dev/null && [[ -f "$WL" ]] && grep -qx password "$WL"; then
  echo secret > "$T/flag.txt"
  ( cd "$T" && zip -q -P password locked.zip flag.txt )
  rm -rf "$OUT"
  OUT="$OUT" QUIET=1 CRACK_TIMEOUT=60 ./ctf-recon.sh -x "$T/locked.zip" >/dev/null
  grep -q 'archive password: password' "$OUT/FLAGS.txt" \
    || { echo "FAIL: did not crack zip password"; exit 1; }
  echo "ok: archive cracking"
else
  echo "skip: archive cracking (zip/zip2john/john/rockyou not all present)"
fi

echo "PASS"
