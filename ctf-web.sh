#!/usr/bin/env bash
#
# ctf-web — zero-AI first-pass recon for a WEB CTF challenge.
#
#   Runs the commands you'd type anyway against a target URL — headers,
#   whatweb fingerprint, sensitive-file probes, ffuf dir fuzz, arjun param
#   discovery, nuclei quick scan, katana crawl — hunts for flags, and writes
#   a readable REPORT.md plus raw tool output under <host>.web/.
#
# USAGE
#   ctf-web http://target:1337/
#   ctf-web https://chall.ctf.io/   "login page, maybe sqli"
#
# ENV
#   FLAG_RE   flag regex             (default: [A-Za-z0-9_]{2,}\{[^}]+\})
#   WL        ffuf wordlist          (default: seclists raft-small-words)
#   DEEP=1    bigger wordlist + full nuclei templates (slower)
#   AI=1      after recon, hand URL + report to claude (ctf-solve style)
#
set -uo pipefail   # NOT -e: a failing tool must not abort the whole pass

URL="${1:-}"; [[ -n "$URL" ]] || { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
shift || true
HINT="${*:-}"
[[ "$URL" =~ ^https?:// ]] || URL="http://$URL"
BASE="${URL%/}"
HOST="$(sed -E 's#^https?://##; s#[/:].*##' <<<"$URL")"

FLAG_RE="${FLAG_RE:-[A-Za-z0-9_]{2,}\{[^}]+\}}"
export PATH="$PATH:$HOME/go/bin"
SL=/usr/share/seclists
WL="${WL:-$SL/Discovery/Web-Content/raft-small-words.txt}"
[[ "${DEEP:-0}" == 1 ]] && WL="$SL/Discovery/Web-Content/raft-medium-words.txt"
[[ -f "$WL" ]] || WL=/usr/share/wordlists/dirb/common.txt

OUT="$PWD/$HOST.web"; mkdir -p "$OUT/raw"
R="$OUT/REPORT.md"; : >"$R"
log(){ echo "$@" | tee -a "$R"; }
sec(){ printf '\n## %s\n\n' "$*" >>"$R"; echo; echo "[*] $*"; }

log "# Web recon — $URL"
log ""
log "- target: \`$URL\`   host: \`$HOST\`   started: $(date -Is)"
[[ -n "$HINT" ]] && log "- hint: $HINT"

have(){ command -v "$1" >/dev/null 2>&1; }

sec "Headers & redirects"
curl -sSikL --max-time 20 "$URL" 2>&1 | sed -n '1,40p' | tee "$OUT/raw/headers.txt" | sed 's/^/    /' >>"$R"

sec "Fingerprint (whatweb)"
have whatweb && whatweb -a3 "$URL" 2>&1 | tee "$OUT/raw/whatweb.txt" | sed 's/^/    /' >>"$R"

sec "Sensitive files"
for p in robots.txt sitemap.xml .git/HEAD .env .DS_Store flag flag.txt \
         backup.zip config.php .htaccess package.json composer.json \
         server-status phpinfo.php admin login .well-known/security.txt; do
  code=$(curl -so /dev/null -w '%{http_code}' --max-time 10 "$BASE/$p")
  [[ "$code" =~ ^(200|301|302|403)$ ]] && log "    [$code] $BASE/$p"
  [[ "$code" == 403 ]] && echo "$BASE/$p" >>"$OUT/raw/403.txt"
done
# if .git is exposed, that's usually the whole challenge
if curl -so /dev/null -w '%{http_code}' "$BASE/.git/HEAD" | grep -q 200; then
  log "    [!] .git exposed — dump with: git-dumper $BASE/.git/ $OUT/gitdump"
fi

sec "Directory fuzz (ffuf — $WL)"
if have ffuf; then
  ffuf -u "$BASE/FUZZ" -w "$WL" -mc 200,204,301,302,307,401,403 \
       -t 60 -timeout 10 -s -o "$OUT/raw/ffuf.json" -of json 2>/dev/null
  grep -oE '"url":"[^"]+"' "$OUT/raw/ffuf.json" 2>/dev/null | cut -d'"' -f4 | sort -u | sed 's/^/    /' | tee -a "$R" | head -60
  # collect ffuf 403s for bypass pass
  grep -oE '\{"input":[^}]*"status":403[^}]*\}|"status": *403' "$OUT/raw/ffuf.json" >/dev/null 2>&1 && \
    jq -r '.results[] | select(.status==403) | .url' "$OUT/raw/ffuf.json" 2>/dev/null >>"$OUT/raw/403.txt"
fi

sec "403 bypass (nomore403)"
if have nomore403 && [[ -s "$OUT/raw/403.txt" ]]; then
  sort -u "$OUT/raw/403.txt" | head -5 | while read -r u; do
    log "    -> $u"
    nomore403 -u "$u" 2>/dev/null | grep -iE '20[0-9]|bypass' | sed 's/^/      /' | tee -a "$R"
  done
else
  log "    (no 403s to bypass)"
fi

sec "Request smuggling (smuggler)"
if have smuggler; then
  smuggler -u "$URL" -q 2>/dev/null | tee "$OUT/raw/smuggler.txt" | grep -iE 'potential|vulnerable|CL\.TE|TE\.CL|\[+\]' | sed 's/^/    /' >>"$R"
  [[ -s "$OUT/raw/smuggler.txt" ]] || log "    (smuggler produced no output)"
else
  log "    (smuggler not installed)"
fi

sec "Parameter discovery (arjun)"
have arjun && arjun -u "$URL" -oT "$OUT/raw/arjun.txt" 2>&1 | grep -iE 'parameter|found|heuristic' | sed 's/^/    /' >>"$R"

sec "nuclei quick scan"
if have nuclei; then
  NARGS=(-u "$URL" -silent -nc -o "$OUT/raw/nuclei.txt")
  [[ "${DEEP:-0}" == 1 ]] || NARGS+=(-t http/exposures -t http/misconfiguration -t http/default-logins -t http/cves)
  nuclei "${NARGS[@]}" 2>/dev/null
  [[ -s "$OUT/raw/nuclei.txt" ]] && sed 's/^/    /' "$OUT/raw/nuclei.txt" >>"$R" || log "    (no nuclei hits)"
fi

sec "Crawl (katana)"
have katana && katana -u "$URL" -silent -jc -d 2 -o "$OUT/raw/katana.txt" 2>/dev/null && \
  { sort -u "$OUT/raw/katana.txt" 2>/dev/null | head -80 | sed 's/^/    /' >>"$R"; }

sec "FLAG CANDIDATES"
HITS="$(grep -rohoE "$FLAG_RE" "$OUT/raw" 2>/dev/null | sort -u)"
if [[ -n "$HITS" ]]; then log "    $HITS"; else log "    (none in recon output — dig deeper)"; fi

echo
echo "[*] Report: $R"

# ---- optional AI hand-off --------------------------------------------------
if [[ "${AI:-0}" == 1 ]]; then
  echo "[*] Handing to Claude…"
  PROMPT="Authorized web CTF challenge. Target: $URL
Recon report is below. Work autonomously: enumerate, find the vuln (sqli/xss/
ssti/idor/lfi/auth-bypass/deserialization/etc.), exploit it, recover the flag.
You have network access and the full Parrot toolset (sqlmap, ffuf, curl,
python+requests, nuclei, burp is NOT scriptable so use CLI tools). Put exploit
scripts in ./solution/ and write WRITEUP.md with the flag. Flag regex: $FLAG_RE
Hint: ${HINT:-none}

== RECON REPORT ==
$(cat "$R")
"
  cd "$OUT"; mkdir -p solution
  printf '%s' "$PROMPT" | claude -p --dangerously-skip-permissions --add-dir "$OUT"
fi
