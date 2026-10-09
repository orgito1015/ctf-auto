#!/usr/bin/env bash
#
# ctf-recon — zero-AI first-pass recon for CTF challenges.
#
#   Runs the commands you'd type anyway (file, strings, grep, binwalk, checksec,
#   exiftool, zsteg, zbarimg, capinfos, …) against a file or a whole folder,
#   hunts for flags, and writes a readable REPORT.md plus the raw tool output.
#
# USAGE
#   ctf-recon [options] <file | folder> [more targets ...]
#
# EXAMPLES
#   ctf-recon ./chall                 # walk every file in a folder
#   ctf-recon secret.png              # one file
#   ctf-recon -x drop.zip             # extract archives/binwalk and recon inside
#   FLAG_RE='HTB\{[^}]+\}' ctf-recon dump.bin     # pin the flag format
#   DEEP=1 ctf-recon maybe_stego.jpg  # heavier passes
#
# OPTIONS
#   -x, --extract     recursively unpack archives + binwalk output and recon them
#   -h, --help        show this help and exit
#
# ENV
#   FLAG_RE    flag regex              (default: any  prefix{...}  form)
#   OUT        output dir              (default: <firsttarget>.recon in CWD)
#   DEEP=1     heavier passes          (objdump -d, foremost carving, steghide empty-pw extract)
#   MAXFILES   cap files inspected     (default 500; stops runaway on huge trees)
#   QUIET=1    less console chatter
#
# OUTPUT  (all under $OUT)
#   REPORT.md     summary: flag candidates, checksec table, per-file detail
#   FLAGS.txt     deduped flag candidates
#   <file>/...    raw output of every tool, per file
#
# WHAT IT RUNS PER FILE (by detected type)
#   any      strings (ascii+utf16le), hex header, md5/sha1, binwalk, base64-decode
#   ELF      readelf, nm, checksec, hot imports (system//bin/sh/gets/strcpy…)
#   image    exiftool, pngcheck, zsteg -a, steghide info, zbarimg (QR), binwalk -e
#   audio    exiftool, spectrogram reminder
#   pcap     capinfos, protocol hierarchy, tcp conversations, http-object hint
#   archive  content listing (+ unpack if -x), zip2john/rar2john hint
#   text     secret grep (password/token/api key/private key/hashes)
#   pdf      exiftool + strings/binwalk
#
set -uo pipefail   # NOT -e: recon tools routinely exit nonzero, that's fine.

# ------------------------------------------------------------- arg parse ----
EXTRACT=0
declare -a ARGS=()
show_help(){ grep '^#' "$0" | sed '1d; s/^#\( \|$\)//'; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    show_help; exit 0 ;;
    -x|--extract) EXTRACT=1 ;;
    --)           shift; while [[ $# -gt 0 ]]; do ARGS+=("$1"); shift; done; break ;;
    -*)           echo "unknown option: $1" >&2; echo "try: ctf-recon --help" >&2; exit 2 ;;
    *)            ARGS+=("$1") ;;
  esac
  shift
done
[[ ${#ARGS[@]} -ge 1 ]] || { show_help; exit 1; }

# ------------------------------------------------------------- config -------
FLAG_RE="${FLAG_RE:-}"
[[ -z "$FLAG_RE" ]] && FLAG_RE='[A-Za-z0-9_]{1,24}\{[^}]{1,256}\}'   # set here, not in ${:-}, to survive the '}'
DEEP="${DEEP:-0}"; QUIET="${QUIET:-0}"; MAXFILES="${MAXFILES:-500}"

first="$(readlink -f "${ARGS[0]}")"
OUT="${OUT:-$PWD/$(basename "$first").recon}"
mkdir -p "$OUT"
REPORT="$OUT/REPORT.md"
BODY="$OUT/.body.md";     : > "$BODY"      # per-file detail; composed into REPORT at the end
FINDINGS="$OUT/FLAGS.txt"; : > "$FINDINGS"
CHECKSEC="$OUT/.checksec.tsv"; : > "$CHECKSEC"
UNPACK="$OUT/_unpacked"; mkdir -p "$UNPACK"    # extracted content lives here, and is the ONLY part of $OUT we recurse into

have(){ command -v "$1" >/dev/null 2>&1; }
log(){ [[ "$QUIET" == 1 ]] || echo -e "$*"; }
sec(){ printf '\n## %s\n\n' "$*" >> "$BODY"; }
run(){  # run(label, outfile|"" , cmd...) : capture to file (or inline) + note in body
  local label="$1" of="$2"; shift 2
  [[ -n "$of" ]] && of="$OUT/$of"
  if ! have "$1"; then printf -- '- _%s: skipped (%s not installed)_\n' "$label" "$1" >> "$BODY"; return; fi
  if [[ -n "$of" ]]; then
    "$@" >"$of" 2>&1
    printf -- '- %s → `%s`\n' "$label" "${of#$OUT/}" >> "$BODY"
  else
    { printf '### %s\n```\n' "$label"; "$@" 2>&1 | head -200; printf '```\n'; } >> "$BODY"
  fi
}
hunt(){ # hunt(sourcelabel, textfile)
  local src="$1" tf="$2"; [[ -s "$tf" ]] || return
  grep -EoI "$FLAG_RE" "$tf" 2>/dev/null | sort -u | while read -r h; do
    printf '%-16s %s\n' "[$src]" "$h" >> "$FINDINGS"
  done
}

# crypto_pass(file, outdir, safe, rel) — zero-AI crypto triage: key material,
# RSA public params, and hash identification. Runs on every file (crypto
# artifacts arrive as plain "ASCII text", so we can't rely on the dispatch).
crypto_pass(){
  local f="$1" d="$2" safe="$3" rel="$4" co="$2/crypto.txt" found=0
  : > "$co"
  if grep -aqE '^-----BEGIN ' "$f" 2>/dev/null; then
    found=1
    { echo "--- PEM/key blocks ---"; grep -aoE '^-----BEGIN [A-Z ]+-----' "$f" | sort -u; } >> "$co"
    if grep -aqE 'BEGIN (RSA )?PUBLIC KEY' "$f" && have openssl; then
      { echo; echo "--- RSA public params (openssl) ---"
        openssl rsa  -pubin -in "$f" -text -noout 2>/dev/null \
          || openssl pkey -pubin -in "$f" -text -noout 2>/dev/null
        echo "hint: factorable/shared modulus? -> RsaCtfTool --publickey $f --private"; } >> "$co"
    fi
  fi
  # hash-looking tokens (md5/sha1/sha256, or $id$-style crypt) -> identify
  local ht; ht="$(grep -aEoh '\$[0-9a-z]{1,4}\$[^ "'\'']{8,}|\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b' "$d/strings.txt" 2>/dev/null | sort -u | head -20)"
  if [[ -n "$ht" ]]; then
    found=1
    { echo; echo "--- hash candidates ---"; echo "$ht"; } >> "$co"
    if have hashid; then echo "$ht" | hashid -m 2>/dev/null >> "$co"
    else echo "hint: identify with hashid / hashcat --identify; crack: john --wordlist=rockyou.txt <hashfile>" >> "$co"; fi
  fi
  if [[ "$found" == 1 ]]; then
    printf -- '- 🔐 crypto material → `%s/crypto.txt`\n' "$safe" >> "$BODY"; hunt "crypto:$rel" "$co"
  else rm -f "$co"; fi
}

# crack_archive(file, ftype, outdir, safe, rel) — if a zip/rar/7z is password
# protected, run *2john + john/rockyou and report the recovered password.
# ponytail: rockyou+timeout only; raise CRACK_TIMEOUT or point WL elsewhere for more.
crack_archive(){
  local f="$1" ft="$2" d="$3" safe="$4" rel="$5" j2j hash="$3/archive.hash"
  local wl=/usr/share/wordlists/rockyou.txt
  [[ -f "$wl" ]] || wl=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
  case "$ft" in *Zip*) j2j=zip2john ;; *RAR*) j2j=rar2john ;; *7-zip*) j2j=7z2john ;; *) return ;; esac
  have "$j2j" && have john || { printf -- '- _crack: need %s + john (not installed)_\n' "$j2j" >> "$BODY"; return; }
  [[ -f "$wl" ]] || { printf -- '- _crack: no rockyou wordlist found_\n' >> "$BODY"; return; }
  "$j2j" "$f" > "$hash" 2>/dev/null
  [[ -s "$hash" ]] || { printf -- '- crack: archive is not password-protected\n' >> "$BODY"; rm -f "$hash"; return; }
  printf -- '- 🔑 password-protected; john+rockyou (≤%ss)…\n' "${CRACK_TIMEOUT:-120}" >> "$BODY"
  timeout "${CRACK_TIMEOUT:-120}" john --wordlist="$wl" "$hash" >/dev/null 2>&1
  local pw; pw="$(john --show "$hash" 2>/dev/null | grep -a ':' | grep -av 'password hash' | head -1 | cut -d: -f2)"
  if [[ -n "$pw" ]]; then
    printf -- '  - ⚠ CRACKED password: `%s`\n' "$pw" >> "$BODY"
    printf '%-16s archive password: %s\n' "[crack:$rel]" "$pw" >> "$FINDINGS"
    echo "$pw" > "$d/password.txt"
  else
    printf -- '  - not cracked within timeout (raise CRACK_TIMEOUT or use a bigger list)\n' >> "$BODY"
  fi
}

# ------------------------------------------------------------- extraction ---
extract_into(){ # extract_into(file, ftype, dest) -> unpack into dest (best effort)
  local f="$1" ft="$2" dest="$3"; mkdir -p "$dest"
  case "$ft" in
    *Zip*)   have unzip && unzip -o -q "$f" -d "$dest" 2>/dev/null ;;
    *tar*)   tar xf "$f" -C "$dest" 2>/dev/null ;;
    *gzip*)  gzip  -dc "$f" > "$dest/$(basename "${f%.gz}")"  2>/dev/null ;;
    *bzip2*) bzip2 -dc "$f" > "$dest/$(basename "${f%.bz2}")" 2>/dev/null ;;
    *XZ*)    xz    -dc "$f" > "$dest/$(basename "${f%.xz}")"  2>/dev/null ;;
    *7-zip*) have 7z    && 7z x -y -o"$dest" "$f" >/dev/null 2>&1 ;;
    *RAR*)   have unrar && unrar x -o+ "$f" "$dest/" >/dev/null 2>&1 ;;
    *)       have binwalk && binwalk -e -q -C "$dest" "$f" >/dev/null 2>&1 ;;  # carve unknowns
  esac
}

# ------------------------------------------------------------- queue --------
declare -a QUEUE=()
declare -A SEEN=()
COUNT=0
enqueue(){ # enqueue(path) if a readable regular file, unseen, under the cap
  local p; p="$(readlink -f "$1" 2>/dev/null)" || return
  [[ -f "$p" && -r "$p" ]] || return
  # never recon our own report/tool output — but DO recurse into unpacked content
  [[ "$p" == "$OUT"/* && "$p" != "$UNPACK"/* ]] && return
  [[ -n "${SEEN[$p]:-}" ]] && return
  SEEN[$p]=1; QUEUE+=("$p")
}

# =============================================================== per-file ===
recon_one(){
  local f="$1"
  local safe; safe="$(echo "${f#/}" | tr '/ ' '__')"
  local d="$OUT/$safe"; mkdir -p "$d"
  local rel; rel="$(basename "$f")"
  local ft; ft="$(file -b "$f" 2>/dev/null)"

  sec "FILE: \`$f\`"
  { echo "- type: $ft"; echo "- size: $(stat -c%s "$f" 2>/dev/null) bytes"
    echo "- md5:  $(md5sum "$f"  2>/dev/null | awk '{print $1}')"
    echo "- sha1: $(sha1sum "$f" 2>/dev/null | awk '{print $1}')"; } >> "$BODY"

  # --- universal passes --------------------------------------------------
  strings -n 6 "$f"        > "$d/strings.txt"  2>/dev/null
  strings -n 6 -e l "$f"  >> "$d/strings.txt"  2>/dev/null
  printf -- '- strings → `%s/strings.txt`\n' "$safe" >> "$BODY"
  hunt "strings:$rel" "$d/strings.txt"

  xxd "$f" 2>/dev/null | head -40 > "$d/hexhead.txt"
  if have binwalk; then
    binwalk "$f" > "$d/binwalk.txt" 2>&1
    printf -- '- binwalk → `%s/binwalk.txt`\n' "$safe" >> "$BODY"
    grep -qiE 'zip|gzip|rar|7-zip|PNG|JPEG|ELF|tar|compressed|certificate|LZMA|cpio|squashfs' "$d/binwalk.txt" \
      && printf -- '  - ⚠ embedded data detected by binwalk%s\n' "$([[ $EXTRACT == 1 ]] && echo '' || echo ' (re-run with -x to unpack)')" >> "$BODY"
  fi

  # --- base64 blob decode + re-hunt --------------------------------------
  grep -EoI '[A-Za-z0-9+/]{20,}={0,2}' "$d/strings.txt" 2>/dev/null | sort -u | head -50 \
    | while read -r b; do echo "$b" | base64 -d 2>/dev/null; echo; done > "$d/b64decoded.txt" 2>/dev/null
  [[ -s "$d/b64decoded.txt" ]] && { printf -- '- base64-decoded blobs → `%s/b64decoded.txt`\n' "$safe" >> "$BODY"; hunt "b64:$rel" "$d/b64decoded.txt"; }

  # --- crypto pass (keys / RSA params / hashes) --------------------------
  crypto_pass "$f" "$d" "$safe" "$rel"

  # --- category dispatch -------------------------------------------------
  case "$ft" in
    *ELF*)
      sec "binary: \`$rel\`"
      run "readelf header" "$safe/readelf.txt"  readelf -hdl "$f"
      run "symbols (nm)"   "$safe/nm.txt"       nm -C "$f"
      run "checksec"       "$safe/checksec.txt" checksec --file="$f"
      if [[ -s "$d/checksec.txt" ]]; then      # pull a one-row summary for the top table
        local cs="$d/checksec.txt"
        local relro canary nx pie
        relro=$(grep -oiE 'Full RELRO|Partial RELRO|No RELRO' "$cs" | head -1)
        # NB: test "No canary found" FIRST — it contains the substring "canary found"
        if   grep -qi 'No canary found' "$cs"; then canary="No canary"
        elif grep -qi 'Canary found'    "$cs"; then canary="Canary"
        else canary="?"; fi
        nx=$(grep -qiE 'NX enabled' "$cs" && echo "NX" || echo "NX off")
        pie=$(grep -qiE 'PIE enabled' "$cs" && echo "PIE" || { grep -qiE 'No PIE|PIE disabled' "$cs" && echo "No PIE" || echo "?"; })
        printf '%s\t%s\t%s\t%s\t%s\n' "$rel" "${relro:-?}" "$canary" "$nx" "$pie" >> "$CHECKSEC"
      fi
      { echo "### hot imports/strings"; echo '```'
        grep -Eiaoh 'system|execve|/bin/sh|setuid|setgid|gets|strcpy|strcat|sprintf|scanf|printf|memcpy|rand|srand|mmap|mprotect|puts|malloc|free|fopen|open|read|write' "$d/strings.txt" \
          | sort | uniq -c | sort -rn | head -30
        echo '```'; } >> "$BODY"
      [[ "$DEEP" == 1 ]] && run "objdump -d" "$safe/objdump.txt" objdump -d -M intel "$f"
      ;;
    *PE32*|*MS-DOS*|*PE\ *)
      sec "PE binary: \`$rel\`"; run "exiftool" "$safe/exif.txt" exiftool "$f" ;;
    *image*|*PNG*|*JPEG*|*bitmap*|*GIF*|*TIFF*|*BMP*)
      sec "image: \`$rel\`"
      run "exiftool" "$safe/exif.txt" exiftool "$f"
      case "$ft" in *PNG*) run "pngcheck -v" "$safe/pngcheck.txt" pngcheck -v "$f";; esac
      if have zsteg && [[ "$ft" == *PNG* || "$ft" == *bitmap* || "$ft" == *BMP* ]]; then
        run "zsteg -a" "$safe/zsteg.txt" zsteg -a "$f"; hunt "zsteg:$rel" "$d/zsteg.txt"
      fi
      if have zbarimg; then     # QR / barcodes
        zbarimg -q --raw "$f" > "$d/qr.txt" 2>/dev/null
        [[ -s "$d/qr.txt" ]] && { printf -- '- 📷 QR/barcode decoded → `%s/qr.txt`\n' "$safe" >> "$BODY"; hunt "qr:$rel" "$d/qr.txt"; }
      else
        printf -- '- _QR: zbarimg not installed (apt install zbar-tools)_\n' >> "$BODY"
      fi
      if have steghide; then
        steghide info "$f" > "$d/steghide.txt" 2>&1 <<<""
        printf -- '- steghide info → `%s/steghide.txt`\n' "$safe" >> "$BODY"
        if [[ "$DEEP" == 1 ]]; then           # try the empty password and mine the result
          local so="$UNPACK/$safe.steghide_out"
          steghide extract -sf "$f" -p "" -xf "$so" >>"$d/steghide.txt" 2>&1 <<<""
          if [[ -s "$so" ]]; then
            printf -- '  - ⚠ steghide extracted data → `_unpacked/%s.steghide_out`\n' "$safe" >> "$BODY"
            hunt "steghide:$rel" "$so"; enqueue "$so"
          fi
        fi
      fi
      have binwalk && binwalk -e -q -C "$d/binwalk_extract" "$f" >/dev/null 2>&1
      ;;
    *audio*|*WAVE*|*Audio*|*MPEG*layer*)
      sec "audio: \`$rel\`"; run "exiftool" "$safe/exif.txt" exiftool "$f"
      printf -- '- hint: open in Audacity/Sonic Visualiser → spectrogram for hidden text\n' >> "$BODY" ;;
    *PDF*)
      sec "pdf: \`$rel\`"; run "exiftool" "$safe/exif.txt" exiftool "$f"
      printf -- '- note: pdfinfo/pdf-parser not installed; using strings+binwalk. `apt install poppler-utils pdf-parser`.\n' >> "$BODY" ;;
    *pcap*|*tcpdump*|*capture*)
      sec "network capture: \`$rel\`"
      run "capinfos"        "$safe/capinfos.txt" capinfos "$f"
      run "proto hierarchy" "$safe/proto.txt"    tshark -r "$f" -q -z io,phs
      run "tcp conversations" "$safe/convs.txt"  tshark -r "$f" -q -z conv,tcp
      printf -- '- hint: `tshark -r %q --export-objects http,%s/http_objs` to dump transferred files\n' "$f" "$d" >> "$BODY" ;;
    *Zip*|*gzip*|*tar*|*7-zip*|*RAR*|*bzip2*|*XZ*|*compressed*)
      sec "archive: \`$rel\`"
      case "$ft" in
        *Zip*)   run "zip list" "$safe/list.txt" unzip -l "$f" ;;
        *tar*)   run "tar list" "$safe/list.txt" tar tvf "$f" ;;
        *7-zip*) run "7z list"  "$safe/list.txt" 7z l "$f" ;;
        *RAR*)   run "rar list" "$safe/list.txt" unrar l "$f" ;;
      esac
      crack_archive "$f" "$ft" "$d" "$safe" "$rel"
      # if we cracked it (and -x is on), unpack WITH the password and recurse
      if [[ $EXTRACT == 1 && -s "$d/password.txt" ]]; then
        local pw ex="$UNPACK/$safe"; pw="$(cat "$d/password.txt")"; mkdir -p "$ex"
        case "$ft" in
          *Zip*)   unzip -P "$pw" -o -q "$f" -d "$ex" 2>/dev/null ;;
          *RAR*)   have unrar && unrar x -p"$pw" -o+ "$f" "$ex/" >/dev/null 2>&1 ;;
          *7-zip*) have 7z    && 7z x -p"$pw" -y -o"$ex" "$f" >/dev/null 2>&1 ;;
        esac
        while IFS= read -r x; do enqueue "$x"; done < <(find "$ex" -type f 2>/dev/null)
      fi
      [[ $EXTRACT == 1 ]] \
        && printf -- '- -x: extracting + reconning contents\n' >> "$BODY" \
        || printf -- '- hint: re-run with -x to unpack\n' >> "$BODY" ;;
    *ASCII*|*text*|*source*|*script*|*JSON*|*XML*|*HTML*)
      sec "text/source: \`$rel\`"
      { echo "### secret-ish grep"; echo '```'
        grep -Einaoh 'password|passwd|secret|token|api[_-]?key|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|[a-f0-9]{32,64}' "$f" | head -40
        echo '```'; } >> "$BODY"
      hunt "text:$rel" "$f" ;;
    *)
      sec "unknown/data: \`$rel\`"
      printf -- '- relying on universal passes (strings/binwalk/hex). %s\n' \
        "$([[ $EXTRACT == 1 ]] && echo 'carving with binwalk -e.' || echo 'Try -x to carve, or DEEP=1 for foremost.')" >> "$BODY"
      [[ "$DEEP" == 1 ]] && have foremost && run "foremost carve" "$safe/foremost.txt" foremost -i "$f" -o "$d/foremost_out" ;;
  esac

  # --- recurse into anything we unpacked (extract mode) ------------------
  if [[ $EXTRACT == 1 ]]; then
    local ex="$UNPACK/$safe"
    extract_into "$f" "$ft" "$ex"            # archives unpack; images/unknowns get binwalk-carved
    while IFS= read -r x; do enqueue "$x"; done < <(find "$ex" -type f 2>/dev/null)
  fi
}

# =============================================================== header =====
{
  echo "# CTF recon report"
  echo
  echo "- generated: $(date -Iseconds)"
  echo "- targets: ${ARGS[*]}"
  echo "- flag regex: \`$FLAG_RE\`"
  echo "- extract mode: $([[ $EXTRACT == 1 ]] && echo on || echo off)"
  echo "- output dir: \`$OUT\`"
} > "$REPORT"

# =============================================================== walk =======
log "[*] recon → $OUT"
for a in "${ARGS[@]}"; do
  p="$(readlink -f "$a")"
  if [[ -d "$p" ]]; then
    while IFS= read -r x; do enqueue "$x"; done < <(find "$p" -type f | sort)
  elif [[ -f "$p" ]]; then enqueue "$p"
  else log "[!] skip (not found): $a"; fi
done

qi=0
while (( qi < ${#QUEUE[@]} )); do
  f="${QUEUE[$qi]}"; qi=$((qi+1)); COUNT=$((COUNT+1))
  if (( COUNT > MAXFILES )); then
    log "[!] hit MAXFILES=$MAXFILES cap; stopping (raise with MAXFILES=...)"
    printf '\n> ⚠ stopped at MAXFILES=%s; %s files were queued.\n' "$MAXFILES" "${#QUEUE[@]}" >> "$BODY"
    break
  fi
  log "  [$COUNT] ${f}"
  recon_one "$f"
done

# =============================================================== compose ====
sort -u -o "$FINDINGS" "$FINDINGS"

{
  echo
  echo "## 🚩 Flag candidates"
  echo
  if [[ -s "$FINDINGS" ]]; then echo '```'; cat "$FINDINGS"; echo '```'
  else echo "_none matched \`$FLAG_RE\`. Widen with FLAG_RE=... or read the per-file output._"; fi

  if [[ -s "$CHECKSEC" ]]; then
    echo; echo "## 🔒 checksec summary"; echo
    echo "| binary | RELRO | canary | NX | PIE |"
    echo "|---|---|---|---|---|"
    while IFS=$'\t' read -r b r c n p; do echo "| $b | $r | $c | $n | $p |"; done < "$CHECKSEC"
  fi

  echo; echo "---"
  cat "$BODY"
} >> "$REPORT"

rm -f "$BODY" "$CHECKSEC"

# =============================================================== finish =====
log ""
log "[*] done — inspected $COUNT file(s)."
log "    report : $REPORT"
log "    flags  : $FINDINGS"
if [[ -s "$FINDINGS" ]]; then
  log "\n\033[1;32m== FLAG CANDIDATES ==\033[0m"
  [[ "$QUIET" == 1 ]] || cat "$FINDINGS"
else
  log "    (no flag-regex hits — read $REPORT)"
fi
