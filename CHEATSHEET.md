# CTF Toolkit — Cheat Sheet

My home-built CTF automation on Parrot OS. `cat ~/ctf-auto/CHEATSHEET.md` to recall.

---

## The three scripts (`~/ctf-auto/`)

| Script | Input | Does | Output (in CWD) |
|--------|-------|------|-----------------|
| `ctf-solve.sh` | folder / archive / file | hands challenge to Claude, solves autonomously | `WRITEUP.md` + `solution/` |
| `ctf-recon.sh` | file / folder | zero-AI first pass (file, strings, binwalk, steg…) | `<name>.recon/REPORT.md` |
| `ctf-web.sh`   | URL | zero-AI web first pass (+ optional AI exploit) | `<host>.web/REPORT.md` |

### ctf-solve
```bash
ctf-solve ~/Downloads/pwn_babyheap            # solve a folder
ctf-solve chall.zip "format string, CTF{...}" # archive + hint
QUIET=1 ctf-solve chall/                       # print ONLY the flag
NETWORK=1 ctf-solve web_chall/                 # let tools reach network
SAFE=1 ctf-solve chall/                        # ask before each tool
MODEL=opus ctf-solve chall/                    # pick model
FLAG_FMT='CTF{...}' ctf-solve chall/           # tell it the flag format
RECON=0 ctf-solve chall/                       # skip the auto recon pre-pass
```
⚠ `claude -p` always needs internet (the API). NETWORK=1 only steers the prompt; it does not firewall tools.
ℹ ctf-solve runs ctf-recon first and feeds the report into the prompt (RECON=0 to skip). Recon output lands in `<chall>/.recon/`.

### ctf-recon  (run BEFORE solve to eyeball quickly)
```bash
ctf-recon ./chall                 # walk a folder
ctf-recon secret.png              # one file
ctf-recon -x drop.zip             # unpack archives/binwalk, recon inside
DEEP=1 ctf-recon maybe_stego.jpg  # heavier steg passes
FLAG_RE='HTB\{[^}]+\}' ctf-recon dump.bin
CRACK_TIMEOUT=300 ctf-recon -x locked.zip   # also: auto zip2john/rar2john+john on rockyou
```
Now also: detects RSA public keys (dumps n/e + RsaCtfTool hint) and hash candidates (hashid),
and auto-cracks password-protected zip/rar/7z with john+rockyou (`-x` then unpacks with the password).

### ctf-web  (Pretera is web-heavy — start here for web)
```bash
ctf-web http://target:1337/                       # recon only
ctf-web http://target/ "login, maybe sqli"        # + hint
DEEP=1 ctf-web http://target/                      # medium wordlist + full nuclei
AI=1   ctf-web http://target/ "idor?"              # recon THEN autonomous exploit
WL=/path/list.txt FLAG_RE='flag\{[^}]+\}' ctf-web http://target/
```
Runs: headers → whatweb → sensitive files → ffuf → arjun → nuclei → katana → flag hunt.

---

## Right-click in Caja (file manager)
Right-click a challenge file/folder → **Scripts →**
- **Solve with AI** — offline, shows only the flag in a terminal.
- **Solve with AI (online)** — same but network allowed (remote/web/pwn).

Scripts live in `~/.config/caja/scripts/`. If a new one doesn't appear, press **F5**.

---

## Per-category quick commands

### Recon / triage (any file)
```bash
file f; strings -n8 f | less; xxd f | head; binwalk -e f
exiftool f; echo $?; ls -la
```

### pwn
```bash
checksec --file=./bin
gdb -q ./bin            # pwndbg auto-loads
python3 -c 'from pwn import *; e=ELF("./bin"); print(hex(e.sym.main))'
# template:  r = process("./bin")   /   r = remote("host", PORT)
```

### rev
```bash
ghidra &                # GUI decompiler
r2 -AA ./bin            # then: afl ; pdf @ main
jadx-gui app.apk        # android
```

### crypto
```bash
RsaCtfTool --publickey key.pub --uncipher cipher     # or: rsacrack
factor 123456789
python3   # from Crypto.Util.number import long_to_bytes, ...
```

### forensics
```bash
vol -f mem.raw windows.info          # volatility3 (vol 2.28)
vol -f mem.raw windows.pslist
foremost -i disk.img -o out/         # carve files
tshark -r cap.pcap -Y 'http.request' # or open in wireshark
```

### stego
```bash
zsteg -a img.png ; steghide extract -sf img.jpg
binwalk -e img.png ; exiftool img.png ; strings img.png | grep -i flag
```

### web
```bash
whatweb -a3 http://t/ ; nikto -h http://t/
ffuf -u http://t/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,301,403
arjun -u http://t/page                      # hidden params
nuclei -u http://t/ -silent                 # template vuln scan (~/go/bin)
katana -u http://t/ -silent -jc             # crawl + js endpoints
sqlmap -u 'http://t/?id=1' --batch --dbs    # sqli
wpscan --url http://t/ --enumerate          # wordpress
```
**Easiest web win:** exposed `.git` → `git-dumper http://t/.git/ ./gitdump` → read the source.

---

## Burp Suite via MCP (web challenges)
Claude Code is wired to Burp's MCP server (SSE, `http://127.0.0.1:9876`, user scope).
```bash
claude mcp list            # burp should show ✔ Connected
claude mcp get burp
```
To use it:
1. Start/keep **Burp** open with the **MCP Server** extension enabled (MCP tab).
2. Proxy the challenge through Burp (browser → `127.0.0.1:8080`) so traffic lands in history.
3. Start a **fresh** `claude` session (MCP tools load at session start), then ask e.g.
   *"read the Burp proxy history, take the last POST to /login and try auth-bypass / SQLi on the username param, show me the responses."*

Claude can then read proxy history and send/replay/modify requests through Burp — best for
stateful flows (auth, CSRF tokens, sessions) where curl/ffuf are clumsy.
Remove: `claude mcp remove burp -s user`.

## Wordlists
- `/usr/share/wordlists/rockyou.txt` — passwords
- `/usr/share/seclists/Discovery/Web-Content/` — dir/file fuzzing
- `/usr/share/seclists/Usernames/`, `.../Passwords/`

## Where tools live
Go tools (nuclei, katana) in `~/go/bin` (on PATH via `~/.bashrc`). New terminal picks them up; current one: `source ~/.bashrc`.

## Typical flow
```
1. ctf-recon ./chall        # look first
2. (web?) ctf-web http://target/
3. QUIET=1 ctf-solve ./chall   # or right-click → Solve with AI
4. read WRITEUP.md + solution/ if the flag needs manual finishing
```

## Web exploit-gen tools (from awesome-ctf-resources)

These need a *known sink*, so they're manual — not wired into ctf-web.sh.

- **phpggc** — PHP `unserialize()` gadget chains. List: `phpggc -l`.
  Build: `phpggc Laravel/RCE1 system id` → paste into the deserialization param.
  Base64: `phpggc -b Monolog/RCE1 system id`. phar: `phpggc -p phar -o x.phar ...`.
- **git-dumper** — exposed `.git`: `git-dumper http://t/.git/ loot && cd loot && git log -p`.
- **smuggler** — HTTP desync (also auto-run by ctf-web.sh): `smuggler -u https://t/`.
- **nomore403** — 40x bypass (also auto-run on 403s): `nomore403 -u https://t/admin`.
- **dirhunt** — smart dir discovery, no bruteforce: `dirhunt http://t/`.
- **gopherus** — SSRF→RCE gopher:// payloads. NOT installed (needs python2).
  Finish: `sudo apt install python2 && git clone .../Gopherus` then run with python2.
