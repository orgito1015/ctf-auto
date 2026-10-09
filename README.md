# ctf-auto

Home-built CTF automation for Parrot/Kali-style boxes. Two ways to attack a
challenge:

- **Without AI** — `ctf-recon` and `ctf-web` run the recon commands you'd type
  anyway (file/strings/binwalk/steg, or headers/ffuf/nuclei/katana for web),
  hunt for flags, and drop a readable `REPORT.md`.
- **With AI** — `ctf-solve` hands the whole challenge to [Claude Code](https://claude.com/claude-code)
  headless (`claude -p`), which analyzes, writes & runs an exploit, recovers the
  flag, and leaves a `WRITEUP.md` + `solution/`.

> For **authorized, educational** CTF use only. See [disclaimer](#disclaimer).

## Scripts

| Script | AI? | Input | Output (in CWD) |
|--------|-----|-------|-----------------|
| `ctf-recon.sh` | no | file / folder | `<name>.recon/REPORT.md` + raw tool output |
| `ctf-web.sh`   | no* | URL | `<host>.web/REPORT.md` (`AI=1` to then exploit) |
| `ctf-solve.sh` | yes | folder / archive / file | `WRITEUP.md` + `solution/` |

\* `ctf-web` is zero-AI recon by default; `AI=1` hands the report to the solver.

## Install

```bash
git clone https://github.com/<you>/ctf-auto.git ~/ctf-auto
chmod +x ~/ctf-auto/*.sh
# put them on PATH (aliases keep the `.sh` off):
cat >> ~/.bashrc <<'EOF'
alias ctf-recon='~/ctf-auto/ctf-recon.sh'
alias ctf-web='~/ctf-auto/ctf-web.sh'
alias ctf-solve='~/ctf-auto/ctf-solve.sh'
EOF
source ~/.bashrc
```

`ctf-solve` (and `ctf-web AI=1`) need the [Claude Code CLI](https://claude.com/claude-code)
installed and authenticated (`claude` on PATH). The recon scripts just call
standard tools — install whatever you're missing: `binwalk exiftool steghide
zsteg zbar-tools checksec foremost tshark ffuf nuclei katana arjun whatweb
seclists`. Each script degrades gracefully and notes what it skipped.

## Usage

```bash
# look first (no AI)
ctf-recon ./chall                 # walk a folder
ctf-recon -x drop.zip             # unpack archives/binwalk, recon inside
DEEP=1 ctf-recon maybe_stego.jpg  # heavier steg passes

# web first pass (no AI)
ctf-web http://target:1337/ "login, maybe sqli"
AI=1 ctf-web http://target/ "idor?"   # recon THEN autonomous exploit

# hand it to the AI
ctf-solve ./chall
QUIET=1 ctf-solve ./chall             # print ONLY the flag
NETWORK=1 ctf-solve web_chall/        # steer prompt toward network use
FLAG_FMT='CTF{...}' ctf-solve ./chall # tell it the flag format
```

See [`CHEATSHEET.md`](CHEATSHEET.md) for every flag, env var, and per-category
command reference.

## Caja right-click menu (optional, MATE)

```bash
cp caja/* ~/.config/caja/scripts/
chmod +x ~/.config/caja/scripts/*
```

Then right-click a challenge in Caja → **Scripts → Solve with AI** (offline,
shows only the flag) or **Solve with AI (online)** (network allowed). Both
assume the scripts live in `~/ctf-auto/`.

## Disclaimer

Built for Capture The Flag competitions and security learning on systems you
are authorized to test. `ctf-solve` runs with `--dangerously-skip-permissions`
so the agent works unattended — run it on challenge files, in a VM/sandbox, not
against anything you don't own or have explicit permission to attack. You are
responsible for how you use it.

## License

MIT — see [LICENSE](LICENSE).
