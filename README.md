# 👻 ghost-scan

> Detect invisible Unicode payloads hiding in your JavaScript/TypeScript projects.

Built by [@JuanAtLarge](https://x.com/JuanAtLarge) after seeing this attack scale with AI-generated malicious npm packages.

## The Attack

Malicious npm packages are hiding payloads in **invisible Unicode characters** — zero-width spaces, soft hyphens, BOM characters — that don't render in code editors or GitHub diffs. The payload gets decoded and passed to `eval()` at runtime. You never see it during review.

AI is now generating 100+ convincing fake packages per week. Manual review is useless against this.

## What ghost-scan Does

- Scans JS/TS files for invisible/zero-width Unicode characters
- Flags files that combine invisible chars with `eval()`, `new Function()`, `setTimeout(string)`, or `child_process`
- Marks those as **CRITICAL** — invisible Unicode + eval is the attack signature
- Works on your source code or full `node_modules`

## Usage

No install needed:

```bash
npx ghost-scan
```

Or install globally:

```bash
npm install -g ghost-scan
ghost-scan
```

### Options

```bash
# Scan current directory (skips node_modules by default)
npx ghost-scan

# Scan a specific path
npx ghost-scan ./src

# Include node_modules (slow but thorough)
npx ghost-scan . --node-modules

# Scan before installing a suspicious package
cd /tmp && mkdir test-pkg && cd test-pkg
npm pack <suspicious-package> && tar -xf *.tgz
npx ghost-scan ./package
```

## Output

```
👻 ghost-scan — invisible Unicode payload detector
   by @JuanAtLarge | github.com/JuanAtLarge/ghost-scan

📂 Scanning: /your/project

🚨 CRITICAL node_modules/some-package/index.js
   Invisible chars found:
     • Zero-Width Space (U+200B) ×47
     • Soft Hyphen (U+00AD) ×12
   ⚡ Also contains: eval(), child_process
   → Invisible Unicode + eval pattern = likely malicious payload

🔍 1 file(s) flagged out of 1,847 scanned

🚨 CRITICAL findings detected. Do not run this code.
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no invisible Unicode found |
| `1` | Warning — invisible Unicode found, no eval patterns |
| `2` | Critical — invisible Unicode + eval/exec patterns found |

## What It Detects

**Invisible Unicode characters:**
- Zero-Width Space (U+200B)
- Zero-Width Non-Joiner / Joiner (U+200C, U+200D)
- Soft Hyphen (U+00AD)
- BOM / Zero-Width No-Break Space (U+FEFF)
- Deprecated Format Characters (U+206A-206F)
- Invisible Math Operators (U+2061-2064)
- Private Use Area characters

**Dangerous execution patterns:**
- `eval()`
- `new Function()`
- `setTimeout(string)` / `setInterval(string)`
- `execSync()` / `child_process`

## Limitations

This catches the specific attack pattern described above. It won't catch every obfuscation technique. Defense in depth still applies — use a lockfile, audit your deps, don't install random packages.

## License

MIT
