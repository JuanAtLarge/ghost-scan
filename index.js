#!/usr/bin/env node
// ghost-scan — detect invisible Unicode payloads in JS/TS projects
// by @JuanAtLarge | github.com/JuanAtLarge/ghost-scan

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Invisible/suspicious Unicode ranges
const INVISIBLE_CHARS = [
  { range: /\u200b/g, name: 'Zero-Width Space (U+200B)' },
  { range: /\u200c/g, name: 'Zero-Width Non-Joiner (U+200C)' },
  { range: /\u200d/g, name: 'Zero-Width Joiner (U+200D)' },
  { range: /\u200e/g, name: 'Left-to-Right Mark (U+200E)' },
  { range: /\u200f/g, name: 'Right-to-Left Mark (U+200F)' },
  { range: /\u00ad/g, name: 'Soft Hyphen (U+00AD)' },
  { range: /\ufeff/g, name: 'BOM / Zero-Width No-Break Space (U+FEFF)' },
  { range: /\u2060/g, name: 'Word Joiner (U+2060)' },
  { range: /\u180e/g, name: 'Mongolian Vowel Separator (U+180E)' },
  { range: /[\u2061-\u2064]/g, name: 'Invisible Math Operators (U+2061-2064)' },
  { range: /[\u206a-\u206f]/g, name: 'Deprecated Format Characters (U+206A-206F)' },
  { range: /[\ue000-\uf8ff]/g, name: 'Private Use Area (U+E000-F8FF)' },
];

// Dangerous eval patterns
const EVAL_PATTERNS = [
  { pattern: /\beval\s*\(/, name: 'eval()' },
  { pattern: /new\s+Function\s*\(/, name: 'new Function()' },
  { pattern: /setTimeout\s*\(\s*['"`]/, name: 'setTimeout(string)' },
  { pattern: /setInterval\s*\(\s*['"`]/, name: 'setInterval(string)' },
  { pattern: /execSync\s*\(/, name: 'execSync()' },
  { pattern: /child_process/, name: 'child_process' },
];

const SCAN_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx'];
const SKIP_DIRS = ['node_modules/.cache', '.git', 'dist', 'build', '.next'];

let totalFiles = 0;
let flaggedFiles = 0;
const findings = [];

function shouldSkip(filePath) {
  return SKIP_DIRS.some(d => filePath.includes(d));
}

function scanFile(filePath) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return;
  }

  totalFiles++;
  const issues = [];

  // Check for invisible chars
  const invisibleFound = [];
  for (const { range, name } of INVISIBLE_CHARS) {
    const matches = content.match(range);
    if (matches) {
      invisibleFound.push({ name, count: matches.length });
    }
  }

  // Check for eval patterns
  const evalFound = [];
  for (const { pattern, name } of EVAL_PATTERNS) {
    if (pattern.test(content)) {
      evalFound.push(name);
    }
  }

  // Flag if invisible chars present
  if (invisibleFound.length > 0) {
    issues.push({
      type: 'INVISIBLE_UNICODE',
      severity: evalFound.length > 0 ? 'CRITICAL' : 'WARNING',
      details: invisibleFound,
      evalPatterns: evalFound,
    });
  }

  if (issues.length > 0) {
    flaggedFiles++;
    findings.push({ file: filePath, issues });
  }
}

function walkDir(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (shouldSkip(fullPath)) continue;
    if (entry.isDirectory()) {
      walkDir(fullPath);
    } else if (entry.isFile() && SCAN_EXTENSIONS.includes(path.extname(entry.name))) {
      scanFile(fullPath);
    }
  }
}

// CLI
const args = process.argv.slice(2);
const scanPath = args[0] || '.';
const includeNodeModules = args.includes('--node-modules');

console.log(`\n👻 ghost-scan — invisible Unicode payload detector`);
console.log(`   by @JuanAtLarge | github.com/JuanAtLarge/ghost-scan\n`);
console.log(`📂 Scanning: ${path.resolve(scanPath)}`);
if (includeNodeModules) console.log(`   (including node_modules — this may take a while)\n`);
else console.log(`   (skipping node_modules — use --node-modules to include)\n`);

if (!includeNodeModules) {
  SKIP_DIRS.push('node_modules');
}

walkDir(path.resolve(scanPath));

console.log(`📊 Scanned ${totalFiles} files\n`);

if (findings.length === 0) {
  console.log(`✅ No invisible Unicode characters detected. You're clean.\n`);
  process.exit(0);
}

for (const { file, issues } of findings) {
  for (const issue of issues) {
    const badge = issue.severity === 'CRITICAL' ? '🚨 CRITICAL' : '⚠️  WARNING';
    console.log(`${badge} ${file}`);
    console.log(`   Invisible chars found:`);
    for (const { name, count } of issue.details) {
      console.log(`     • ${name} ×${count}`);
    }
    if (issue.evalPatterns.length > 0) {
      console.log(`   ⚡ Also contains: ${issue.evalPatterns.join(', ')}`);
      console.log(`   → Invisible Unicode + eval pattern = likely malicious payload`);
    }
    console.log();
  }
}

console.log(`🔍 ${flaggedFiles} file(s) flagged out of ${totalFiles} scanned`);
if (findings.some(f => f.issues.some(i => i.severity === 'CRITICAL'))) {
  console.log(`\n🚨 CRITICAL findings detected. Do not run this code.`);
  process.exit(2);
} else {
  console.log(`\n⚠️  Review flagged files before running.`);
  process.exit(1);
}
