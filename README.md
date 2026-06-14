# AUR PKGBUILD Checker

Checks all installed AUR packages for suspicious content in their
PKGBUILDs — malicious npm packages, curl piping into bash, base64
decoded execution, and more.

Inspired by the June 2026 Atomic Arch AUR supply chain attack.

## Install
\`\`\`bash
git clone https://github.com/<yourusername>/aur-pkgbuild-check.git
cd aur-pkgbuild-check
chmod +x aur-pkgbuild-check.sh
./aur-pkgbuild-check.sh
\`\`\`

## What it checks
- Known malicious npm packages (atomic-lockfile, js-digest, lockfile-js)
- curl/wget piped directly into shell
- Base64 decoded execution
- eval with network fetches
- npm/bun installs in non-JavaScript packages
- Orphaned packages with no maintainer
