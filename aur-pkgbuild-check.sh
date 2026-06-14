#!/usr/bin/env bash
# ============================================================
#  AUR PKGBUILD Manual Checker v2
#  Smarter detection — distinguishes real threats from
#  legitimate use of npm/bun/curl/wget in packages
# ============================================================

CACHE_DIR="$HOME/.cache/aur-pkgbuild-check"
LOG_FILE="$HOME/.local/share/aur-pkgbuild-check/report.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
SUSPICIOUS=()
ORPHANED=()
CLEAN=()
FAILED=()

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

mkdir -p "$CACHE_DIR" "$(dirname "$LOG_FILE")"

log() {
    echo "[$TIMESTAMP] $*" >> "$LOG_FILE"
}

# ── Known malicious npm packages ─────────────────────────────
KNOWN_MALICIOUS=(
    "atomic-lockfile"
    "js-digest"
    "lockfile-js"
    "temp.sh"
)

# ── Packages known to legitimately use npm/bun ───────────────
# These are whitelisted so they don't produce false positives
JS_PACKAGES=(
    "libelectron"
    "libelectron-electron-meta"
    "electron39-bin"
    "openclaude"
    "pomatez"
    "visual-studio-code-bin"
    "github-copilot-cli"
    "discord"
    "spotify"
    "flutter-bin"
    "deno"
    "node-gyp"
)

is_js_package() {
    local pkg="$1"
    for jp in "${JS_PACKAGES[@]}"; do
        [[ "$pkg" == "$jp" ]] && return 0
    done
    return 1
}

check_package() {
    local pkg="$1"
    local pkg_cache="$CACHE_DIR/$pkg"
    local found_issues=()

    # Fetch PKGBUILD from AUR
    local pkgbuild
    pkgbuild=$(curl -s "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=$pkg" 2>/dev/null)

    if [ -z "$pkgbuild" ] || echo "$pkgbuild" | grep -q "404\|Not Found"; then
        FAILED+=("$pkg")
        return
    fi

    # Save PKGBUILD to cache for manual review
    echo "$pkgbuild" > "$pkg_cache.PKGBUILD"

    # Check maintainer (orphaned = no maintainer)
    local maintainer
    maintainer=$(curl -s "https://aur.archlinux.org/rpc/v5/info?arg=$pkg" 2>/dev/null | \
        grep -o '"Maintainer":[^,}]*' | cut -d: -f2 | tr -d '"' | xargs)
    if [ -z "$maintainer" ] || [ "$maintainer" = "null" ]; then
        ORPHANED+=("$pkg")
    fi

    # ── Check 1: Known malicious packages (always flag) ──────
    for malicious in "${KNOWN_MALICIOUS[@]}"; do
        local match
        match=$(echo "$pkgbuild" | grep -v "^#" | grep -iE "(npm install|bun (install|add)).*$malicious|$malicious" | head -1)
        if [ -n "$match" ]; then
            found_issues+=("🚨 Known malicious package '$malicious': $match")
        fi
    done

    # ── Check 2: curl/wget actually piped into shell ──────────
    # Only flag when output is directly executed, not just used as a download tool
    local curl_pipe
    curl_pipe=$(echo "$pkgbuild" | grep -v "^#" | grep -iE "curl.+\|\s*(bash|sh|zsh|fish)" | head -1)
    if [ -n "$curl_pipe" ]; then
        found_issues+=("🚨 curl piped directly into shell: $curl_pipe")
    fi

    local wget_pipe
    wget_pipe=$(echo "$pkgbuild" | grep -v "^#" | grep -iE "wget.+\|\s*(bash|sh|zsh|fish)" | head -1)
    if [ -n "$wget_pipe" ]; then
        found_issues+=("🚨 wget piped directly into shell: $wget_pipe")
    fi

    # ── Check 3: base64 decode piped into shell ───────────────
    local b64_exec
    b64_exec=$(echo "$pkgbuild" | grep -v "^#" | grep -iE "base64\s+-d.+\|\s*(bash|sh)|echo.+\|\s*base64\s+-d\s*\|\s*(bash|sh)" | head -1)
    if [ -n "$b64_exec" ]; then
        found_issues+=("🚨 Base64 decoded and executed: $b64_exec")
    fi

    # ── Check 4: eval with curl/wget ─────────────────────────
    local eval_net
    eval_net=$(echo "$pkgbuild" | grep -v "^#" | grep -iE "eval.*curl|eval.*wget" | head -1)
    if [ -n "$eval_net" ]; then
        found_issues+=("🚨 eval with network fetch: $eval_net")
    fi

    # ── Check 5: npm installing unrelated packages ────────────
    # Only flag if: not a known JS package AND npm installs something
    # that isn't a dev dependency of the software itself
    if ! is_js_package "$pkg"; then
        local npm_install
        npm_install=$(echo "$pkgbuild" | grep -v "^#" | grep -iE "^\s*npm install" | head -1)
        if [ -n "$npm_install" ]; then
            found_issues+=("⚠️  npm install in non-JS package: $npm_install")
        fi

        local bun_install
        bun_install=$(echo "$pkgbuild" | grep -v "^#" | grep -iE "^\s*bun (install|add)" | head -1)
        if [ -n "$bun_install" ]; then
            found_issues+=("⚠️  bun install in non-JS package: $bun_install")
        fi
    fi

    # ── Check 6: Downloading and executing scripts ────────────
    local dl_exec
    dl_exec=$(echo "$pkgbuild" | grep -v "^#" | grep -iE "(curl|wget).+(-O|-o)\s+.+\.(sh|bash)\s*&&?\s*(bash|sh|chmod)" | head -1)
    if [ -n "$dl_exec" ]; then
        found_issues+=("⚠️  Downloading and executing a script: $dl_exec")
    fi

    # ── Check 7: Suspicious install hooks ────────────────────
    if [ -f "$pkg_cache.install" ]; then
        local hook_issue
        hook_issue=$(grep -iE "npm install|curl.+\|.*(bash|sh)|base64" "$pkg_cache.install" | grep -v "^#" | head -1)
        if [ -n "$hook_issue" ]; then
            found_issues+=("⚠️  Suspicious .install hook: $hook_issue")
        fi
    fi

    # ── Result ────────────────────────────────────────────────
    if [ ${#found_issues[@]} -gt 0 ]; then
        SUSPICIOUS+=("$pkg")
        log "SUSPICIOUS: $pkg"
        for issue in "${found_issues[@]}"; do
            log "  -> $issue"
        done
        printf '%s\n' "${found_issues[@]}" > "$pkg_cache.issues"
    else
        CLEAN+=("$pkg")
        log "CLEAN: $pkg"
    fi
}

# ── Main ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     AUR PKGBUILD Suspicious Content Checker v2   ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

AUR_PACKAGES=$(pacman -Qqm)
TOTAL=$(echo "$AUR_PACKAGES" | wc -l)

echo -e "${CYAN}Checking $TOTAL AUR packages...${NC}"
echo ""

i=0
while IFS= read -r pkg; do
    i=$((i + 1))
    printf "\r${CYAN}[%d/%d]${NC} Checking: %-40s" "$i" "$TOTAL" "$pkg"
    check_package "$pkg"
    sleep 0.3
done <<< "$AUR_PACKAGES"

echo -e "\r$(printf ' %.0s' {1..60})\r"

# ── Results ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════ RESULTS ══════════════════${NC}"
echo ""

if [ ${#SUSPICIOUS[@]} -gt 0 ]; then
    echo -e "${RED}${BOLD}🚨 SUSPICIOUS PACKAGES (${#SUSPICIOUS[@]})${NC}"
    echo -e "${RED}────────────────────────────────────────────${NC}"
    for pkg in "${SUSPICIOUS[@]}"; do
        echo -e "${RED}  ✗ $pkg${NC}"
        if [ -f "$CACHE_DIR/$pkg.issues" ]; then
            while IFS= read -r issue; do
                echo -e "${YELLOW}      → $issue${NC}"
            done < "$CACHE_DIR/$pkg.issues"
        fi
        echo -e "${CYAN}      Review: https://aur.archlinux.org/packages/$pkg${NC}"
        echo -e "${CYAN}      PKGBUILD: $CACHE_DIR/$pkg.PKGBUILD${NC}"
    done
    echo ""
fi

if [ ${#ORPHANED[@]} -gt 0 ]; then
    echo -e "${YELLOW}${BOLD}⚠️  ORPHANED PACKAGES (${#ORPHANED[@]}) — No maintainer, higher risk${NC}"
    echo -e "${YELLOW}────────────────────────────────────────────${NC}"
    for pkg in "${ORPHANED[@]}"; do
        echo -e "${YELLOW}  ! $pkg${NC}"
    done
    echo ""
fi

if [ ${#FAILED[@]} -gt 0 ]; then
    echo -e "${YELLOW}${BOLD}⚙  COULD NOT CHECK (${#FAILED[@]}) — Not found on AUR${NC}"
    echo -e "${YELLOW}────────────────────────────────────────────${NC}"
    for pkg in "${FAILED[@]}"; do
        echo -e "${YELLOW}  ? $pkg${NC}"
    done
    echo ""
fi

echo -e "${GREEN}${BOLD}✅ CLEAN PACKAGES (${#CLEAN[@]})${NC}"
echo -e "${GREEN}────────────────────────────────────────────${NC}"
for pkg in "${CLEAN[@]}"; do
    echo -e "${GREEN}  ✓ $pkg${NC}"
done
echo ""

echo -e "${BOLD}══════════════════ SUMMARY ══════════════════${NC}"
echo -e "  Total checked  : $TOTAL"
echo -e "  ${GREEN}Clean          : ${#CLEAN[@]}${NC}"
echo -e "  ${YELLOW}Orphaned       : ${#ORPHANED[@]}${NC}"
echo -e "  ${RED}Suspicious     : ${#SUSPICIOUS[@]}${NC}"
echo -e "  ${YELLOW}Could not check: ${#FAILED[@]}${NC}"
echo ""
echo -e "  PKGBUILDs cached at : ${CYAN}$CACHE_DIR${NC}"
echo -e "  Full log at         : ${CYAN}$LOG_FILE${NC}"
echo ""

if [ ${#SUSPICIOUS[@]} -gt 0 ]; then
    echo -e "${RED}${BOLD}⚠  ACTION REQUIRED: Investigate suspicious packages before updating!${NC}"
    notify-send -u critical "🚨 Suspicious AUR Packages Found" \
        "${#SUSPICIOUS[@]} package(s) flagged. Check terminal for details." 2>/dev/null
else
    echo -e "${GREEN}${BOLD}All checked packages look clean!${NC}"
    notify-send -u normal "✅ AUR Check Complete" \
        "All $TOTAL AUR packages look clean." 2>/dev/null
fi
echo ""
