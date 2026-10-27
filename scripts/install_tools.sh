#!/usr/bin/env bash
# install_tools.sh — best-effort installer for the VAPT-AI pentest-tool catalog on Ubuntu.
#
# Idempotent: skips anything already on PATH, keeps going on failure, prints ✓/✗ per tool.
# Uses the right method per tool: prebuilt GitHub binaries, go install, pipx, apt, gem,
# git-clone wrappers, single-file scripts. Re-run it any time to fill gaps.
#
#   bash scripts/install_tools.sh                 # all sections (recommended)
#   bash scripts/install_tools.sh binrel git      # only chosen sections
#   sections: prereqs binrel go pipx apt gem git scripts seclists
#
# go tools land in ~/go/bin, pipx in ~/.local/bin — both must be on PATH (pipx ensurepath is
# run). Re-check with:  python3 scripts/check_tools.py
set -u
DEFAULT="prereqs binrel go pipx apt gem git scripts seclists"
SECTIONS=("${@:-$DEFAULT}")
RUN(){ for s in ${SECTIONS[@]}; do [ "$s" = "$1" ] && return 0; done; return 1; }
have(){ command -v "$1" >/dev/null 2>&1; }
ok(){ printf '  \033[92m✓\033[0m %s\n' "$1"; }
no(){ printf '  \033[91m✗\033[0m %s (%s)\n' "$1" "$2"; }
hdr(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
export DEBIAN_FRONTEND=noninteractive
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"

# --- prereqs ---------------------------------------------------------------------------
if RUN prereqs; then
  hdr "Prerequisites"
  sudo apt-get update -qq
  sudo apt-get install -y -qq git curl jq build-essential pipx ruby ruby-dev perl >/dev/null 2>&1 \
    && ok "git curl jq build pipx ruby perl" || no "apt prereqs" "check sudo/network"
  pipx ensurepath >/dev/null 2>&1 || true
  have go && ok "golang present" || { sudo apt-get install -y -qq golang-go >/dev/null 2>&1 \
    && ok "golang" || no "golang" "install Go manually"; }
fi

# --- prebuilt GitHub binaries → /usr/local/bin (most reliable) -------------------------
if RUN binrel; then
  hdr "Prebuilt binaries → /usr/local/bin"
  # gitleaks (CORE: the source pipeline uses it) — go install is flaky, use the release.
  if have gitleaks; then ok "gitleaks (present)"; else
    u=$(curl -sL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep -oE 'https://[^"]+linux_x64\.tar\.gz' | head -1)
    [ -n "$u" ] && curl -sL "$u" | sudo tar -xz -C /usr/local/bin gitleaks 2>/dev/null && ok "gitleaks" || no "gitleaks" "release fetch failed"
  fi
  if have feroxbuster; then ok "feroxbuster (present)"; else
    curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz | sudo tar -xz -C /usr/local/bin feroxbuster 2>/dev/null && ok "feroxbuster" || no "feroxbuster" "release fetch failed"
  fi
  if have pspy; then ok "pspy (present)"; else
    sudo curl -sL -o /usr/local/bin/pspy https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 2>/dev/null && sudo chmod +x /usr/local/bin/pspy && ok "pspy" || no "pspy" "release fetch failed"
  fi
  if have ligolo-proxy; then ok "ligolo-proxy (present)"; else
    u=$(curl -sL https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep -oE 'https://[^"]+proxy[^"]+linux_amd64\.tar\.gz' | head -1)
    [ -n "$u" ] && curl -sL "$u" | sudo tar -xz -C /usr/local/bin proxy 2>/dev/null && sudo mv -f /usr/local/bin/proxy /usr/local/bin/ligolo-proxy && ok "ligolo-proxy" || no "ligolo-proxy" "release fetch failed"
  fi
  if have trufflehog; then ok "trufflehog (present)"; else
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin >/dev/null 2>&1 && ok "trufflehog" || no "trufflehog" "installer failed"
  fi
fi

# --- Go tools → ~/go/bin --------------------------------------------------------------
if RUN go && have go; then
  hdr "Go tools → ~/go/bin"
  declare -A GO=(
    [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [asnmap]="github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    [uncover]="github.com/projectdiscovery/uncover/cmd/uncover@latest"
    [interactsh-client]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    [gau]="github.com/lc/gau/v2/cmd/gau@latest"
    [waybackurls]="github.com/tomnomnom/waybackurls@latest"
    [subzy]="github.com/PentestPad/subzy@latest"
    [chisel]="github.com/jpillora/chisel@latest"
    [amass]="github.com/owasp-amass/amass/v4/...@master"
    [kerbrute]="github.com/ropnop/kerbrute@latest"
    [windapsearch]="github.com/ropnop/go-windapsearch/cmd/windapsearch@latest"
  )
  for bin in "${!GO[@]}"; do
    have "$bin" && { ok "$bin (present)"; continue; }
    go install "${GO[$bin]}" >/dev/null 2>&1 && ok "$bin" || no "$bin" "go install failed"
  done
fi

# --- pipx → ~/.local/bin --------------------------------------------------------------
if RUN pipx && have pipx; then
  hdr "pipx tools → ~/.local/bin"
  declare -A PIPX=(
    [wafw00f]="wafw00f" [sslyze]="sslyze" [ssh-audit]="ssh-audit" [arjun]="arjun"
    [dirsearch]="dirsearch" [xsrfprobe]="XSRFProbe" [dnsrecon]="dnsrecon" [sublist3r]="Sublist3r"
    [wapiti]="wapiti3" [ghauri]="git+https://github.com/r0oth3x49/ghauri.git"
    [nxc]="git+https://github.com/Pennyw0rth/NetExec.git" [certipy]="certipy-ad"
    [lsassy]="lsassy" [bloodyAD]="bloodyAD" [mitm6]="mitm6" [coercer]="coercer"
    [impacket-secretsdump]="impacket" [s3scanner]="s3scanner" [smtp-user-enum]="smtp-user-enum"
    [ldapdomaindump]="ldapdomaindump" [droopescan]="droopescan" [git-dumper]="git-dumper"
    [paramspider]="git+https://github.com/devanshbatham/ParamSpider.git"
    [theHarvester]="git+https://github.com/laramies/theHarvester.git"
    [graphql-cop]="git+https://github.com/dolevf/graphql-cop.git"
  )
  for bin in "${!PIPX[@]}"; do
    have "$bin" && { ok "$bin (present)"; continue; }
    pipx install "${PIPX[$bin]}" >/dev/null 2>&1 && ok "$bin" || no "$bin" "pipx install failed"
  done
fi

# --- apt (Ubuntu universe; best-effort) -----------------------------------------------
if RUN apt; then
  hdr "apt tools"
  declare -A APT=(
    [exiftool]="libimage-exiftool-perl" [dirb]="dirb" [wfuzz]="wfuzz" [cewl]="cewl"
    [onesixtyone]="onesixtyone" [swaks]="swaks" [john]="john" [medusa]="medusa"
    [lynis]="lynis" [smbmap]="smbmap" [sqlmap]="sqlmap" [nikto]="nikto"
    [netdiscover]="netdiscover" [hashcat]="hashcat"
  )
  for bin in "${!APT[@]}"; do
    have "$bin" && { ok "$bin (present)"; continue; }
    sudo apt-get install -y -qq "${APT[$bin]}" >/dev/null 2>&1 && ok "$bin" || no "$bin" "not in your apt repos"
  done
fi

# --- gem -------------------------------------------------------------------------------
if RUN gem && have gem; then
  hdr "gem"
  have wpscan && ok "wpscan (present)" || { sudo gem install wpscan >/dev/null 2>&1 && ok "wpscan" || no "wpscan" "gem failed"; }
fi

# --- git-clone wrappers → /opt + /usr/local/bin ---------------------------------------
if RUN git; then
  hdr "git-clone tools → /opt"
  clone(){ # name repo interp entry
    local name="$1" repo="$2" interp="$3" entry="$4"
    have "$name" && { ok "$name (present)"; return; }
    [ -d "/opt/$name" ] || sudo git clone --depth 1 "$repo" "/opt/$name" >/dev/null 2>&1 || { no "$name" "clone failed"; return; }
    [ -f "/opt/$name/requirements.txt" ] && sudo pip3 install -q --break-system-packages -r "/opt/$name/requirements.txt" >/dev/null 2>&1
    printf '#!/usr/bin/env bash\nexec %s /opt/%s/%s "$@"\n' "$interp" "$name" "$entry" | sudo tee "/usr/local/bin/$name" >/dev/null
    sudo chmod +x "/usr/local/bin/$name" && ok "$name"
  }
  clone xsstrike   https://github.com/s0md3v/XSStrike.git        python3 xsstrike.py
  clone sstimap    https://github.com/vladko312/SSTImap.git      python3 sstimap.py
  clone corsy      https://github.com/s0md3v/Corsy.git           python3 corsy.py
  clone fuxploider https://github.com/almandin/fuxploider.git    python3 fuxploider.py
  clone shcheck    https://github.com/santoru/shcheck.git        python3 shcheck.py
  clone humble     https://github.com/rfc-st/humble.git          python3 humble.py
  clone jwt_tool   https://github.com/ticarpi/jwt_tool.git       python3 jwt_tool.py
  clone nosqlmap   https://github.com/codingo/NoSQLMap.git       python2 nosqlmap.py
  clone commix     https://github.com/commixproject/commix.git   python3 commix.py
  clone dotdotpwn  https://github.com/wireghoul/dotdotpwn.git     perl   dotdotpwn.pl
  clone cmseek     https://github.com/Tuhinshubhra/CMSeeK.git    python3 cmseek.py
  clone joomscan   https://github.com/OWASP/joomscan.git         perl   joomscan.pl
  clone linkfinder https://github.com/GerbenJavado/LinkFinder.git python3 linkfinder.py
  clone krbrelayx  https://github.com/dirkjanm/krbrelayx.git     python3 krbrelayx.py
fi

# --- single-file scripts → /usr/local/bin ---------------------------------------------
if RUN scripts; then
  hdr "single-file scripts"
  getf(){ have "$1" && { ok "$1 (present)"; return; }; sudo curl -sL -o "/usr/local/bin/$1" "$2" 2>/dev/null && sudo chmod +x "/usr/local/bin/$1" && ok "$1" || no "$1" "fetch failed"; }
  getf linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
  getf linux-exploit-suggester.sh https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh
fi

# --- SecLists --------------------------------------------------------------------------
if RUN seclists; then
  hdr "SecLists"
  [ -d /usr/share/seclists ] && ok "SecLists (present)" || { sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists >/dev/null 2>&1 && ok "SecLists" || no "SecLists" "clone failed"; }
fi

hdr "Done"
echo "Re-check:  python3 scripts/check_tools.py"
echo "If tools aren't found, restart your shell so ~/go/bin and ~/.local/bin are on PATH."
cat <<'NOTE'

Heavy / manual (install deliberately — large, or P3 'denied' in VAPT-AI so they never auto-run):
  Metasploit · BloodHound CE · Sliver · BeEF · Responder · bettercap · ettercap
NOTE
