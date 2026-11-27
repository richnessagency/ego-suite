#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}================================================${NC}"
echo -e "${YELLOW}   EGO Suite — Portable Linux Setup & Installer ${NC}"
echo -e "${YELLOW}================================================${NC}"

mkdir -p "$SCRIPT_DIR/bin" "$SCRIPT_DIR/data/reports" "$SCRIPT_DIR/.node_tools"

# 1. Python Virtual Environment
if [ ! -d "$SCRIPT_DIR/.venv" ]; then
  echo -e "${YELLOW}[1/5] Creating isolated Python .venv...${NC}"
  python3 -m venv "$SCRIPT_DIR/.venv"
fi

PIP="$SCRIPT_DIR/.venv/bin/pip"
"$PIP" install --upgrade pip --quiet || true

echo -e "${YELLOW}[2/5] Installing EGO Suite core dependencies...${NC}"
"$PIP" install -r "$SCRIPT_DIR/requirements.txt" --quiet

# 2. Portable Python Security Tools
echo -e "${YELLOW}[3/5] Installing Python security tools into .venv...${NC}"
for pkg in bandit pip-audit wapiti3 semgrep checkov; do
  if "$PIP" install "$pkg" --quiet 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} $pkg installed"
  else
    echo -e "  ${RED}!${NC} $pkg skipped (can be installed later via UI or Docker)"
  fi
done

# 3. Portable Node.js Tools
if command -v npm >/dev/null 2>&1; then
  echo -e "${YELLOW}[4/5] Installing Node.js security tools into .node_tools...${NC}"
  if npm install --prefix "$SCRIPT_DIR/.node_tools" retire eslint eslint-plugin-security --silent 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} retire & eslint-plugin-security installed"
  else
    echo -e "  ${RED}!${NC} Node tools skipped"
  fi
fi

# 4. Portable CLI / Git / Binary Tools into ./bin
echo -e "${YELLOW}[5/6] Setting up portable CLI & binary tools in ./bin...${NC}"
if [ ! -d "$SCRIPT_DIR/bin/testssl.sh" ] && command -v git >/dev/null 2>&1; then
  if git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$SCRIPT_DIR/bin/testssl.sh" --quiet 2>/dev/null; then
    chmod +x "$SCRIPT_DIR/bin/testssl.sh/testssl.sh"
    echo -e "  ${GREEN}✓${NC} testssl.sh cloned"
  fi
fi

if [ ! -d "$SCRIPT_DIR/bin/nikto" ] && command -v git >/dev/null 2>&1; then
  if git clone --depth 1 https://github.com/sullo/nikto.git "$SCRIPT_DIR/bin/nikto" --quiet 2>/dev/null; then
    chmod +x "$SCRIPT_DIR/bin/nikto/program/nikto.pl"
    echo -e "  ${GREEN}✓${NC} nikto cloned"
  fi
fi

ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ] && command -v curl >/dev/null 2>&1; then
  download_gh_asset() {
    local repo="$1" pattern="$2" bin_name="$3"
    if [ -x "$SCRIPT_DIR/bin/$bin_name" ]; then
      echo -e "  ${GREEN}✓${NC} $bin_name already present"
      return 0
    fi
    local url
    url="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | grep -oE "https://[^\"]+$pattern" | head -n1 || true)"
    if [ -z "$url" ]; then
      echo -e "  ${RED}!${NC} $bin_name release URL not found"
      return 1
    fi
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    if curl -fsSL "$url" -o "$tmp_dir/pkg"; then
      case "$url" in
        *.tar.gz|*.tgz) tar -xzf "$tmp_dir/pkg" -C "$tmp_dir" && find "$tmp_dir" -type f -name "$bin_name" -exec mv {} "$SCRIPT_DIR/bin/$bin_name" \; ;;
        *.zip) python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$tmp_dir/pkg" "$tmp_dir" && find "$tmp_dir" -type f -name "$bin_name" -exec mv {} "$SCRIPT_DIR/bin/$bin_name" \; ;;
        *) mv "$tmp_dir/pkg" "$SCRIPT_DIR/bin/$bin_name" ;;
      esac
      if [ -f "$SCRIPT_DIR/bin/$bin_name" ]; then
        chmod +x "$SCRIPT_DIR/bin/$bin_name"
        echo -e "  ${GREEN}✓${NC} $bin_name installed"
      fi
    fi
    rm -rf "$tmp_dir"
  }

  download_gh_asset "projectdiscovery/nuclei" "linux_amd64\.zip" "nuclei" || true
  download_gh_asset "projectdiscovery/httpx" "linux_amd64\.zip" "httpx" || true
  download_gh_asset "aquasecurity/trivy" "Linux-64bit\.tar\.gz" "trivy" || true
  download_gh_asset "gitleaks/gitleaks" "linux_x64\.tar\.gz" "gitleaks" || true
  download_gh_asset "google/osv-scanner" "linux_amd64" "osv-scanner" || true
  download_gh_asset "trufflesecurity/trufflehog" "linux_amd64\.tar\.gz" "trufflehog" || true

  if [ ! -x "$SCRIPT_DIR/bin/bearer" ]; then
    if curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b "$SCRIPT_DIR/bin" >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${NC} bearer installed"
    fi
  else
    echo -e "  ${GREEN}✓${NC} bearer already present"
  fi
fi

# 5. Docker images for container-based tools
if command -v docker >/dev/null 2>&1; then
  echo -e "${YELLOW}[6/6] Pulling Docker images for container tools...${NC}"
  for img in "ghcr.io/zaproxy/zaproxy:stable" "trufflesecurity/trufflehog:latest" "sonarqube:community"; do
    if docker image inspect "$img" >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${NC} $img already present"
    elif docker pull "$img" >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${NC} $img pulled"
    else
      echo -e "  ${RED}!${NC} $img pull failed (check Docker daemon/permissions)"
    fi
  done
fi

# 5. Global launcher symlink (~/.local/bin/ego) & Desktop Entry
chmod +x "$SCRIPT_DIR/ego" "$SCRIPT_DIR/ego-setup.sh"
mkdir -p "$HOME/.local/bin" "$HOME/.local/share/applications"
ln -sf "$SCRIPT_DIR/ego" "$HOME/.local/bin/ego"

cat > "$HOME/.local/share/applications/ego-suite.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=EGO Suite
GenericName=Security Auditing Suite
Comment=Unified Local & Web Security Auditing Platform
Exec=$HOME/.local/bin/ego --open
Icon=$SCRIPT_DIR/EGOicon.png
Terminal=false
Categories=Development;Security;Utility;
Keywords=security;ego;scanner;pentest;audit;
StartupNotify=true
EOF
chmod +x "$HOME/.local/share/applications/ego-suite.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN} EGO Suite installed successfully!${NC}"
echo -e " Run: ${YELLOW}./ego${NC} (or ${YELLOW}ego${NC}) to start on http://127.0.0.1:8787"
echo -e "${GREEN}================================================${NC}"

