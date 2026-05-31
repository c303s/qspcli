#!/usr/bin/env bash
# Installer for Linux/Mac
# Downloads the project from GitHub, creates a launcher, and starts the tool.
#
# Usage:
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/c303s/qspcli/main/install.sh)"

set -euo pipefail

APP_NAME="qspcli"
SCRIPT_NAME="qspcli.py"
REPO_SLUG="${QSPCLI_REPO:-c303s/qspcli}"
REPO_BRANCH="${QSPCLI_BRANCH:-main}"
INSTALL_DIR="${QSPCLI_INSTALL_DIR:-$(pwd -P)}"
LAUNCHER_PATH="$INSTALL_DIR/$APP_NAME"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/${APP_NAME}.XXXXXX")"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: '$1' is required to install $APP_NAME." >&2
    exit 1
  fi
}

print_step() {
  echo "==> $1"
}

download_source() {
  if [[ -n "${QSPCLI_SOURCE_DIR:-}" ]]; then
    SOURCE_DIR="$QSPCLI_SOURCE_DIR"
    if [[ ! -f "$SOURCE_DIR/$SCRIPT_NAME" ]]; then
      echo "Error: QSPCLI_SOURCE_DIR does not contain $SCRIPT_NAME." >&2
      exit 1
    fi
    return
  fi

  need_command curl
  need_command tar

  local archive="$WORK_DIR/source.tar.gz"
  local repo_url="https://github.com/$REPO_SLUG/archive/refs/heads/$REPO_BRANCH.tar.gz"

  print_step "Downloading $APP_NAME from GitHub ($REPO_SLUG@$REPO_BRANCH)"
  curl -fsSL "$repo_url" -o "$archive"
  tar -xzf "$archive" -C "$WORK_DIR"

  SOURCE_DIR="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "$SOURCE_DIR" || ! -f "$SOURCE_DIR/$SCRIPT_NAME" ]]; then
    echo "Error: Could not unpack application files from the archive." >&2
    exit 1
  fi
}

create_launcher() {
  cat > "$LAUNCHER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$INSTALL_DIR"
exec python3 "$INSTALL_DIR/$SCRIPT_NAME" "\$@"
EOF
  chmod 755 "$LAUNCHER_PATH"
}

install_files() {
  local env_backup="$WORK_DIR/.env.bak"

  mkdir -p "$INSTALL_DIR"

  # Preserve existing .env so credentials survive a reinstall.
  if [[ -f "$INSTALL_DIR/.env" ]]; then
    cp "$INSTALL_DIR/.env" "$env_backup"
  fi

  for f in "$SCRIPT_NAME" "README.md" "install.sh" ".gitignore"; do
    if [[ -f "$SOURCE_DIR/$f" ]]; then
      cp "$SOURCE_DIR/$f" "$INSTALL_DIR/$f"
    fi
  done

  chmod 755 "$INSTALL_DIR/$SCRIPT_NAME"
  [[ -f "$INSTALL_DIR/install.sh" ]] && chmod 755 "$INSTALL_DIR/install.sh"

  # Restore credentials.
  if [[ -f "$env_backup" ]]; then
    cp "$env_backup" "$INSTALL_DIR/.env"
  fi

  create_launcher
}

launch_application() {
  if [[ "${QSPCLI_SKIP_LAUNCH:-0}" == "1" ]]; then
    print_step "Installation complete"
    echo "Run './$APP_NAME' from $INSTALL_DIR to start QSPCLI."
    return
  fi

  print_step "Starting QSPCLI"
  exec "$LAUNCHER_PATH"
}

main() {
  need_command python3
  download_source
  install_files
  launch_application
}

main "$@"
