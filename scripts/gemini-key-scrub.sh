#!/usr/bin/env bash
#
# gemini-key-scrub.sh
#
# General-purpose Linux utility to FIND and optionally REMOVE references to
# Google Gemini API keys and related configuration.
#
# Searches common locations where API keys and env vars persist on Linux:
#   - Current environment and shell startup files
#   - .env files and dotfiles under $HOME
#   - System-wide env (/etc/environment, /etc/profile.d/)
#   - Shell history
#   - Docker containers, compose files, and images metadata
#   - systemd units and drop-ins
#   - cron jobs
#   - Running process environments (/proc)
#
# DEFAULT: dry-run (report only). Use --execute to apply changes.
#
# Usage:
#   ./gemini-key-scrub.sh                  # scan, report only
#   ./gemini-key-scrub.sh --execute        # scan and remove (with confirmation)
#   ./gemini-key-scrub.sh --execute -y     # scan and remove (no confirmation)
#   ./gemini-key-scrub.sh --home /path     # scan a specific home directory
#   ./gemini-key-scrub.sh --log /tmp/scrub.log
#
# Exit codes:
#   0  success (nothing found, or cleanup completed)
#   1  error (bad args, permission failure)
#   2  findings reported in dry-run mode
#   3  user aborted confirmation
#
# IMPORTANT:
#   - Revoke/delete the key at https://aistudio.google.com/apikey after scrubbing.
#   - Review backups in $BACKUP_DIR before deleting them.
#   - This script edits text files; it does not guarantee zero traces in
#     binary logs, cloud backups, or third-party tools.
#
set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly VERSION="1.0.0"

# Patterns matched case-insensitively during search and line removal.
readonly -a SEARCH_PATTERNS=(
  'GEMINI_API_KEY'
  'GOOGLE_API_KEY'
  'GOOGLE_GENAI_API_KEY'
  'GOOGLE_AI_API_KEY'
  'GEMINI_KEY'
  'langchain_google'
  'google.generativeai'
  'generativeai'
  'ChatGoogleGenerativeAI'
  'aistudio\.google\.com'
  'generativelanguage\.googleapis\.com'
)

readonly -a ENV_FILENAMES=(
  '.env'
  '.env.local'
  '.env.production'
  '.env.development'
  '.envrc'
)

readonly -a ENV_VAR_NAMES=(
  GEMINI_API_KEY
  GOOGLE_API_KEY
  GOOGLE_GENAI_API_KEY
  GOOGLE_AI_API_KEY
  GEMINI_KEY
)

EXECUTE=false
ASSUME_YES=false
SCAN_HOME="${HOME:-/root}"
LOG_FILE=""
BACKUP_DIR=""
FOUND_COUNT=0

EGREP_PATTERN="$(
  IFS='|'
  echo "${SEARCH_PATTERNS[*]}"
)"

log() {
  local level="$1"
  shift
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
  echo "$msg" >&2
  if [[ -n "$LOG_FILE" ]]; then
    echo "$msg" >> "$LOG_FILE"
  fi
}

log_info()   { log "INFO"   "$@"; }
log_warn()   { log "WARN"   "$@"; }
log_action() { log "ACTION" "$@"; }
log_found()  { log "FOUND"  "$@"; FOUND_COUNT=$((FOUND_COUNT + 1)); }

usage() {
  cat <<EOF
${SCRIPT_NAME} v${VERSION} — find and remove Gemini API key references on Linux

Options:
  --execute          Apply removals (default is dry-run)
  -y, --yes          Skip confirmation prompt (requires --execute)
  --home PATH        Home directory to scan (default: \$HOME)
  --log FILE         Append detailed log to FILE
  --backup-dir DIR   Store file backups here
                     (default: /tmp/gemini-scrub-backup-TIMESTAMP)
  -h, --help         Show this help

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} --execute
  ${SCRIPT_NAME} --execute -y --home /home/deploy
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --execute) EXECUTE=true ;;
      -y|--yes) ASSUME_YES=true ;;
      --home)
        shift
        SCAN_HOME="${1:?--home requires a path}"
        ;;
      --log)
        shift
        LOG_FILE="${1:?--log requires a path}"
        ;;
      --backup-dir)
        shift
        BACKUP_DIR="${1:?--backup-dir requires a path}"
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log_warn "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
    shift
  done

  BACKUP_DIR="${BACKUP_DIR:-/tmp/gemini-scrub-backup-$(date +%Y%m%d%H%M%S)}"
}

is_text_file() {
  local f="$1"
  [[ -f "$f" && -r "$f" ]] || return 1
  file -b --mime-type "$f" 2>/dev/null | grep -qE 'text/|application/json|application/x-shellscript|application/xml|empty' \
    || head -c 512 "$f" 2>/dev/null | grep -qI .
}

backup_file() {
  local src="$1"
  local dest_dir="${BACKUP_DIR}/$(dirname "$src" | tr '/' '_')"
  mkdir -p "$dest_dir"
  cp -a "$src" "${dest_dir}/$(basename "$src").bak"
  log_action "Backed up: $src -> ${dest_dir}/"
}

sed_inplace() {
  local expression="$1"
  local file="$2"
  if sed --version >/dev/null 2>&1; then
    sed -i "$expression" "$file"
  else
    sed -i '' "$expression" "$file"
  fi
}

scrub_file_lines() {
  local file="$1"
  local label="$2"

  [[ -f "$file" ]] || return 0
  is_text_file "$file" || {
    log_warn "Skipping non-text: $file"
    return 0
  }

  if grep -qiE "$EGREP_PATTERN" "$file" 2>/dev/null; then
    log_found "$label: $file"
    grep -niE "$EGREP_PATTERN" "$file" 2>/dev/null | while IFS= read -r line; do
      log_info "  match: $line"
    done

    if $EXECUTE; then
      backup_file "$file"
      sed_inplace "/${EGREP_PATTERN}/Id" "$file"
      log_action "Scrubbed lines from: $file"
    fi
  fi
}

scrub_current_env() {
  local var
  for var in "${ENV_VAR_NAMES[@]}"; do
    if [[ -n "${!var:-}" ]]; then
      log_found "Environment variable set in current shell: $var"
      if $EXECUTE; then
        unset "$var"
        log_action "Unset $var in current shell (session only)"
      fi
    fi
  done
}

section_header() {
  echo ""
  log_info "========== $1 =========="
}

scan_current_environment() {
  section_header "Current shell environment"
  scrub_current_env
  env 2>/dev/null | grep -iE "$EGREP_PATTERN" | while IFS= read -r line; do
    log_found "env output: $line"
  done || true
}

scan_shell_configs() {
  section_header "Shell startup files"
  local files=(
    "${SCAN_HOME}/.bashrc"
    "${SCAN_HOME}/.bash_profile"
    "${SCAN_HOME}/.profile"
    "${SCAN_HOME}/.zshrc"
    "${SCAN_HOME}/.zshenv"
    "${SCAN_HOME}/.config/fish/config.fish"
    "/etc/profile"
    "/etc/bash.bashrc"
  )
  local f
  for f in "${files[@]}"; do
    scrub_file_lines "$f" "shell config"
  done

  for f in /etc/profile.d/*.sh; do
    [[ -f "$f" ]] && scrub_file_lines "$f" "profile.d"
  done
}

scan_system_env() {
  section_header "System-wide environment files"
  scrub_file_lines "/etc/environment" "system env"
  scrub_file_lines "/etc/default/locale" "system default"

  local f
  for f in /etc/default/*; do
    [[ -f "$f" ]] && scrub_file_lines "$f" "etc/default"
  done
}

scan_dotenv_files() {
  section_header ".env and dotenv files"
  local name
  for name in "${ENV_FILENAMES[@]}"; do
    find "$SCAN_HOME" -maxdepth 6 -name "$name" -type f 2>/dev/null | while IFS= read -r f; do
      scrub_file_lines "$f" ".env file"
    done
  done
}

scan_home_configs() {
  section_header "Config files under $SCAN_HOME (depth <= 5)"
  find "$SCAN_HOME" -maxdepth 5 \
    \( -name '*.env' -o -name '*.yml' -o -name '*.yaml' -o -name 'docker-compose*.yml' \
       -o -name '*.sh' -o -name '*.json' -o -name '*.toml' -o -name '*.ini' \
       -o -name '*.service' -o -name '*.conf' \) \
    -type f 2>/dev/null | while IFS= read -r f; do
      scrub_file_lines "$f" "config"
    done
}

scan_shell_history() {
  section_header "Shell history"
  local hist_files=(
    "${SCAN_HOME}/.bash_history"
    "${SCAN_HOME}/.zsh_history"
    "${SCAN_HOME}/.history"
  )
  local f
  for f in "${hist_files[@]}"; do
    scrub_file_lines "$f" "shell history"
  done
}

scan_docker() {
  section_header "Docker"
  if ! command -v docker >/dev/null 2>&1; then
    log_info "docker not installed; skipping"
    return
  fi

  find "$SCAN_HOME" -maxdepth 6 -name 'docker-compose*.yml' -type f 2>/dev/null | while IFS= read -r f; do
    scrub_file_lines "$f" "docker-compose"
  done

  local cid
  for cid in $(docker ps -aq 2>/dev/null); do
    if docker inspect "$cid" 2>/dev/null | grep -qiE "$EGREP_PATTERN"; then
      log_found "Docker container $cid has Gemini-related env/config"
      log_info "  name: $(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null)"
      if $EXECUTE; then
        log_warn "  Cannot edit in-container env in place. Recreate container without GEMINI vars."
        log_warn "  Consider: docker rm -f $cid && rebuild with updated compose/env"
      fi
    fi
  done

  if [[ -f "${SCAN_HOME}/.docker/.env" ]]; then
    scrub_file_lines "${SCAN_HOME}/.docker/.env" "docker .env"
  fi
}

scan_systemd() {
  section_header "systemd units"
  local dirs=(
    "/etc/systemd/system"
    "${SCAN_HOME}/.config/systemd/user"
  )
  local dir
  for dir in "${dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    find "$dir" -type f \( -name '*.service' -o -name '*.conf' -o -name '*.env' \) 2>/dev/null | while IFS= read -r f; do
      scrub_file_lines "$f" "systemd"
    done
  done
}

scan_cron() {
  section_header "cron"
  local tmp
  tmp="$(mktemp)"
  crontab -l 2>/dev/null > "$tmp" || true
  if [[ -s "$tmp" ]] && grep -qiE "$EGREP_PATTERN" "$tmp"; then
    log_found "User crontab contains Gemini references"
    if $EXECUTE; then
      backup_file "$tmp"
      grep -viE "$EGREP_PATTERN" "$tmp" | crontab -
      log_action "Scrubbed user crontab"
    fi
  fi
  rm -f "$tmp"

  local f
  for f in /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/*; do
    [[ -f "$f" ]] && scrub_file_lines "$f" "cron file"
  done
}

scan_proc_environ() {
  section_header "Running process environments (/proc)"
  local pid_dir pid cmdline
  for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir#/proc/}"
    [[ -r "/proc/$pid/environ" ]] || continue
    if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -qiE "$EGREP_PATTERN"; then
      cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo '?')"
      log_found "PID $pid has Gemini env: $cmdline"
      log_warn "  Restart this process after scrubbing its config/source"
    fi
  done
}

scan_known_tools() {
  section_header "Known secret stores (report only)"
  local paths=(
    "${SCAN_HOME}/.config/gcloud"
    "${SCAN_HOME}/.aws/credentials"
  )
  local p
  for p in "${paths[@]}"; do
    [[ -d "$p" ]] || continue
    if grep -rqiE "$EGREP_PATTERN" "$p" 2>/dev/null; then
      log_found "Possible match in: $p (manual review required)"
    fi
  done
}

confirm_execute() {
  if ! $EXECUTE; then
    return
  fi
  if $ASSUME_YES; then
    return
  fi

  echo ""
  log_warn "EXECUTE mode will modify files. Backups -> $BACKUP_DIR"
  read -r -p "Proceed with removal? [y/N] " ans
  case "${ans,,}" in
    y|yes) ;;
    *)
      log_info "Aborted."
      exit 3
      ;;
  esac
}

print_summary() {
  echo ""
  log_info "========== Summary =========="
  if [[ "$FOUND_COUNT" -eq 0 ]]; then
    log_info "No Gemini-related references found."
  else
    log_info "Findings: $FOUND_COUNT"
    if ! $EXECUTE; then
      log_info "Dry-run only. Re-run with --execute to apply removals."
    else
      log_info "Removals applied. Backups: $BACKUP_DIR"
      log_warn "Revoke the key at https://aistudio.google.com/apikey"
      log_warn "Restart affected services/containers/shells."
    fi
  fi
}

main() {
  parse_args "$@"

  log_info "Starting ${SCRIPT_NAME} v${VERSION}"
  log_info "Mode: $( $EXECUTE && echo EXECUTE || echo DRY-RUN )"
  log_info "Scan home: $SCAN_HOME"
  if [[ -n "$LOG_FILE" ]]; then
    log_info "Log file: $LOG_FILE"
  fi

  confirm_execute

  scan_current_environment
  scan_shell_configs
  scan_system_env
  scan_dotenv_files
  scan_home_configs
  scan_shell_history
  scan_docker
  scan_systemd
  scan_cron
  scan_proc_environ
  scan_known_tools

  print_summary

  if [[ "$FOUND_COUNT" -gt 0 ]] && ! $EXECUTE; then
    exit 2
  fi
  exit 0
}

main "$@"
