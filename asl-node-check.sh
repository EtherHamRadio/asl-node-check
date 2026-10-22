#!/usr/bin/env bash
# asl-node-check.sh — a plain-language security check for AllStarLink 3 nodes
# Version 1.1 (October 22, 2026)
# https://github.com/EtherHamRadio/asl-node-check
# MIT License. Copyright (c) 2026 Tom Salzer, KJ7T
#
# What it does: looks at your node and reports, in plain language, anything
# that needs attention: missing security updates (including the October 2026
# "PHP2Shell" fix), services still running old code, end-of-life systems,
# and a few common settings worth a second look.
#
# What it does NOT do: it doesn't install, remove, or change anything. The only
# thing it touches is the list of available updates (it runs "apt-get update"
# so its answers are current). Skip that with:  sudo bash asl-node-check.sh --no-refresh
#
# Run it with:  sudo bash asl-node-check.sh
#
# The report does not print passwords, IP addresses, or MAC addresses, so it's
# reasonably safe to share when asking for help. Read it over first anyway.

VERSION="1.1"

# PHP releases that fix CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell").
# Branches not listed here (7.x, 8.0, 8.1) have no packaged fix on Debian.
declare -A PHP_FIXED=( ["8.2"]="8.2.35" ["8.3"]="8.3.36" ["8.4"]="8.4.27" ["8.5"]="8.5.12" )
PHP_CVE="CVE-2026-109618"

REFRESH=1
for arg in "$@"; do
  case "$arg" in
    --no-refresh) REFRESH=0 ;;
    --version) echo "asl-node-check $VERSION"; exit 0 ;;
    -h|--help)
      echo "Usage: sudo bash asl-node-check.sh [--no-refresh]"
      echo "  --no-refresh   don't run apt-get update first (uses the last downloaded list)"
      exit 0 ;;
    *) echo "Unknown option: $arg (try --help)"; exit 2 ;;
  esac
done

# ---------- output helpers ----------
if [ -t 1 ]; then
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_BAD=$'\e[31m'; C_INFO=$'\e[36m'; C_B=$'\e[1m'; C_0=$'\e[0m'
else
  C_OK=""; C_WARN=""; C_BAD=""; C_INFO=""; C_B=""; C_0=""
fi
N_OK=0; N_WARN=0; N_BAD=0
ok()   { echo "  ${C_OK}[ OK ]${C_0} $1"; N_OK=$((N_OK+1)); }
# todo: first line is "What to do:"; any line starting with "$ " is a command, shown on its own line
todo() {
  local first=1 line
  for line in "$@"; do
    if [ "${line:0:2}" = '$ ' ]; then echo "             ${line:2}"
    elif [ "$first" -eq 1 ]; then echo "         What to do: $line"
    else echo "         $line"; fi
    first=0
  done
}
warn() { echo "  ${C_WARN}[WARN]${C_0} $1"; shift; [ "$#" -gt 0 ] && todo "$@"; N_WARN=$((N_WARN+1)); }
bad()  { echo "  ${C_BAD}[FIX ]${C_0} $1"; shift; [ "$#" -gt 0 ] && todo "$@"; N_BAD=$((N_BAD+1)); }
info() { echo "  ${C_INFO}[info]${C_0} $1"; }
section() { echo; echo "${C_B}$1${C_0}"; }

is_root() { [ "$(id -u)" -eq 0 ]; }
have() { command -v "$1" >/dev/null 2>&1; }
pkg_installed() { dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^ii'; }
upstream_ver() { local v=${1#*:}; echo "${v%%-*}"; }   # strip epoch and Debian revision

# Seconds since epoch when a package was last installed or upgraded
pkg_changed_at() { stat -c %Y "/var/lib/dpkg/info/$1.list" 2>/dev/null || echo 0; }
# Seconds since epoch when a systemd service last started (0 if not running)
svc_started_at() {
  local ts; ts=$(systemctl show -p ActiveEnterTimestamp --value "$1" 2>/dev/null)
  [ -n "$ts" ] && date -d "$ts" +%s 2>/dev/null || echo 0
}
svc_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

echo "${C_B}AllStarLink node security check, version $VERSION${C_0}"
echo "Run on $(date '+%Y-%m-%d %H:%M %Z'). This script doesn't change your node's settings."

if ! is_root; then
  echo
  echo "${C_WARN}Note:${C_0} you're not running this as root, so some checks will be skipped."
  echo "For the full report, run it again with:  sudo bash $0"
fi

# ---------- 1. Operating system ----------
section "1. Operating system"
OS_CODENAME=""; OS_PRETTY=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_CODENAME="$VERSION_CODENAME"; OS_PRETTY="$PRETTY_NAME"
fi

if [ -f /etc/arch-release ] || have pacman; then
  bad "This looks like HamVoIP or another Arch Linux-based system." \
      "HamVoIP's base system rarely gets security updates, and this script can't check it. Plan a move to AllStarLink 3 (ASL3). Your radio hardware, including a SHARI, stays the same."
  echo; echo "Stopping here: the remaining checks are for Debian-based ASL3 systems."
  exit 1
fi

if ! have dpkg; then
  bad "This doesn't look like a Debian-based system, so this script can't check it." \
      "This script is written for AllStarLink 3, which runs on Debian 12 or 13 (including Raspberry Pi OS)."
  exit 1
fi

case "$OS_CODENAME" in
  trixie)   ok "$OS_PRETTY: current Debian release, receiving security updates." ;;
  bookworm) ok "$OS_PRETTY: still receiving security updates (long-term support runs until mid-2028)." ;;
  bullseye) bad "$OS_PRETTY: Debian 11 has reached end of life and won't get the PHP fix." \
                "Reinstall with a current ASL3 image (Debian 13). Back up your settings in /etc/asterisk first." ;;
  buster|stretch|jessie) bad "$OS_PRETTY: this Debian release stopped getting security updates years ago." \
                "Reinstall with a current ASL3 image (Debian 13). Back up your settings in /etc/asterisk first." ;;
  *) warn "Unrecognized system ($OS_PRETTY). The checks below may not all apply." \
          "AllStarLink 3 officially supports Debian 12 and 13." ;;
esac

if [ -f /var/run/reboot-required ]; then
  warn "A restart is waiting to finish an earlier update." "Restart the node with:" '$ sudo reboot'
else
  ok "No restart is waiting from earlier updates."
fi

# ---------- 2. Updates ----------
section "2. Updates"
if [ "$REFRESH" -eq 1 ] && is_root; then
  echo "  Checking for new updates (this can take a minute)..."
  if apt-get update -qq >/dev/null 2>&1; then
    ok "Downloaded the latest list of available updates."
  else
    warn "Couldn't download the latest update list." \
         "Check the node's internet connection, then run:" '$ sudo apt update'
  fi
else
  LISTS_AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0) ) / 86400 ))
  info "Using the update list from $LISTS_AGE_DAYS day(s) ago (not refreshed)."
fi

UPGRADABLE=$(apt list --upgradable 2>/dev/null | grep -c 'upgradable from')
SEC_UPGRADABLE=$(apt list --upgradable 2>/dev/null | grep 'upgradable from' | grep -c -- '-security')
if [ "$UPGRADABLE" -eq 0 ]; then
  if [ "$REFRESH" -eq 1 ] && is_root; then
    ok "All installed software is up to date."
  else
    info "No updates were waiting as of that list. Run:  sudo apt update   to check for newer ones."
  fi
elif [ "$SEC_UPGRADABLE" -gt 0 ]; then
  bad "$UPGRADABLE update(s) waiting, including $SEC_UPGRADABLE security update(s)." \
      "Install the updates, then restart:" '$ sudo apt update && sudo apt upgrade' '$ sudo reboot'
else
  warn "$UPGRADABLE update(s) waiting (none marked as security updates)." \
       "When convenient, run:" '$ sudo apt update && sudo apt upgrade'
fi

if pkg_installed unattended-upgrades && \
   apt-config dump 2>/dev/null | grep -q 'APT::Periodic::Unattended-Upgrade "1"'; then
  ok "Automatic security updates are turned on."
else
  warn "Automatic security updates are not turned on." \
       "Run these two commands, and answer Yes when asked:" '$ sudo apt install unattended-upgrades' '$ sudo dpkg-reconfigure -plow unattended-upgrades'
fi

# ---------- 3. PHP (web dashboards) ----------
section "3. PHP and your web dashboards"

DASHES=()
[ -d /var/www/html/supermon ]   && DASHES+=("Supermon")
[ -d /var/www/html/supermon2 ]  && DASHES+=("Supermon 2")
[ -d /var/www/html/allscan ]    && DASHES+=("AllScan")
[ -d /var/www/html/allmon2 ]    && DASHES+=("Allmon2")
{ [ -d /etc/allmon3 ] || pkg_installed allmon3; } && DASHES+=("Allmon3")
if [ "${#DASHES[@]}" -gt 0 ]; then
  DLIST=$(printf '%s, ' "${DASHES[@]}"); info "Dashboards found: ${DLIST%, }."
fi

PHP_LINES=$(dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' 'php*-common' 2>/dev/null \
            | awk -F'\t' '$1 ~ /^php[0-9]+\.[0-9]+-common$/ && $3 ~ /^ii/ {print $1"\t"$2}')

if [ -z "$PHP_LINES" ]; then
  ok "PHP isn't installed, so the October 2026 PHP flaws (PHP2Shell) don't apply."
else
  while IFS=$'\t' read -r pkg ver; do
    branch=${pkg#php}; branch=${branch%-common}
    up=$(upstream_ver "$ver")
    fixed=${PHP_FIXED[$branch]}
    cl="/usr/share/doc/php$branch-common/changelog.Debian.gz"
    if [ -n "$fixed" ] && dpkg --compare-versions "$up" ge "$fixed"; then
      ok "PHP $branch is version $up, which includes the PHP2Shell fix."
    elif [ -r "$cl" ] && zgrep -q "$PHP_CVE" "$cl" 2>/dev/null; then
      ok "PHP $branch ($up) includes the PHP2Shell fix (confirmed in its changelog)."
    elif [ -n "$fixed" ]; then
      bad "PHP $branch is version $up. The PHP2Shell fix arrived in $fixed." \
          "Install the updates, then restart:" '$ sudo apt update && sudo apt upgrade' '$ sudo reboot'
    else
      bad "PHP $branch is too old to receive the PHP2Shell fix from Debian." \
          "Move to a current ASL3 image (Debian 13), or remove PHP if no dashboard needs it."
    fi

    # Is the web server still running the old PHP from before the update?
    for svc in "php$branch-fpm" apache2; do
      svc_active "$svc" || continue
      case "$svc" in
        apache2) pkg_installed "libapache2-mod-php$branch" || continue; srcpkg="libapache2-mod-php$branch" ;;
        *) srcpkg="php$branch-fpm" ;;
      esac
      started=$(svc_started_at "$svc"); changed=$(pkg_changed_at "$srcpkg")
      if [ "$started" -gt 0 ] && [ "$changed" -gt "$started" ]; then
        bad "$svc has been running since before PHP was last updated, so it may still be using the old code." \
            "Restart it (or restart the whole node with: sudo reboot):" "\$ sudo systemctl restart $svc"
      else
        ok "$svc is running the currently installed PHP."
      fi
    done
  done <<< "$PHP_LINES"
fi

# ---------- 4. Exposure to the internet ----------
section "4. Exposure to the internet"

PUBLIC_V4=0
while read -r addr; do
  ip4=${addr%/*}
  case "$ip4" in
    10.*|127.*|169.254.*|192.168.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
    *) PUBLIC_V4=1 ;;
  esac
done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}')

WEB_LISTEN=0
if have ss && ss -Hltn 2>/dev/null | awk '{print $4}' | grep -Eq '[:.](80|443)$'; then WEB_LISTEN=1; fi

if [ "$PUBLIC_V4" -eq 1 ]; then
  info "This node has a public internet address (for example, a rented server or a 44Net address)."
  if [ "$WEB_LISTEN" -eq 1 ]; then
    warn "Its web dashboard is reachable from the whole internet unless a firewall blocks it." \
         "Make sure the dashboard is password-protected and kept up to date, and consider limiting who can reach it."
  fi
else
  info "This node uses a private (home network) address."
  if [ "$WEB_LISTEN" -eq 1 ]; then
    info "Its web dashboard is reachable on your home network. This script can't see your router."
    echo "         Check your router: if it forwards port 80 or 443 to this node, the dashboard is on the open internet."
    echo "         For access from away, a VPN such as Tailscale or WireGuard is safer than a port forward."
  fi
fi

FW=""
if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then FW="ufw"
elif svc_active firewalld; then FW="firewalld"
elif is_root && have nft && [ "$(nft list ruleset 2>/dev/null | grep -c 'hook input')" -gt 0 ]; then FW="nftables"
fi
if [ -n "$FW" ]; then
  ok "A firewall is active ($FW)."
elif ! is_root; then
  info "Firewall status needs root to check."
elif [ "$PUBLIC_V4" -eq 1 ]; then
  bad "No firewall is active, and this node has a public address." \
      "Set one up that allows only SSH and the ports your node needs. Allow SSH first, or you'll lock yourself out."
else
  info "No firewall is active on the node. Behind a home router that's common, but a firewall adds a layer."
fi

if svc_active fail2ban; then
  ok "fail2ban is running (it blocks addresses that keep failing to log in)."
elif [ "$PUBLIC_V4" -eq 1 ]; then
  warn "fail2ban isn't running." "Install it with:" '$ sudo apt install fail2ban'
else
  info "fail2ban isn't running. It's most useful on nodes reachable from the internet."
fi

# ---------- 5. Logins ----------
section "5. Logins"
if is_root && have sshd; then
  SSHD=$(sshd -T 2>/dev/null)
  if echo "$SSHD" | grep -qi '^permitrootlogin yes'; then
    warn "SSH allows logging in directly as root with a password." \
         "Log in as your regular user and use sudo instead. Set PermitRootLogin to no in /etc/ssh/sshd_config."
  else
    ok "SSH doesn't allow direct root logins with a password."
  fi
  if echo "$SSHD" | grep -qi '^passwordauthentication yes'; then
    if [ "$PUBLIC_V4" -eq 1 ]; then
      warn "SSH accepts passwords, and this node has a public address." \
           "Use SSH keys instead, then turn off password logins. At minimum, use a long, unique password."
    else
      info "SSH accepts passwords. That's fine at home with a strong, unique password; SSH keys are better."
    fi
  else
    ok "SSH only accepts keys, not passwords."
  fi
elif svc_active ssh; then
  info "SSH settings need root to check."
else
  info "SSH isn't running."
fi

# ---------- Summary ----------
echo
echo "${C_B}Summary${C_0}"
echo "  ${C_OK}$N_OK OK${C_0}, ${C_WARN}$N_WARN worth a look${C_0}, ${C_BAD}$N_BAD to fix${C_0}"
if [ "$N_BAD" -gt 0 ]; then
  echo "  Start with the [FIX ] items. Each one says what to do."
elif [ "$N_WARN" -gt 0 ]; then
  echo "  Nothing urgent. The [WARN] items are worth a look when you have time."
else
  echo "  Nothing needs attention right now. Run this again after the next security news."
fi
echo "  Reminder: this script can't see your router, your passwords, or your accounts."
[ "$N_BAD" -gt 0 ] && exit 1 || exit 0
