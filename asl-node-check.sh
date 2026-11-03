#!/usr/bin/env bash
# asl-node-check.sh — a plain-language security check for AllStarLink 3 nodes
#
# FOR ASL3 NODES ONLY. Not for HamVoIP or ASL2 nodes: it checks for ASL3 and
# stops on anything else.
# Version 2.0 (November 3, 2026)
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
# Optional: if it finds waiting updates or services running old code, it offers
# to download and run the separate update script, asl-node-update.sh. Each
# question's answer is no unless you type y, and answering no changes nothing.
# If you say yes, it saves one small file, /var/lib/asl-node-check/findings
# (short codes, never commands), and runs the update script only if it matches
# the fingerprint (SHA-256) built into this release.
#
# Run it with:  sudo bash asl-node-check.sh
#
# The report does not print passwords, IP addresses, or MAC addresses, so it's
# reasonably safe to share when asking for help. Read it over first anyway.

# Named SCRIPT_VERSION, not VERSION: /etc/os-release (read in section 1) sets
# its own VERSION variable, which would overwrite ours.
SCRIPT_VERSION="2.0"
REPO_BASE="https://raw.githubusercontent.com/EtherHamRadio/asl-node-check"
REPO_RAW="$REPO_BASE/main"
# The update script comes from this release's own tag (2.0, 2.1, ...), so it
# always matches the fingerprint below, even right after a new release or when
# someone runs an older check. Release checklist: merge to main, then tag the
# merge commit "$SCRIPT_VERSION" (no leading v) and push the tag.
# For testing a branch before release:  sudo ASL_NODE_CHECK_REF=branch-name bash asl-node-check.sh
UPDATE_REF="${ASL_NODE_CHECK_REF:-$SCRIPT_VERSION}"
[[ "$UPDATE_REF" =~ ^[A-Za-z0-9._-]+$ ]] || UPDATE_REF="$SCRIPT_VERSION"
UPDATE_RAW="$REPO_BASE/$UPDATE_REF"

# Fingerprint of the asl-node-update.sh released with this version. The check
# runs the update script only if it matches exactly. Update this whenever
# asl-node-update.sh changes:  sha256sum asl-node-update.sh
UPDATE_SCRIPT="asl-node-update.sh"
UPDATE_SHA256="64e9e59bb8067286a520b59339a87313a7f97cf897cb1379807bf4ce6add37b1"

# PHP releases that fix CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell").
# Branches not listed here (7.x, 8.0, 8.1) have no packaged fix on Debian.
declare -A PHP_FIXED=( ["8.2"]="8.2.35" ["8.3"]="8.3.36" ["8.4"]="8.4.27" ["8.5"]="8.5.12" )
PHP_CVE="CVE-2026-109618"

REFRESH=1
UPDATE_CHECK=1
for arg in "$@"; do
  case "$arg" in
    --no-refresh) REFRESH=0 ;;
    --no-update-check) UPDATE_CHECK=0 ;;
    --version) echo "asl-node-check $SCRIPT_VERSION"; exit 0 ;;
    -h|--help)
      echo "Usage: sudo bash asl-node-check.sh [--no-refresh] [--no-update-check]"
      echo "  --no-refresh        don't run apt-get update first (uses the last downloaded list)"
      echo "  --no-update-check   don't check GitHub for a newer version of this script"
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

# Findings that asl-node-update.sh knows how to handle. Each is a short code, never a
# command. Saved only if the user says yes at the end of the report.
FINDINGS_DIR="/var/lib/asl-node-check"
FINDINGS_FILE="$FINDINGS_DIR/findings"
FINDINGS_FORMAT=1
FINDINGS=()
finding() { [[ " ${FINDINGS[*]} " == *" $1 "* ]] || FINDINGS+=("$1"); }

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
# Packages a regular upgrade would keep back, space-separated (practice run, changes nothing)
held_back_pkgs() {
  LC_ALL=C apt-get -s --with-new-pkgs upgrade 2>/dev/null \
    | awk '/have been kept back:/{f=1;next} f&&/^  /{printf "%s ", $0;next} f{f=0}' \
    | tr -s ' ' | sed 's/^ //;s/ $//'
}

echo "${C_B}AllStarLink node security check, version $SCRIPT_VERSION${C_0}"
echo "Run on $(date '+%Y-%m-%d %H:%M %Z'). This script doesn't change your node's settings."

# ---------- Is this copy of the script current? ----------
# Reads the one-line VERSION file from the GitHub repo. If GitHub can't be
# reached, or the answer doesn't look like a version number, it says nothing.
NEWER_VERSION=""
if [ "$UPDATE_CHECK" -eq 1 ]; then
  latest=""
  if have curl; then
    latest=$(curl -fsS --max-time 5 "$REPO_RAW/VERSION" 2>/dev/null)
  elif have wget; then
    latest=$(wget -q -T 5 -t 1 -O - "$REPO_RAW/VERSION" 2>/dev/null)
  fi
  latest=$(printf '%s' "$latest" | head -n 1 | tr -d '[:space:]')
  if [[ "$latest" =~ ^[0-9]+(\.[0-9]+)+$ ]] && [ "$latest" != "$SCRIPT_VERSION" ] \
     && [ "$(printf '%s\n%s\n' "$SCRIPT_VERSION" "$latest" | sort -V | tail -n 1)" = "$latest" ]; then
    NEWER_VERSION="$latest"
    echo
    echo "${C_WARN}Newer version available:${C_0} you're running $SCRIPT_VERSION; version $latest is out."
    echo "To get it, run this, then run the check again:"
    echo "    wget -O asl-node-check.sh $REPO_RAW/asl-node-check.sh"
  fi
fi

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

# This script is for AllStarLink 3 only. ASL3 installs the "asl3" package.
if ! pkg_installed asl3 && ! pkg_installed asl3-asterisk; then
  if [ -d /etc/asterisk ] || have asterisk; then
    bad "This node runs AllStarLink, but not version 3. It's most likely ASL2 or older." \
        "This script only checks ASL3 nodes. ASL2 runs on Debian releases that no longer get security updates, so plan a move to ASL3 (Debian 13). Back up your settings in /etc/asterisk first."
  else
    bad "AllStarLink 3 doesn't appear to be installed on this computer." \
        "This script only checks ASL3 nodes. Run it on the node itself."
  fi
  echo; echo "Stopping here: this script is for AllStarLink 3 (ASL3) nodes only."
  exit 1
fi
ok "AllStarLink 3 is installed."

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
  warn "The system says a restart is needed to finish an earlier update." "Restart the node at a quiet moment:" '$ sudo reboot'
  finding REBOOT_NEEDED
else
  ok "The system hasn't asked for a restart. (Section 2 checks whether any programs still need one.)"
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
# Updates apt "keeps back": installing them would remove or replace another
# package, which a regular upgrade never does. A practice run (-s) finds them.
HELD=$(held_back_pkgs)
N_HELD=0; [ -n "$HELD" ] && N_HELD=$(wc -w <<< "$HELD")
INSTALLABLE=$(( UPGRADABLE - N_HELD )); [ "$INSTALLABLE" -lt 0 ] && INSTALLABLE=0
if [ "$UPGRADABLE" -eq 0 ]; then
  if [ "$REFRESH" -eq 1 ] && is_root; then
    ok "All installed software is up to date."
  else
    info "No updates were waiting as of that list. Run:  sudo apt update   to check for newer ones."
  fi
elif [ "$INSTALLABLE" -gt 0 ] && [ "$SEC_UPGRADABLE" -gt 0 ]; then
  finding UPDATES_WAITING
  bad "$INSTALLABLE update(s) waiting, including security updates." \
      "Install the updates, then run this script again. It will tell you whether anything needs restarting:" '$ sudo apt update && sudo apt upgrade' '$ sudo bash asl-node-check.sh'
elif [ "$INSTALLABLE" -gt 0 ]; then
  finding UPDATES_WAITING
  warn "$INSTALLABLE update(s) waiting (none marked as security updates)." \
       "When convenient, run:" '$ sudo apt update && sudo apt upgrade'
fi
if [ "$N_HELD" -gt 0 ]; then
  held_msg="$N_HELD update(s) held back by apt: $HELD."
  held_todo=("Installing these replaces or removes another package, so a regular upgrade skips them. Usually it's an old library being swapped for a newer one." \
             "Run this, then read the list under \"will be REMOVED\" before answering. If anything there looks important, answer n and ask for help:" \
             '$ sudo apt full-upgrade')
  if [ "$INSTALLABLE" -eq 0 ] && [ "$SEC_UPGRADABLE" -gt 0 ]; then
    bad "$held_msg" "${held_todo[@]}"
  else
    warn "$held_msg" "${held_todo[@]}"
  fi
fi

# Installing unattended-upgrades does NOT reliably switch it on: on fresh Debian 12
# and 13 nodes the package installs but /etc/apt/apt.conf.d/20auto-upgrades is
# never created. So when it's missing, give both commands at once.
if pkg_installed unattended-upgrades && \
   apt-config dump 2>/dev/null | grep -q 'APT::Periodic::Unattended-Upgrade "1"'; then
  ok "Automatic security updates are turned on."
elif ! pkg_installed unattended-upgrades; then
  finding AUTO_UPDATES_OFF
  warn "Automatic security updates are not turned on." \
       "Run these two commands. The second one asks a question; answer Yes:" \
       '$ sudo apt install unattended-upgrades' \
       '$ sudo dpkg-reconfigure -plow unattended-upgrades' \
       "Then run this script again to confirm."
else
  finding AUTO_UPDATES_OFF
  warn "Automatic security updates are installed but switched off." \
       "Run this command, and answer Yes when asked:" '$ sudo dpkg-reconfigure -plow unattended-upgrades' \
       "Then run this script again to confirm."
fi

# Programs still running old code from before an update (a library or program
# was replaced on disk, but the running copy in memory is the old one).
if [ -f /var/run/reboot-required ]; then
  info "Skipping the check for programs running old code, since a restart is already waiting (see section 1)."
elif ! is_root; then
  info "Checking for programs still running old code needs root."
else
  SAFE=(); NET=(); LATER=(); ASTERISK_OLD=0; CORE_OLD=0
  add() { local -n arr=$1; [[ " ${arr[*]} " == *" $2 "* ]] || arr+=("$2"); }
  while read -r pid; do
    unit=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
    name=${unit%.service}
    case "$unit" in
      ""|-) continue ;;
      asterisk.service) ASTERISK_OLD=1 ;;
      # systemd itself, login sessions, and core system services: next reboot
      init.scope|*.scope|user@*) CORE_OLD=1 ;;
      dbus.service|dbus-broker.service|systemd-*|getty@*|serial-getty@*) CORE_OLD=1; add LATER "$name" ;;
      # restarting these can briefly drop the network, including your SSH session
      NetworkManager.service|ModemManager.service|networking.service|wpa_supplicant*|dhcpcd.service|tailscaled.service|wg-quick@*|ifup@*)
        add NET "$name" ;;
      *.service) add SAFE "$name" ;;
    esac
  done < <(grep -lE ' /(usr/)?(lib|lib64|bin|sbin)/[^ ]* \(deleted\)$' /proc/[0-9]*/maps 2>/dev/null | cut -d/ -f3 | sort -un)

  TOTAL=$(( ${#SAFE[@]} + ${#NET[@]} + ASTERISK_OLD ))
  if [ "$TOTAL" -eq 0 ] && [ "$CORE_OLD" -eq 0 ]; then
    ok "No running programs are using old code from before an update."
  elif [ "$TOTAL" -gt 6 ] || { [ "$CORE_OLD" -eq 1 ] && [ "$TOTAL" -gt 2 ]; }; then
    # Many things, or the core system plus several services: one reboot is simpler and safer
    finding REBOOT_NEEDED
    warn "Many services ($TOTAL), including core parts of the system, are still running old code from earlier updates." \
         "The simplest fix is to restart the node at a quiet moment. It's offline for about a minute, and connected stations drop:" \
         '$ sudo reboot'
  else
    if [ "${#SAFE[@]}" -gt 0 ]; then
      finding SERVICES_OLD_CODE
      warn "Some services are still running old code from before an update: ${SAFE[*]}." \
           "Restart them with this command. No reboot needed, and it doesn't affect your node's connections:" \
           "\$ sudo systemctl restart ${SAFE[*]}"
    fi
    if [ "$ASTERISK_OLD" -eq 1 ]; then
      finding ASTERISK_OLD_CODE
      warn "Asterisk (the node itself) is still running old code from before an update." \
           "Restarting it briefly drops every connected station, so pick a quiet moment:" \
           '$ sudo systemctl restart asterisk'
    fi
    if [ "${#NET[@]}" -gt 0 ]; then
      info "Network services (${NET[*]}) are running old code. Restarting them can briefly drop the network,"
      echo "         including your SSH session, so let them pick up the update at the next reboot."
    fi
    if [ "$CORE_OLD" -eq 1 ]; then
      if [ "${#LATER[@]}" -gt 0 ]; then
        info "A few core system services (${LATER[*]}) will pick up updates at the next reboot. There's no hurry."
      else
        info "Core parts of the system will pick up updates at the next reboot. There's no hurry."
      fi
    fi
  fi
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
      finding UPDATES_WAITING
      bad "PHP $branch is version $up. The PHP2Shell fix arrived in $fixed." \
          "Install the updates, then run this script again. It will tell you whether anything needs restarting:" '$ sudo apt update && sudo apt upgrade' '$ sudo bash asl-node-check.sh'
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
        finding PHP_SERVICE_STALE
        bad "$svc has been running since before PHP was last updated, so it may still be using the old code." \
            "Restart it. This doesn't affect your node's connections:" "\$ sudo systemctl restart $svc"
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

FW=""
if have ufw && is_root && ufw status 2>/dev/null | grep -q '^Status: active'; then FW="ufw"
elif svc_active firewalld; then FW="firewalld"
elif is_root && have nft && [ "$(nft list ruleset 2>/dev/null | grep -c 'hook input')" -gt 0 ]; then FW="nftables"
fi

if [ "$PUBLIC_V4" -eq 1 ]; then
  info "This node has a public internet address (for example, a rented server or a 44Net address)."
else
  info "This node uses a private (home network) address."
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

if [ "$WEB_LISTEN" -eq 1 ] && [ "$PUBLIC_V4" -eq 1 ]; then
  if [ "$FW" = "ufw" ]; then
    # Firewall rules that let web traffic (port 80 or 443, or a web server profile) in
    WEB_RULES=$(ufw status 2>/dev/null | grep -E '[[:space:]](ALLOW|LIMIT)([[:space:]]+IN)?[[:space:]]' \
                | grep -Ei '^((apache|www|nginx)|([0-9]+,)*(80|443)(,[0-9]+)*(/tcp)?[[:space:]])')
    if [ -z "$WEB_RULES" ]; then
      ok "The firewall blocks the web dashboard from the internet."
    elif echo "$WEB_RULES" | grep -q 'Anywhere'; then
      warn "The firewall lets anyone on the internet reach the web dashboard (port 80 or 443)." \
           "That's normal for a public hub. Make sure the dashboard is password-protected and kept up to date." \
           "If only you use it, allow just your own address instead, or reach it over a VPN such as Tailscale."
    else
      ok "The firewall lets only specific addresses reach the web dashboard."
    fi
  elif [ -n "$FW" ]; then
    warn "The web dashboard may be reachable from the internet. This script can only read ufw rules, not $FW." \
         "Check that your $FW rules allow ports 80 and 443 only from where you intend."
  elif is_root; then
    warn "The web dashboard is reachable from the whole internet." \
         "Make sure it's password-protected and kept up to date, and set up a firewall (see above)."
  fi
elif [ "$WEB_LISTEN" -eq 1 ]; then
  info "Its web dashboard is reachable on your home network. This script can't see your router."
  echo "         Check your router: if it forwards port 80 or 443 to this node, the dashboard is on the open internet."
  echo "         For access from away, a VPN such as Tailscale or WireGuard is safer than a port forward."
fi

# Cockpit: the web admin console on port 9090 (included in the ASL3 Raspberry Pi image)
COCKPIT=0
if svc_active cockpit.socket || svc_active cockpit; then COCKPIT=1
elif have ss && ss -Hltn 2>/dev/null | awk '{print $4}' | grep -Eq '[:.]9090$'; then COCKPIT=1; fi
if [ "$COCKPIT" -eq 1 ]; then
  if [ "$PUBLIC_V4" -eq 1 ]; then
    OPEN9090=unknown
    if [ "$FW" = "ufw" ]; then
      if ufw status 2>/dev/null | grep -E '[[:space:]](ALLOW|LIMIT)' | grep -Eq '^(9090|([0-9]+,)*9090(,[0-9]+)*)(/tcp)?[[:space:]].*Anywhere'; then OPEN9090=yes; else OPEN9090=no; fi
    elif [ "$FW" = "firewalld" ] && have firewall-cmd; then
      if firewall-cmd --list-all 2>/dev/null | grep -Eq '(services:.*\bcockpit\b|ports:.*\b9090/tcp\b)'; then OPEN9090=yes; else OPEN9090=no; fi
    fi
    case "$OPEN9090" in
      no)  ok "The Cockpit web console (port 9090) is running, and the firewall blocks it from the internet." ;;
      yes) bad "The Cockpit web console (port 9090) is open to the whole internet. Cockpit gives full control of this node." \
               "Block port 9090 in your firewall, and reach Cockpit over a VPN such as Tailscale instead." ;;
      *)   warn "The Cockpit web console (port 9090) is running, and this node has a public address. Cockpit gives full control of this node." \
                "Make sure your firewall blocks port 9090 from the internet, and reach Cockpit over a VPN such as Tailscale." ;;
    esac
  else
    info "The Cockpit web console (port 9090) is running. It gives full control of this node,"
    echo "         so never forward port 9090 on your router. Use a VPN such as Tailscale to reach it from away."
  fi
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
if [ -n "$NEWER_VERSION" ]; then
  echo "  This report came from version $SCRIPT_VERSION. Version $NEWER_VERSION is available; see the top of the report."
fi

# ---------- Optional: offer the update script ----------
# Asks only when there's something the update script handles, the check ran as
# root, and someone is at the keyboard. Any answer other than y means no.
save_findings() {
  umask 077
  mkdir -p "$FINDINGS_DIR" && chmod 700 "$FINDINGS_DIR" && {
    echo "# asl-node-check findings. Codes only; asl-node-update.sh re-checks each one first."
    echo "format=$FINDINGS_FORMAT"
    echo "check_version=$SCRIPT_VERSION"
    echo "saved=$(date +%s)"
    printf '%s\n' "${FINDINGS[@]}"
  } > "$FINDINGS_FILE.tmp" && mv -f "$FINDINGS_FILE.tmp" "$FINDINGS_FILE"
}
sha_ok() { [ -f "$1" ] && [ "$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)" = "$UPDATE_SHA256" ]; }

if [ "${#FINDINGS[@]}" -gt 0 ] && is_root && [ -t 0 ] && [ -t 1 ]; then
  # The update script goes next to this one, owned by whoever ran sudo.
  HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || HERE="$PWD"
  LOCAL_UPDATE="$HERE/$UPDATE_SCRIPT"
  echo
  echo "${C_B}Optional:${C_0} the update script ($UPDATE_SCRIPT) can take care of ${#FINDINGS[@]} of these for you."
  echo "It installs waiting updates, turns on automatic security updates, and restarts"
  echo "services that are still running old code. It shows each step and asks first."
  echo "It never touches your firewall, SSH settings, or node settings."
  READY=0; SAVED_NOW=0
  if sha_ok "$LOCAL_UPDATE"; then
    READY=1
  else
    echo
    if [ -e "$LOCAL_UPDATE" ]; then
      echo "Your copy of $UPDATE_SCRIPT doesn't match this version of the check."
      Q="Download the current update script? [y/N] "
    else
      Q="Download the update script? [y/N] "
    fi
    read -r -p "$Q" ANSWER
    if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
      TMP_DL=$(mktemp) || TMP_DL=""
      got=1
      # Try this release's tag first, then main. The fingerprint decides what's accepted.
      for src in "$UPDATE_RAW" "$REPO_RAW"; do
        [ -n "$TMP_DL" ] || break
        if have wget; then wget -q -T 20 -t 2 -O "$TMP_DL" "$src/$UPDATE_SCRIPT" && got=0
        elif have curl; then curl -fsS --max-time 30 -o "$TMP_DL" "$src/$UPDATE_SCRIPT" 2>/dev/null && got=0
        fi
        [ "$got" -eq 0 ] && sha_ok "$TMP_DL" && break
      done
      if [ "$got" -ne 0 ]; then
        echo "  Couldn't download it. Check the node's internet connection and try again later."
      elif ! sha_ok "$TMP_DL"; then
        echo "  ${C_BAD}The download doesn't match this version's fingerprint, so it wasn't saved or run.${C_0}"
        echo "  Try again later. If it keeps happening, please report it at"
        echo "  https://github.com/EtherHamRadio/asl-node-check/issues"
      elif install -m 644 "$TMP_DL" "$LOCAL_UPDATE"; then
        [ -n "$SUDO_UID" ] && chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$LOCAL_UPDATE" 2>/dev/null
        echo "  Downloaded $UPDATE_SCRIPT ($(( $(stat -c %s "$LOCAL_UPDATE") / 1024 )) KB) to $HERE."
        if save_findings; then READY=1; SAVED_NOW=1; else echo "  Couldn't save the findings file."; fi
      else
        echo "  Couldn't save the update script to $HERE."
      fi
      [ -n "$TMP_DL" ] && rm -f "$TMP_DL"
    else
      echo "  Not downloaded. Nothing was changed."
    fi
  fi

  if [ "$READY" -eq 1 ]; then
    read -r -p "Run it now? [y/N] " ANSWER
    if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
      # Run a root-only copy, checked again, so it can't change between the check and the run.
      if save_findings && RUN_COPY="$FINDINGS_DIR/$UPDATE_SCRIPT" \
         && install -m 700 "$LOCAL_UPDATE" "$RUN_COPY" && sha_ok "$RUN_COPY"; then
        echo
        bash "$RUN_COPY"
        exit $?
      else
        echo "  Couldn't prepare the update script. Nothing was changed."
      fi
    else
      if [ "$SAVED_NOW" -eq 1 ]; then
        echo "  Not run. Your findings are saved, so you can run it later with:"
        echo "      sudo bash $LOCAL_UPDATE"
      else
        echo "  Not run. Nothing was changed. To use it later, run this check again and answer y."
      fi
    fi
  fi
fi

[ "$N_BAD" -gt 0 ] && exit 1 || exit 0
