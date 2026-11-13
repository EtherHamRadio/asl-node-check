#!/usr/bin/env bash
# asl-node-update.sh — optional companion to asl-node-check.sh for AllStarLink 3 nodes
#
# Version 0.6 (November 13, 2026)
# https://github.com/EtherHamRadio/asl-node-check
# MIT License. Copyright (c) 2026 Tom Salzer, KJ7T
#
# What it does: reads the findings that asl-node-check.sh saved (only if you said
# yes when it asked), checks each one again to make sure it still applies, then
# shows you each step and asks before doing it. Any answer other than y means no.
#
# What it handles: waiting updates, automatic security updates, services still
# running old code, leftovers from removed software that are still running,
# and a restart when one is needed.
# What it never touches: firewall rules, SSH settings, passwords, your router,
# or your node's own settings in /etc/asterisk. Those stay advice only.
#
# Run it with:  sudo bash asl-node-update.sh
# Just see the plan, change nothing:  sudo bash asl-node-update.sh --dry-run

UPDATE_VERSION="0.6"
# Files this script or apt creates get Debian's normal permissions, whatever
# umask it was started with (check 2.2 and earlier passed along umask 077).
umask 022
FINDINGS_DIR="/var/lib/asl-node-check"
FINDINGS_FILE="$FINDINGS_DIR/findings"
FINDINGS_FORMAT=1
LOG_FILE="$FINDINGS_DIR/update.log"
KNOWN_CODES="UPDATES_WAITING AUTO_UPDATES_OFF SERVICES_OLD_CODE PHP_SERVICE_STALE ASTERISK_OLD_CODE REBOOT_NEEDED ORPHAN_SERVICES"

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --version) echo "asl-node-update $UPDATE_VERSION"; exit 0 ;;
    -h|--help)
      echo "Usage: sudo bash asl-node-update.sh [--dry-run]"
      echo "  --dry-run   show what it would do, change nothing"
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
say()  { echo "$@"; }
done_() { echo "  ${C_OK}[DONE]${C_0} $1"; log "done: $1"; }
skip() { echo "  ${C_INFO}[skip]${C_0} $1"; log "skipped: $1"; }
fail() { echo "  ${C_BAD}[FAIL]${C_0} $1"; log "failed: $1"; }
log()  { [ "$DRY_RUN" -eq 1 ] && return; echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null; }
have() { command -v "$1" >/dev/null 2>&1; }
pkg_installed() { dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^ii'; }
pkg_changed_at() { stat -c %Y "/var/lib/dpkg/info/$1.list" 2>/dev/null || echo 0; }
svc_started_at() {
  local ts; ts=$(systemctl show -p ActiveEnterTimestamp --value "$1" 2>/dev/null)
  [ -n "$ts" ] && date -d "$ts" +%s 2>/dev/null || echo 0
}
svc_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

# ask "question" -> 0 only for y or Y. In --dry-run, never asks and never says yes.
ask() {
  local a
  if [ "$DRY_RUN" -eq 1 ]; then echo "  (dry run: would ask) $1"; return 1; fi
  read -r -p "  $1 [y/N] " a
  [[ "$a" =~ ^[Yy]$ ]]
}
# show the exact command, then (unless dry run) run it
show_cmd() { echo "      $*"; }

echo "${C_B}AllStarLink node update script, version $UPDATE_VERSION${C_0}"
[ "$DRY_RUN" -eq 1 ] && echo "Dry run: this shows the plan and changes nothing."

# ---------- Safety checks before anything else ----------
if [ "$(id -u)" -ne 0 ]; then
  echo "This script needs root to install updates. Run it with:  sudo bash $0"
  exit 1
fi
if ! have dpkg || ! { pkg_installed asl3 || pkg_installed asl3-asterisk; }; then
  echo "This script is for AllStarLink 3 (ASL3) nodes only. Nothing was changed."
  exit 1
fi
if [ "$DRY_RUN" -eq 0 ] && ! [ -t 0 ]; then
  echo "This script asks before each step, so it needs someone at the keyboard."
  echo "Run it directly in your SSH session, not from a pipe or a scheduled job. Nothing was changed."
  exit 1
fi

# ---------- Tidy up backups that older versions left where apt reads them ----------
# Update script 0.5 and earlier saved the old 20auto-upgrades next to the
# original, as /etc/apt/apt.conf.d/20auto-upgrades.bak-DATE. apt skips that
# name but prints "N: Ignoring file ..." every time it runs. Move any such
# copies to /var/backups, where this script now keeps them. Nothing is deleted.
BACKUP_DIR="/var/backups"
NOTHING_CHANGED="Nothing was changed."
OLD_BAKS=()
for f in /etc/apt/apt.conf.d/20auto-upgrades.bak-*; do
  [ -f "$f" ] && [ ! -L "$f" ] && OLD_BAKS+=("$f")
done
if [ "${#OLD_BAKS[@]}" -gt 0 ]; then
  echo; echo "${C_B}Old backup copies in apt's settings folder${C_0}"
  echo "  An earlier version of this script left these where apt reads its settings, so apt"
  echo "  prints \"N: Ignoring file ...\" every time it runs. Moving them to $BACKUP_DIR:"
  for f in "${OLD_BAKS[@]}"; do show_cmd "mv $f $BACKUP_DIR/"; done
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  (dry run: would move them)"
  else
    mkdir -p "$BACKUP_DIR"
    MOVED=0
    for f in "${OLD_BAKS[@]}"; do
      mv -n "$f" "$BACKUP_DIR/" 2>/dev/null
      [ -e "$f" ] || MOVED=$((MOVED + 1))
    done
    if [ "$MOVED" -eq "${#OLD_BAKS[@]}" ]; then
      done_ "Moved $MOVED old backup copy(s) to $BACKUP_DIR. apt's \"Ignoring file\" notice is gone."
    else
      fail "Moved $MOVED of ${#OLD_BAKS[@]}. A file with the same name may already be in $BACKUP_DIR; the rest are still in /etc/apt/apt.conf.d."
    fi
    [ "$MOVED" -gt 0 ] && NOTHING_CHANGED="Nothing else was changed."
  fi
fi

# ---------- Read the saved findings, trusting only a file root wrote ----------
if [ ! -e "$FINDINGS_FILE" ]; then
  echo
  echo "No saved findings yet. Run the check first, and answer y when it asks to save:"
  echo "    sudo bash asl-node-check.sh"
  exit 0
fi
bad_file() { echo "The findings file isn't safe to use ($1). $NOTHING_CHANGED"; echo "Run the check again and save a fresh copy:  sudo bash asl-node-check.sh"; exit 1; }
[ -L "$FINDINGS_DIR" ] || [ -L "$FINDINGS_FILE" ] && bad_file "it's a link, not a regular file"
[ -f "$FINDINGS_FILE" ] || bad_file "it isn't a regular file"
for path in "$FINDINGS_DIR" "$FINDINGS_FILE"; do
  read -r owner mode < <(stat -c '%u %a' "$path")
  [ "$owner" = "0" ] || bad_file "$path isn't owned by root"
  (( 8#$mode & 8#022 )) && bad_file "$path can be changed by other users"
done

FORMAT=""; CHECK_VER="?"; SAVED=0; CODES=()
while IFS= read -r line; do
  case "$line" in
    ""|\#*) ;;
    format=*) FORMAT=${line#format=} ;;
    check_version=*) CHECK_VER=${line#check_version=} ;;
    saved=*) SAVED=${line#saved=}; [[ "$SAVED" =~ ^[0-9]+$ ]] || SAVED=0 ;;
    *)
      if [[ "$line" =~ ^[A-Z_]+$ ]] && [[ " $KNOWN_CODES " == *" $line "* ]]; then
        [[ " ${CODES[*]} " == *" $line "* ]] || CODES+=("$line")
      else
        echo "  ${C_INFO}[info]${C_0} Ignoring an entry this version doesn't recognize: ${line:0:40}"
      fi ;;
  esac
done < "$FINDINGS_FILE"

[ "$FORMAT" = "$FINDINGS_FORMAT" ] || bad_file "it was written by a different version of the check (format ${FORMAT:-unknown})"
has() { [[ " ${CODES[*]} " == *" $1 "* ]]; }

AGE_DAYS=$(( ( $(date +%s) - SAVED ) / 86400 ))
echo
echo "Using findings saved by asl-node-check $CHECK_VER, $AGE_DAYS day(s) ago."
[ "$AGE_DAYS" -gt 7 ] && echo "${C_WARN}They're more than a week old.${C_0} Each one is checked again below, but running the check again first is a good idea."
if [ "${#CODES[@]}" -eq 0 ]; then
  echo "Nothing in the saved findings is something this script handles. $NOTHING_CHANGED"
  exit 0
fi
log "run started (update $UPDATE_VERSION, findings from check $CHECK_VER: ${CODES[*]})"

# ---------- Re-check helpers (the same tests the check script uses) ----------
auto_updates_on() {
  pkg_installed unattended-upgrades && apt-config dump 2>/dev/null | grep -q 'APT::Periodic::Unattended-Upgrade "1"'
}
updates_waiting() { apt list --upgradable 2>/dev/null | grep -c 'upgradable from'; }
# Packages a regular upgrade would keep back, space-separated (practice run, changes nothing)
held_back_pkgs() {
  LC_ALL=C apt-get -s --with-new-pkgs upgrade 2>/dev/null \
    | awk '/have been kept back:/{f=1;next} f&&/^  /{printf "%s ", $0;next} f{f=0}' \
    | tr -s ' ' | sed 's/^ //;s/ $//'
}
held_note() {
  [ -n "$1" ] || return 0
  echo "  ${C_INFO}[info]${C_0} Held back by apt: $1"
  echo "         Installing these replaces or removes another package, so this script leaves"
  echo "         them to you. Run the check again; it explains how to install them."
}

# A service whose unit file is gone (its package was removed) but whose program is
# still running. "systemctl restart" fails on these with "Unit ... not found";
# they can only be stopped.
unit_gone() { [ "$(systemctl show -p LoadState --value "$1" 2>/dev/null)" = "not-found" ]; }

# Fills SAFE (plain services), ORPHAN (leftovers), ASTERISK_OLD, CORE_OLD, NET_COUNT
scan_old_code() {
  SAFE=(); ORPHAN=(); ASTERISK_OLD=0; CORE_OLD=0; NET_COUNT=0
  local pid unit name
  while read -r pid; do
    unit=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
    name=${unit%.service}
    case "$unit" in
      ""|-) continue ;;
      asterisk.service) ASTERISK_OLD=1 ;;
      init.scope|*.scope|user@*) CORE_OLD=1 ;;
      dbus.service|dbus-broker.service|systemd-*|getty@*|serial-getty@*) CORE_OLD=1 ;;
      NetworkManager.service|ModemManager.service|networking.service|wpa_supplicant*|dhcpcd.service|tailscaled.service|wg-quick@*|ifup@*)
        NET_COUNT=$((NET_COUNT+1)) ;;
      *.service)
        if unit_gone "$unit"; then
          [[ " ${ORPHAN[*]} " == *" $name "* ]] || ORPHAN+=("$name")
        else
          [[ " ${SAFE[*]} " == *" $name "* ]] || SAFE+=("$name")
        fi ;;
    esac
  done < <(grep -lE ' /(usr/)?(lib|lib64|bin|sbin)/[^ ]* \(deleted\)$' /proc/[0-9]*/maps 2>/dev/null | cut -d/ -f3 | sort -un)
}

# Web servers still running PHP from before the last PHP update
stale_php_services() {
  local pkg branch svc srcpkg out=()
  for pkg in $(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\n' 'php*-common' 2>/dev/null | awk '$1 ~ /^php[0-9]+\.[0-9]+-common$/ && $2 ~ /^ii/ {print $1}'); do
    branch=${pkg#php}; branch=${branch%-common}
    for svc in "php$branch-fpm" apache2; do
      svc_active "$svc" || continue
      case "$svc" in
        apache2) pkg_installed "libapache2-mod-php$branch" || continue; srcpkg="libapache2-mod-php$branch" ;;
        *) srcpkg="php$branch-fpm" ;;
      esac
      [ "$(pkg_changed_at "$srcpkg")" -gt "$(svc_started_at "$svc")" ] && [[ " ${out[*]} " != *" $svc "* ]] && out+=("$svc")
    done
  done
  echo "${out[*]}"
}

# ---------- 1. Automatic security updates ----------
if has AUTO_UPDATES_OFF; then
  echo; echo "${C_B}Automatic security updates${C_0}"
  if auto_updates_on; then
    skip "Automatic security updates are already on. Nothing to do."
  else
    echo "  Automatic security updates are off. This step installs unattended-upgrades (if needed)"
    echo "  and switches it on, the same as answering Yes in dpkg-reconfigure. It runs:"
    pkg_installed unattended-upgrades || show_cmd "apt-get install -y unattended-upgrades"
    show_cmd "write /etc/apt/apt.conf.d/20auto-upgrades (a copy of the old one is kept in $BACKUP_DIR)"
    if ask "Turn on automatic security updates?"; then
      if ! pkg_installed unattended-upgrades; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades || { fail "Couldn't install unattended-upgrades."; }
      fi
      AU=/etc/apt/apt.conf.d/20auto-upgrades
      # Keep the copy outside /etc/apt/apt.conf.d: apt reads every file there and
      # complains about names it doesn't recognize ("N: Ignoring file ...").
      if [ -f "$AU" ]; then
        mkdir -p "$BACKUP_DIR"
        cp -p "$AU" "$BACKUP_DIR/20auto-upgrades.bak-$(date +%Y%m%d-%H%M%S)"
      fi
      printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > "$AU"
      chmod 644 "$AU"
      if auto_updates_on; then done_ "Automatic security updates are on."; else fail "Automatic updates still don't show as on. Run the check again for details."; fi
    else
      skip "Left automatic security updates as they are."
    fi
  fi
fi

# ---------- 2. Waiting updates ----------
if has UPDATES_WAITING; then
  echo; echo "${C_B}Waiting updates${C_0}"
  if [ "$DRY_RUN" -eq 0 ]; then
    echo "  Downloading the latest list of updates..."
    apt-get update -qq >/dev/null 2>&1 || echo "  ${C_WARN}Couldn't refresh the update list; using the last one.${C_0}"
  fi
  TOTAL_WAITING=$(updates_waiting)
  HELD=$(held_back_pkgs)
  N_HELD=0; [ -n "$HELD" ] && N_HELD=$(wc -w <<< "$HELD")
  N=$(( TOTAL_WAITING - N_HELD )); [ "$N" -lt 0 ] && N=0
  if [ "$TOTAL_WAITING" -eq 0 ]; then
    skip "No updates are waiting anymore. Nothing to do."
  elif [ "$N" -eq 0 ]; then
    skip "The only waiting updates are ones apt holds back."
    held_note "$HELD"
  else
    echo "  $N update(s) are waiting. This installs them and keeps your current settings files"
    echo "  whenever an update offers a newer one. It runs:"
    show_cmd "apt-get --with-new-pkgs upgrade -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
    echo "  It can take several minutes. Your node keeps running while it works."
    if ask "Install the $N waiting update(s)?"; then
      if DEBIAN_FRONTEND=noninteractive apt-get -y --with-new-pkgs upgrade \
           -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold; then
        LEFT=$(updates_waiting)
        DONE_N=$(( TOTAL_WAITING - LEFT )); [ "$DONE_N" -lt 0 ] && DONE_N=0
        done_ "Installed $DONE_N update(s)."
        held_note "$(held_back_pkgs)"
      else
        fail "The update didn't finish cleanly. Scroll up for the message, or run the check again."
      fi
    else
      skip "Left the waiting updates for later."
      held_note "$HELD"
    fi
  fi
fi

# ---------- 3. Services still running old code ----------
# Re-scanned now, after any updates above, which can add new ones. That's why this
# section can run even if the saved findings didn't list it.
scan_old_code
STALE_PHP=$(stale_php_services)
NEED_REBOOT=0
[ -f /var/run/reboot-required ] && NEED_REBOOT=1
TOTAL=$(( ${#SAFE[@]} + ${#ORPHAN[@]} + NET_COUNT + ASTERISK_OLD ))
if [ "$TOTAL" -gt 6 ] || { [ "$CORE_OLD" -eq 1 ] && [ "$TOTAL" -gt 2 ]; }; then NEED_REBOOT=1; fi

if [ "$NEED_REBOOT" -eq 0 ]; then
  # Restart plain services and stale PHP web servers (none of these drop node connections)
  RESTART=("${SAFE[@]}")
  for s in $STALE_PHP; do [[ " ${RESTART[*]} " == *" $s "* ]] || RESTART+=("$s"); done
  if [ "${#RESTART[@]}" -gt 0 ]; then
    echo; echo "${C_B}Services running old code${C_0}"
    echo "  These services are still running code from before an update: ${RESTART[*]}"
    echo "  Restarting them doesn't affect your node's connections. It runs:"
    show_cmd "systemctl restart ${RESTART[*]}"
    if ask "Restart these services?"; then
      if systemctl restart "${RESTART[@]}"; then done_ "Restarted: ${RESTART[*]}"; else fail "Some services didn't restart. Run the check again for details."; fi
    else
      skip "Left those services running as they are."
    fi
  elif has SERVICES_OLD_CODE || has PHP_SERVICE_STALE; then
    echo; skip "No services are running old code anymore. Nothing to do."
  fi

  # Leftovers from removed software: stop them, then have systemd forget them.
  if [ "${#ORPHAN[@]}" -gt 0 ]; then
    ORPHAN_UNITS=()
    for s in "${ORPHAN[@]}"; do ORPHAN_UNITS+=("$s.service"); done
    echo; echo "${C_B}Leftovers from removed software${C_0}"
    echo "  These are still running, but the software they came from has been removed: ${ORPHAN[*]}"
    echo "  Their files are gone, so they can't be restarted, only stopped. Stopping them"
    echo "  doesn't affect your node's connections. It runs:"
    show_cmd "systemctl stop ${ORPHAN_UNITS[*]}"
    show_cmd "systemctl daemon-reload"
    if ask "Stop these leftovers?"; then
      if systemctl stop "${ORPHAN_UNITS[@]}" && systemctl daemon-reload; then
        done_ "Stopped: ${ORPHAN[*]}"
      else
        fail "Some leftovers didn't stop. A reboot will clear them, since nothing starts them again."
      fi
    else
      skip "Left those running. A reboot will clear them, since nothing starts them again."
    fi
  elif has ORPHAN_SERVICES; then
    echo; skip "No leftovers from removed software are running anymore. Nothing to do."
  fi

  if [ "$ASTERISK_OLD" -eq 1 ]; then
    echo; echo "${C_B}Asterisk (the node itself)${C_0}"
    echo "  Asterisk is still running code from before an update."
    echo "  ${C_WARN}Restarting it briefly drops every connected station.${C_0} Pick a quiet moment. It runs:"
    show_cmd "systemctl restart asterisk"
    if ask "Restart Asterisk now?"; then
      if systemctl restart asterisk; then done_ "Restarted Asterisk."; else fail "Asterisk didn't restart cleanly. Check it with:  sudo systemctl status asterisk"; fi
    else
      skip "Left Asterisk running. Restart it later at a quiet moment."
    fi
  elif has ASTERISK_OLD_CODE; then
    echo; skip "Asterisk is no longer running old code. Nothing to do."
  fi
  [ "$NET_COUNT" -gt 0 ] && echo && echo "  ${C_INFO}[info]${C_0} Network services will pick up their updates at the next reboot. This script won't restart them, since that can drop your SSH session."
fi

# ---------- 4. Restart the node (always last) ----------
if [ "$NEED_REBOOT" -eq 1 ]; then
  echo; echo "${C_B}Restart the node${C_0}"
  if [ -f /var/run/reboot-required ]; then
    echo "  The system says a restart is needed to finish an update."
  else
    echo "  Many services, including core parts of the system, are running old code. One restart fixes them all."
  fi
  echo "  ${C_WARN}The node goes offline for about a minute, connected stations drop, and this SSH session ends.${C_0}"
  echo "  It runs:"
  show_cmd "reboot"
  if ask "Restart the node now?"; then
    done_ "Restarting the node."
    echo
    echo "When it's back up (give it a minute or two), log in again and run the check to confirm:"
    echo "    sudo bash asl-node-check.sh"
    sleep 2
    reboot
    exit 0
  else
    skip "Didn't restart. Restart later at a quiet moment with:  sudo reboot"
  fi
elif has REBOOT_NEEDED; then
  echo; skip "A restart is no longer needed. Nothing to do."
fi

# ---------- Wrap-up ----------
echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "Dry run finished. Nothing was changed. To make the changes, run:  sudo bash asl-node-update.sh"
else
  log "run finished"
  echo "Finished. A log of what was done is in $LOG_FILE."
  echo "Run the check again to confirm everything:"
  echo "    sudo bash asl-node-check.sh"
fi
echo "This script never changes firewall rules, SSH settings, or anything in /etc/asterisk."
echo "Any of those items in the check's report are still yours to handle."
