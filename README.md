# asl-node-check

Version 2.4, November 13, 2026 (update script: version 0.6)

**For AllStarLink 3 (ASL3) nodes only.** It does not work on HamVoIP or ASL2 nodes. It checks which system it's on and stops, with an explanation, if the node isn't running ASL3. If your node runs HamVoIP or ASL2, its operating system no longer gets regular security updates, and moving to ASL3 is the fix.

A plain-language security check for AllStarLink 3 (ASL3) nodes, written for node owners who aren't Linux administrators. Run one command, and it tells you what needs attention and exactly what to do about it.

It was written in response to the October 2026 "PHP2Shell" flaws (CVE-2026-109618 and CVE-2026-109619), which affect the PHP software behind dashboards such as Supermon, AllScan, and Allmon2. It also checks several other things worth knowing about any node.

## What It Checks

- **Operating system:** that the node runs ASL3, whether the system still gets security updates, and whether a restart is waiting to finish an earlier update.
- **Updates:** how many updates are waiting, how many are security updates, and whether automatic security updates are turned on. It also finds programs still running old code from before an update, and tells you exactly which services to restart, so you rarely need a full reboot.
- **PHP:** whether PHP is installed, whether it has the PHP2Shell fix, and whether your web server is still running the old PHP from before an update.
- **Exposure to the internet:** whether your node has a public address, whether a firewall and fail2ban are running, and, if the firewall is ufw, whether it lets the whole internet reach your web dashboard. On nodes running the Cockpit web console (included in the ASL3 Raspberry Pi image), it checks whether Cockpit is exposed to the internet.
- **Logins:** whether SSH allows direct root logins or password logins.

## What It Doesn't Do

It doesn't install, remove, or change anything on your node. The only thing it updates is the list of available updates (it runs `apt-get update`), so its answers are current. At the end, it can offer to download and run a separate update script, but only if you say yes (see [Installing Updates for You](#installing-updates-for-you-optional)).

It also checks GitHub for a newer version of itself by reading the small `VERSION` file in this repository. Nothing about your node is sent; it's an ordinary web request, like opening the page in a browser. If GitHub can't be reached, the check is skipped silently. To turn it off, run the script with `--no-update-check`.

It can't see your router, your passwords, or your online accounts. If your router forwards a port to your node, the script can't tell. You should check your router's port forwarding page yourself.

## How to Run It

You'll need a command line on your node. If you normally use your node through a web dashboard only, here's how to get one from a Windows computer.

**Step 1.** On your Windows computer, open Windows PowerShell. (Click Start, type PowerShell, and press Enter.)

**Step 2.** In the PowerShell window, connect to your node over SSH. Replace `yourname` with the user name you log in to the node with, and `192.168.1.50` with your node's address:

```
ssh yourname@192.168.1.50
```

The first time, it asks whether to trust the node. Type `yes` and press Enter, then type your node's password. Nothing appears on screen while you type the password; that's normal. When the prompt changes to show your node's name, the PowerShell window is still open, but what you type now goes to your node.

**Step 3.** Download the script to your node:

```
wget -O asl-node-check.sh https://raw.githubusercontent.com/EtherHamRadio/asl-node-check/main/asl-node-check.sh
```

The `-O asl-node-check.sh` part (a capital letter O) tells wget to replace any older copy. Without it, if you already have the script, wget saves the new download as `asl-node-check.sh.1`, and you keep running the old version without realizing it.

**Step 4.** Run it:

```
sudo bash asl-node-check.sh
```

Type your password if asked. The check takes about a minute, mostly while it downloads the latest list of updates.

## Getting a Newer Version

Starting with version 1.7, the script tells you itself. If a newer version is out, the top of the report says so, with the command to get it:

```
Newer version available: you're running 1.7; version 1.8 is out.
```

The summary at the end repeats the reminder. To update, run Step 3 again, then Step 4.

If your copy is older than 1.7, it can't tell you. The first line of the report shows which version you ran, for example `AllStarLink node security check, version 1.6`. The newest version is listed at the top of this page.

If you see a file named `asl-node-check.sh.1` (or `.2`, `.3`) in your home folder, an older download left it there. You can remove those extra copies:

```
rm asl-node-check.sh.[0-9]*
```

## Installing Updates for You (Optional)

The check only reports. If you'd like help with the updates it finds, a second script, `asl-node-update.sh`, can take care of them for you. Using it is entirely up to you.

When the check finds waiting updates, automatic security updates switched off, services still running old code, or leftovers from removed software still running, it describes the update script at the end of the report and asks:

```
Download the update script? [y/N]
Run it now? [y/N]
```

Each answer is no unless you type `y`. Pressing Enter at either question means no, and if you answer no to everything, nothing on your node changes. If the update script is already in the same folder as the check, the check skips the download question.

The update script checks each item again to make sure it still applies, shows you exactly what it will run, and asks before each step. When it's done, run the check again to confirm:

```
sudo bash asl-node-check.sh
```

**What it can do:**

- Install waiting updates, keeping your current settings files whenever an update offers a newer one.
- Turn on automatic security updates.
- Restart services still running old code from before an update.
- Stop leftovers from software you removed. Removing a package deletes its files but doesn't always stop a program that's already running, and that program can't be restarted because its service is gone.
- Restart Asterisk, after warning you that this briefly drops connected stations.
- Restart the node when one restart is the better choice. This is always the last step, and it warns you first that your SSH session will end.

**Updates apt holds back.** Sometimes installing an update means removing or replacing another package, usually an old library being swapped for a newer one. A regular upgrade skips these, and so does the update script. The check lists them separately, with the command to install them yourself after reading what apt plans to remove.

**What it never touches:** firewall rules, SSH settings, passwords, your router, network services, or your node's settings in `/etc/asterisk`. Those items in the report stay yours to handle.

**Making sure it's the right script.** Each release of the check carries the fingerprint (SHA-256 checksum) of the update script released with it. The check downloads the update script from that same release on GitHub, so the two always match, and it won't run an update script that doesn't match exactly, whether it was damaged in the download or changed afterward.

**Running it yourself.** If you said yes to the download but no to running it, the check tells you the command to run it later. To see what it would do without changing anything, add `--dry-run`:

```
sudo bash asl-node-update.sh --dry-run
```

### About the Saved Files

When you say yes, the check saves a list of what it found in `/var/lib/asl-node-check/findings`, in a folder only root can read. The list holds short codes such as `UPDATES_WAITING`, never commands, and the update script refuses to use it unless root owns it and no other user can change it. The same folder holds the copy of the update script the check runs, plus a short log of what it did, `update.log`.

These files are tiny. The list is a few hundred bytes, the log grows by a line or two per step, and the two scripts are about 28 KB and 14 KB. Even on a small SD card in a Raspberry Pi, they won't affect your node's storage.

To remove the saved files at any time:

```
sudo rm -r /var/lib/asl-node-check
```

## If You Downloaded the Script to Your Computer Instead

Step 3 has the node download the script itself, which avoids copying files around. If you'd rather download it to your Windows computer first and copy it to the node, two things commonly get in the way.

**Your node's SSH may not use port 22.** Many hams move SSH to another port. To find yours, run this on the node's command line:

```
echo $SSH_CONNECTION
```

The last number it prints is the port.

**You may log in with a PuTTY key (.ppk file) instead of a password.** Windows' built-in `scp` can't use PuTTY keys, but PuTTY's own copy tool, `pscp`, can. In Windows PowerShell, in the folder where you saved the script, run this. Replace `2222` with your port (capital `-P`), the key path with yours, and `yourname@192.168.1.50` with your user name and node address. Keep the colon at the end:

```
pscp -P 2222 -i "C:\path\to\your-key.ppk" .\asl-node-check.sh yourname@192.168.1.50:
```

If you use a regular OpenSSH key instead, the built-in `scp` works the same way, with `-P` for the port and `-i` for the key.

## What the Report Looks Like

This is the report from a Raspberry Pi node running the standard ASL3 image, before it was updated. Within ten minutes, every [FIX ] item was cleared.

![Terminal output of the AllStarLink node security check on a Raspberry Pi node. It flags two items to fix: 19 updates waiting, including 13 security updates, and PHP 8.4.26, one release short of the PHP2Shell fix in 8.4.27. It also warns that automatic security updates are off and that several services are running old code, and gives the exact command to fix each item. The summary reads 7 OK, 2 worth a look, 2 to fix.](docs/sample-report.png)

## Reading the Results

Each line starts with one of these labels:

- **[ OK ]** Nothing to do.
- **[info]** Something worth knowing, with no action needed.
- **[WARN]** Worth a look when you have time. A "What to do" line follows.
- **[FIX ]** Needs attention. A "What to do" line follows with the exact command to run.

Start with the [FIX ] items. After you fix them, run the script again to confirm.

## Sharing Your Results

The report doesn't print passwords, IP addresses, or MAC addresses, so it's reasonably safe to paste into a forum or email when asking for help. Read it over before you share it anyway.

## License

MIT License. Copyright (c) 2026 Tom Salzer, KJ7T.

## Version History

- Version 2.4, November 13, 2026: Fixes an apt notice left by the update script. When update script 0.5 and earlier turned on automatic security updates, it saved a backup of the old settings file next to the original, as `/etc/apt/apt.conf.d/20auto-upgrades.bak-` plus a date. apt reads every file in that folder, so every `apt update` and `apt upgrade` afterward printed "N: Ignoring file '20auto-upgrades.bak-...' in directory '/etc/apt/apt.conf.d/' as it has an invalid filename extension." It was harmless, but confusing. Update script 0.6 keeps its backup in `/var/backups` instead, and when it runs it moves any of those old backup copies there too, so the notice goes away. To clear it by hand instead, run `sudo mv /etc/apt/apt.conf.d/20auto-upgrades.bak-* /var/backups/`. The check itself is unchanged apart from its version number.
- Version 2.3, November 12, 2026: Fixes file permissions after the update script runs. The check used a private setting (umask 077) while saving its findings, and the update script it started inherited it, so any file created from scratch during the run came out readable by root only. The one seen in practice was `/etc/apt/apt.conf.d/20auto-upgrades` when the update script turned on automatic security updates: it worked, but every apt command run without sudo then warned "Unable to read /etc/apt/apt.conf.d/20auto-upgrades." The check now keeps that setting to itself, and update script 0.5 sets normal permissions on its own and writes 20auto-upgrades with Debian's usual 644. If a node already has the warning, fix it with `sudo chmod 644 /etc/apt/apt.conf.d/20auto-upgrades`.
- Version 2.2, November 9, 2026: Recognizes leftovers from removed software: a program still running after its package was removed (DVSwitch is a common example). These used to show up as services running old code, and the update script then failed trying to restart them, with "Unit ... not found." The check now lists them separately, with the commands to stop them, and update script 0.4 stops them and has systemd forget them instead of trying a restart.
- Version 2.1, November 5, 2026: The report's wording now matches what the check can do. The line under the title says nothing changes unless you say yes at the end, and each item the update script can handle says so in its "What to do" line, followed by the commands to do it yourself. The update script is unchanged.
- Version 2.0, November 3, 2026: Tells apart updates a regular upgrade can install from ones apt holds back because they'd remove or replace another package. Held-back updates get their own line and the `sudo apt full-upgrade` command, and no longer trigger the update script. Update script 0.3 reports how many updates it actually installed and names any that were held back.
- Version 1.9, November 3, 2026: At the end of the report, offers to download and run the new update script, `asl-node-update.sh` (version 0.2), and runs it only if it matches the fingerprint built into the check. Each answer is no unless you type y. The update script re-checks each item and asks before each step.
- Version 1.8, November 1, 2026: When automatic security updates aren't set up, gives both commands at once (install, then switch on), since installing the package alone doesn't always switch it on.
- Version 1.7, October 30, 2026: Checks GitHub for a newer version of the script and says so at the top of the report and in the summary, with the command to update. Stays silent if GitHub can't be reached. Turn it off with `--no-update-check`. Renamed the script's internal version variable so it can't be overwritten by the operating system's own version information.
- Version 1.6, October 29, 2026: Gives the right fix for automatic security updates. If the unattended-upgrades package is missing, it suggests only installing it, since on Debian that turns automatic updates on by itself. If the package is installed but switched off, it suggests dpkg-reconfigure. Tested on a second ASL3 node (Debian 13 on an x86 laptop).
- Version 1.5, October 22, 2026: Clearer wording when the system hasn't asked for a restart but some programs still need one. Checks whether the Cockpit web console (port 9090) is exposed to the internet.
- Version 1.4, October 22, 2026: When many services, or core parts of the system, are running old code, recommends one reboot instead of a long restart command. Never suggests restarting network services by hand, since that can drop your SSH session.
- Version 1.3, October 22, 2026: Finds services still running old code after an update and gives the command to restart them, noting that restarting Asterisk briefly drops connected stations. Recommends a reboot only when the system asks for one. Reads ufw rules to say whether the web dashboard is open to the whole internet, only to specific addresses, or blocked.
- Version 1.2, October 22, 2026: Checks that the node runs ASL3, and stops with an explanation on HamVoIP, ASL2, or any other system.
- Version 1.1, October 22, 2026: Each suggested command now appears on its own line, so it doesn't wrap mid-command. Fixed spacing in the list of dashboards found. Added the README section on copying the script to a node.
- Version 1.0, October 22, 2026: First version, tested on one ASL3 node.
