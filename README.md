# asl-node-check

Version 1.5, October 22, 2026

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

It doesn't install, remove, or change anything on your node. The only thing it updates is the list of available updates (it runs `apt-get update`), so its answers are current.

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
wget https://raw.githubusercontent.com/EtherHamRadio/asl-node-check/main/asl-node-check.sh
```

**Step 4.** Run it:

```
sudo bash asl-node-check.sh
```

Type your password if asked. The check takes about a minute, mostly while it downloads the latest list of updates.

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

- Version 1.5, October 22, 2026: Clearer wording when the system hasn't asked for a restart but some programs still need one. Checks whether the Cockpit web console (port 9090) is exposed to the internet.
- Version 1.4, October 22, 2026: When many services, or core parts of the system, are running old code, recommends one reboot instead of a long restart command. Never suggests restarting network services by hand, since that can drop your SSH session.
- Version 1.3, October 22, 2026: Finds services still running old code after an update and gives the command to restart them, noting that restarting Asterisk briefly drops connected stations. Recommends a reboot only when the system asks for one. Reads ufw rules to say whether the web dashboard is open to the whole internet, only to specific addresses, or blocked.
- Version 1.2, October 22, 2026: Checks that the node runs ASL3, and stops with an explanation on HamVoIP, ASL2, or any other system.
- Version 1.1, October 22, 2026: Each suggested command now appears on its own line, so it doesn't wrap mid-command. Fixed spacing in the list of dashboards found. Added the README section on copying the script to a node.
- Version 1.0, October 22, 2026: First version, tested on one ASL3 node.
