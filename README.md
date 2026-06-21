# CR-18 / Module 3 / N3c — Advanced ARP Poisoning

CADMUS Cyber Range scenario. The trainee can't connect to telnet directly (iptables whitelist drops their SYN at vm1), so they have to MITM vm2's authenticated session and use an `etterfilter`-compiled script to rewrite the bytes `bait.txt` → `flag.txt` in flight. vm1 runs the modified command under vm2's session; the flag flows back across the trainee's wire.

## Topology

A single `192.168.25.0/24` segment behind one router with a `10.10.10.0/24` WAN.

| Node   | Image                  | IP             | Role |
| ------ | ---------------------- | -------------- | ---- |
| router | debian-12-x86_64       | 192.168.25.1   | LAN gateway. Not involved in the attack. |
| vm1    | ubuntu-noble-x86_64    | 192.168.25.10  | `telnetd` via `inetd` on tcp/23. iptables whitelist allows only vm2; everything else gets DROPped. Holds `bait.txt` and `flag.txt` in the telnet user's home. |
| vm2    | ubuntu-noble-x86_64    | 192.168.25.20  | Systemd timer fires every 30 s and runs an `expect` script that telnets to vm1, executes `cat bait.txt`, logs out. |
| vma    | kali-2026.1-x86_64     | 192.168.25.30  | Trainee workstation. `ettercap-text-only` + `dsniff` pre-installed. |

## Provisioning

`provisioning/playbook.yml` runs three plays:
- **vm1**: installs `inetutils-telnetd` + `inetutils-inetd` + `iptables-persistent`, creates the telnet user (password from APG, `/bin/bash` shell so PAM accepts the login), drops the bait file and the flag file, enables telnetd in inetd, applies the iptables ruleset (only `192.168.25.20` may reach tcp/23).
- **vm2**: installs `expect` + `telnet`, deploys an expect script that logs in to vm1 and runs `cat /home/<telnet_user>/bait.txt`, behind a systemd timer firing every 30 s.
- **vma**: fixes the `/etc/hosts` hostname entry (sudo complains otherwise on Kali), installs `dsniff` (for arpspoof), `telnet`, `python3-scapy`, and `python3-netfilterqueue`, drops a pre-built rewriter script at `/usr/local/sbin/mitm-rewrite.py`, and provisions the trainee user `user` / `Password123` via `user-access`.

APG variables in `variables.yml`:
- `telnet_user` (type=username) — the local user on vm1 that vm2 logs in as
- `telnet_pass` (type=password, length=12) — captured by the trainee in level 1
- `flag` (type=password, length=16) — written verbatim to `flag.txt`, retrieved through the filter rewrite in level 2

## Trainee workflow

1. Console (Open GUI) into **vma** as `user` / `Password123`.
2. Try `telnet 192.168.25.10` — it hangs. iptables on vm1 drops it.
3. Enable IP forwarding, bidirectional `arpspoof` to get on the wire (same recipe as N3b).
4. Open Wireshark on `eth1`, filter `tcp.port == 23`, Follow → TCP Stream, read the password off vm2's next session.
5. Submit the password (level 2).
6. Send tcp/23 forward traffic to NFQUEUE: `sudo iptables -I FORWARD -p tcp --dport 23 -j NFQUEUE --queue-num 1`
7. Run the pre-deployed rewriter: `sudo python3 /usr/local/sbin/mitm-rewrite.py`
8. Watch vm1's responses in parallel: `sudo tcpdump -ni eth1 -A 'tcp port 23 and src host 192.168.25.10'`
9. Wait ≤30 s. When the rewriter logs `[+] rewrote bait.txt -> flag.txt`, vm1 has just run the rewritten `cat /home/<user>/flag.txt` under vm2's session. The flag appears in vm1's response payload visible in tcpdump.
10. Submit the flag (level 3).

## Tools used

`arpspoof` (from `dsniff`) for the bidirectional ARP MITM, `tcpdump` and `wireshark` for capture, `iptables -j NFQUEUE` to route TCP/23 forward traffic to userland, `python3-scapy` + `python3-netfilterqueue` for the in-flight payload rewrite via `/usr/local/sbin/mitm-rewrite.py`.

Why not ettercap or bettercap: bettercap's `arp.spoof` is built for victim ↔ gateway, not victim ↔ victim. Ettercap's filter mechanism works in theory but its `arp:remote` MITM has reliability issues in current versions — the spoofing is announced as active but data forwarding intermittently breaks. NFQUEUE + a Python script gives you a deterministic packet-modifier on top of arpspoof's proven MITM.

## MITRE mapping

- `T1557.002` Adversary-in-the-Middle / ARP Cache Poisoning
- `T1040` Network Sniffing
- `T1565.002` Data Manipulation / Transmitted Data Manipulation
- `T1041` Exfiltration Over C2 Channel
