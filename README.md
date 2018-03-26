# Networking Scripts

Collection of scripts for network traffic analyzation I recently used.

## `elf_parser.py`

Declines of accepts ELF files on outgoing network interface. By default all ELF files are put into `netfilterqueue` by `iptables`.

Reads header of outgoing ELF files (filtered by NetfilterQueue), hashes header and compares it to a whitelist of header hashes. Whitelist created by previously hashed ELF file headers in `/bin/`folder.

## `mk_hash_elf.py`

Similar to above script, was used to create whitelist hashes.


## `mirai_inf.py:`

Compares attacks of mirai (and other common malware) bots on a set of devices and a honeypot. Lists all IPs that attacked both, as well as malware family, along with some TCP header information and timestamps.


## `pcap_analyze.py`

Analyzes pcap files and lists information about number of total/telnet/ssh/http/ICMP packets sent to/by each device/IP. Correlates with cron deamon for capturing and structuring pcap files.
