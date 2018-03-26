#!/usr/bin/env python

# Useful:
# f = rdpcap(...)
# pkt=f[2]
# IP in prk
# ptk[IP].src
# ptk[TCP].dport
# ptk[<protocol>].<field>
# ptk[TCP].flags = "A" / == "A"

from scapy.all import *
import dpkt
import time
import sys


# packet counter
counter = 0

# dict to store and open files
files = {}

# dict for connection statistics
stats = {}
error = 0

#dict for port translation
# ports = {0:0, 22:22, 23:23, 80:80, "ssh":22, "telnet":23, "www_http": 80}

# dict for lan/wan translation, used for easy log function handling and file writing
transl = <HIDDEN>

# open all relevant files
def open_all(path):
    global files
    files['ubiquiti:'] = open(path + 'ubiquiti/ubiquiti','w')
    files['ubiquiti:22'] = open(path + 'ubiquiti/ubiquiti_ssh','w')
    files['ubiquiti:80'] = open(path + 'ubiquiti/ubiquiti_http','w')
    files['ubiquiti:23'] = open(path + 'ubiquiti/ubiquiti_telnet','w')
    files['ubiquiti:0'] = open(path + 'ubiquiti/ubiquiti_icmp','w')
    files['smc:'] = open(path + 'smc/smc','w')
    files['smc:0'] = open(path + 'smc/smc_icmp','w')
    files['smc:22'] = open(path + 'smc/smc_ssh','w')
    files['smc:80'] = open(path + 'smc/smc_http','w')
    files['smc:23'] = open(path + 'smc/smc_telnet','w')
    files['dreambox:'] = open(path + 'dreambox/dreambox','w')
    files['dreambox:0'] = open(path + 'dreambox/dreambox_icmp','w')
    files['dreambox:22'] = open(path + 'dreambox/dreambox_ssh','w')
    files['dreambox:80'] = open(path + 'dreambox/dreambox_http','w')
    files['dreambox:23'] = open(path + 'dreambox/dreambox_telnet','w')
    files['hfw:22'] = open(path + 'hfw/hfw_ssh','w')
    files['hfw:0'] = open(path + 'hfw/hfw_icmp','w')
    files['hfw:80'] = open(path + 'hfw/hfw_http','w')
    files['hfw:23'] = open(path + 'hfw/hfw_telnet','w')
    files['hfw:'] = open(path + 'hfw/hfw','w')
    files['ipd:22']= open(path + 'ipd/ipd_ssh','w')
    files['ipd:80']= open(path + 'ipd/ipd_http','w')
    files['ipd:23']= open(path + 'ipd/ipd_telnet','w')
    files['ipd:'] = open(path + 'ipd/ipd','w')
    files['ipd:0'] = open(path + 'ipd/ipd_icmp','w')
    files['nonip:0'] = open(path + 'nonip', 'w')
    files['kippo:'] = open(path + 'kippo/kippo', 'w')
    files['kippo:0'] = open(path + 'kippo/kippo_icmp', 'w')
    files['kippo:22'] = open(path + 'kippo/kippo_ssh', 'w')
    files['kippo:23'] = open(path + 'kippo/kippo_telnet', 'w')
    files['kippo:80'] = open(path + 'kippo/kippo_http', 'w')
    files['cowrie:'] = open(path + 'cowrie/cowrie', 'w')
    files['cowrie:0']= open(path + 'cowrie/cowrie_icmp', 'w')
    files['cowrie:22']= open(path + 'cowrie/cowrie_ssh', 'w')
    files['cowrie:23']= open(path + 'cowrie/cowrie_telnet', 'w')
    files['cowrie:80']= open(path + 'cowrie/cowrie_http', 'w')


# close all open files
def close_all():
    global files
    for p in files:
        files[p].close()


# one function to log them all.....
# parameters: address, port, packet and flag
# flag is used to generate statistics about number of outgoing and incoming packages
def log(ad, po, p, flag=" "):
    global files
    global stats
    stats[ad + flag] = stats[ad + flag] + 1 if (ad + flag) in stats else 1
    # print(ad, str(po), repr(p))
    files[ad + ":" + str(po)].write(flag + ": " + str(p.time) + "\n")
    files[ad + ":" + str(po)].write(repr(p))
    files[ad + ":" + str(po)].write("\n\n")
    files[ad + ":" + str(po)].flush()


# do scanning here, first for loop is placeholder for continuing scanning, atm not used
def scan(open_path):
    global counter
    global transl
    global error
    with PcapReader(open_path) as packets:
        for i,p in enumerate(packets):
            if i < counter:
                continue
            # log packets without IP header
            try:
                if not IP in p:
                    log("nonip",0, p)
                elif Raw in p:
                    # check which IP/device the packet belongs to
                    if p[IP].src in transl:
                        a = transl[p[IP].src]
                        flag = "o"
                    elif p[IP].dst in transl:
                        a = transl[p[IP].dst]
                        flag = "i"
                    else:
                        # packet not from or to a monitored device
                        continue
                    if UDP in p:
                        if p[UDP].dport in (22, 23, 80):
                            log(a, p[UDP].dport, p, flag)
                        elif p[UDP].sport in (22, 23, 80):
                            log(a, p[UDP].sport, p, flag)
                        # else:
                            # no special monitored service
                        #     log(a, 0, p, flag)

                    elif TCP in p:
                        if p[TCP].dport in (22, 23, 80, "ssh", "telnet", "www_http"):
                            log(a, p[TCP].dport, p, flag)
                        elif p[TCP].sport in (22, 23, 80, "ssh", "telnet", "www_http"):
                            log(a, p[TCP].sport, p, flag)
                        # else:
                        #     log(a, 0, p, flag)

                    elif ICMP in p:
                        log(a, 0, p, flag)

                    else:
                        # print(repr(p))
                        log(a, "", p, flag)

                counter = counter + 1
                # print(i)
            except:
                path = sys.argv[1] if len(sys.argv) > 1 else 'sniffing'
                with open('~/' + path + '/error', 'w') as er:
                    # WTF?
                    # scapy cannot handle this packets, saved in binary pcap
                    # er.write((p)
                    error = error +1
                    # er.write("\n\n")
        print(counter)

def write_stats(path, mode):
    global stats
    global error
    # debug variable to print stats
    f = True
    output = []
    with open(path + 'stats_' + mode, 'w') as a:
        for p in stats:
            direction = p[-1:]
            name = p[:-1]
            output.append(name + " " + ("incoming" if direction == "i" else "outgoing") + " packets: " + str(stats[p]))
        output.append("Error packets: " + str(error))
        for p in sorted(output):
            a.write(p + "\n")
            if f: print (p)
    # print("Error packets: " + str(error))
    stats = {}
    error = 0




print('##################################################\nStarting.')

# if called without parameter, use default ~/sniffng path
# otherwise use special path for each day given via argument
# default pcap and tcpdump pcap file path, default can be changed
if len(sys.argv) > 1:
    path1 = '~/' + sys.argv[1] + "/wan/"
    path2 = '~/' + sys.argv[1] + "/lan/"
    open_path1 = "~/sniffing/" + sys.argv[1] + "_wan"
    open_path2 = "~/sniffing/" + sys.argv[1] + "_lan"

    print("Opening subfolder: " + path1, path2, "opening file: " + open_path1, open_path2)

    # if path is provided, sleep 60s (correlating with cron daemon)
    print("Entering sleep.")
    time.sleep(60)
    print("Done sleeping.")

    print("\nStarting WAN:")
    open_all(path1)
    scan(open_path1)
    close_all()
    write_stats('~/' + sys.argv[1] + '/', 'wan')

    print("\nStarting LAN:")
    counter = 0
    open_all(path2)
    scan(open_path2)
    close_all()
    write_stats('~/' + sys.argv[1] + '/', 'lan')
else:
    # default file is sniffing/new_log is used when not called via bash script/cron
    open_path = "~/sniffing/new_log"
    path="sniffing/"

    open_all(path)
    scan(open_path)
    close_all()
    write_stats("all")



print("Stopping.\n##################################################\n")

