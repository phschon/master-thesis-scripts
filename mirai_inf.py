#!/usr/bin/env python

# Useful:
# f = rdpcap(...)
# pkt=f[2]
# IP in prk
# ptk[IP].src
# ptk[TCP].dport
# ptk[<protocol>].<field>
# ptk[TCP].flags = "A" / == "A"


# Analyze pcap files and extract information about mirai:
# which IP attacked IoT and cowrie
# on which dates
# from which ports
# which mirai family


from scapy.all import *
import dpkt
import time
import sys
import glob
import os
import re
import datetime

inf_mirai = []
inf_bashlite = []
inf_xor = []
inf_coin = []
keywords = []
dates = []

# first analyze pcap files and extract all needed information:

# check if any files have been progressed
os.chdir("~/sniffing")
try:
    with open('~/mirai_out', 'r') as m:
        l = m.readline()
        if l.startswith('#'):
            dates = l[1:].split(',')
except FileNotFoundError:
    pass


now = datetime.datetime.now()
# process all files
for f in glob.glob("*wan"): # 09-12-2017_wan"):
    # but skip those, that were already processed
    if str(f) in dates:
        print('Skipping ' + str(f))
        continue
    # if current file is not today's, add it to processed fils
    if not str(f) == datetime.datetime.now().strftime("%d-%m-%Y") + '_wan':
        dates.append(str(f))
    else:
        # today's capture is not finished, process it, but do not add it to processed files
        print('Not append today: ' + str(f))

    with PcapReader(f) as packets:
        for p in packets:
            if (IP in p) and (TCP in p) and (Raw in p):
                if p[IP].src.startswith(<HIDDEN>):
                    # this IP belongs to honeypot or iot, outgoing connections ignored
                    continue
                try:
                    load = p[Raw].load.decode("utf-8")
                    # contians busybox command -> most likely mirai
                    if 'busybox' in load:
                        # extract command used with busybox
                        l = re.findall(r"[\w']+", load)
                        keys = [i for i, x in enumerate(l) if x == 'busybox']
                        for i in keys:
                            key = l[min(i+1, len(l) - 1)]
                            # these commands are not malware related
                            if not key  in ['ps', 'cat', 'wget', 'dd', 'echo', 'cp', 'rm', '', 'ec', 'chmod', 'busybox', 'printf', 'bs', 'c', 'ch', 'chmo', 'r', 'bin', 'cd', 'e', 'head', 'tftp', 'wge', 'while', 'ftpget']:
                                # append IP, port and malware string
                                inf_mirai.append(",".join([p[IP].src + ":" + str(p[TCP].sport), p[IP].dst + ":" + str(p[TCP].dport), str(p[IP].ttl), key, str(f)[:-4]]))
                                keywords.append(key)
                    # ntpd included in bashlite script
                    elif 'ntpd' in load:
                        inf_bashlite.append(",".join([p[IP].src + ":" + str(p[TCP].sport), p[IP].dst + ":" + str(p[TCP].dport), str(p[IP].ttl), 'xor', str(f)[:-4]]))
                    # coin miner and mrblack files
                    elif 'netwrite' in load or 'lx63' in load:
                        inf_coin.append(",".join([p[IP].src + ":" + str(p[TCP].sport), p[IP].dst + ":" + str(p[TCP].dport), str(p[IP].ttl), 'coin', str(f)[:-4]]))

                except UnicodeDecodeError:
                    pass

# remove dublciates
inf_mirai = sorted(set(inf_mirai))
keywords = sorted(set(keywords))

# write bashlite to file
with open('~/bashlite_out', 'a') as m:
    # this wont work....only for the first time
    m.write('#' + ','.join(dates) + "\n")

    for x in inf_bashlite:
        m.write(x + "\n")

    m.write("\n\n\n")

# write coin and mrblack to file
with open('~/coin_out', 'a') as m:
    # this wont work....only for the first time
    m.write('#' + ','.join(dates) + "\n")

    for x in inf_coin:
        m.write(x + "\n")

    m.write("\n\n\n")

# write mirai to file
with open('~/mirai_out', 'a') as m:
    # this wont work....only for the first time
    m.write('#' + ','.join(dates) + "\n")

    for x in inf_mirai:
        m.write(x + "\n")

    m.write('# number of keywords: ' + str(keywords) + "\n")

    m.write("\n\n\n")



# second, use above information to find out which IP attacked cowrie and IoT:
for dat in ['mirai_out', 'coin_out', 'bashlite_out']:
    d = {}
    with open('~/' + dat, 'r') as f:
        for l in f:
            # not needed information
            if l.startswith('{') or l.startswith('#'):
                continue
            l = l.strip()
            # split at , and :
            t = re.findall(r"[^,:]+", l)
            # append to dictionary
            # each entry: [ [dstIP], [malware string], [ports], [attack dates]  ]
            if len(t) > 1:
                if t[0] in d:
                    if not t[2] in d[t[0]][0]:
                        d[t[0]][0].append(t[2])
                    if not t[5] in d[t[0]][1]:
                        d[t[0]][1].append(t[5])
                    if not t[1] in d[t[0]][2]:
                        d[t[0]][2].append(t[1])
                    if not t[6] in d[t[0]][3]:
                        d[t[0]][3].append(t[6])
                else:
                    # srcIP not in dict
                    d[t[0]] = [[t[2]] ,[t[5]], [t[1]], [t[6]] ]
    
    try:
        os.remove('~/' + dat + '_sol')
    except:
        pass
    output = 0
    for key, value in d.items():
        # if at least to dstIPs are attacked by one srcIP
        if len(value[0]) > 2:
            # honeypot IPs
            ip = <HIDDEN>
            # cowrie and IoT attacked?
            if len([word for word in ip if word in value[0]]) and len([word for word in value[0] if word not in ip]):
                output = output + 1
                out = key + ": " + str(len(value[0])) + " IPs: " + str(value[0]) + " " + str(len(value[1])) + " bots: " + str(value[1]) + " " + str(len(value[2])) + " ports: " + str(value[2]) + " " + str(len(value[3])) + " days: " + str(value[3]) + "\n"
                # write to file
                with open('~/' + dat + '_sol', 'a') as m:
                    m.write(out + "\n")
    
    print(output)
    with open('~/' + dat + '_sol', 'a') as m:
        m.write(output)
