#!/bin/env python

from struct import *
import hashlib
from netfilterqueue import NetfilterQueue
import sys



with open("hash_db", "r") as f:
    sha_list = f.readlines()
    sha_list = [x.strip() for x in sha_list]

# calculate sha hash of file
def hash_header(elf_file):
    # delete everything until 7fELF
    # if file not ELF file return, but this should not happen, since iptables filters only ELF...
    index = elf_file.find(b'\x7fELF')
    elf_file = elf_file[index:]
    mag = elf_file[:4]
    elf_file = elf_file[4:]
    if mag != b'\x7fELF':
        return 0
    eiclass = elf_file[:1]
    elf_file = elf_file[1:]
    
    if eiclass == b'\x01':
        # 32-bit file
        # fallback if packet is smaller than normal header size
        if len(elf_file) < 79:
            sha = hashlib.sha512(elf_file).hexdigest()
            return sha
        # parse ELF header
        data, eiversion, osabi, abiversion, pad, etype, machine, eversion, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = unpack('ssss7s2s2s4s4s4s4s4s2s2s2s2s2s2s', elf_file[:47])
        elf_file = elf_file[47:]
        head = mag + eiclass + data + eiversion + osabi + abiversion + pad + etype + machine + eversion + entry + phoff + shoff + flags + ehsize + phentsize + phnum + shentsize + shnum + shstrndx
        # parse program header
        ptype, poffset, pvaddr, ppaddr, pfilesz, pmemsz, pflags, palign = unpack('4s4s4s4s4s4s4s4s', elf_file[:32])
        elf_file = elf_file[32:]
        prog = ptype + poffset + pvaddr + ppaddr + pfilesz + pmemsz + pflags + palign
    else:
    
        # 64-bit file
        # fallback if packet is smaller than normal header size
        if len(elf_file) < 115:
            sha = hashlib.sha512(elf_file).hexdigest()
            return sha
        # parse ELF header
        data, eiversion, osabi, abiversion, pad, etype, machine, eversion, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = unpack('ssss7s2s2s4s8s8s8s4s2s2s2s2s2s2s', elf_file[:59])
        elf_file = elf_file[59:]
        head = mag + eiclass + data + eiversion + osabi + abiversion + pad + etype + machine + eversion + entry + phoff + shoff + flags + ehsize + phentsize + phnum + shentsize + shnum + shstrndx
        # parse program header
        ptype, pflags, poffset, pvaddr, ppaddr, pfilesz, pmemsz, palign = unpack('4s4s8s8s8s8s8s8s', elf_file[:56])
        elf_file = elf_file[56:]
        prog = ptype + pflags + poffset + pvaddr + ppaddr + pfilesz + pmemsz+ palign
    
    # print(head + prog)
    sha = hashlib.sha512(head + prog).hexdigest()

    return sha


# print(int.from_bytes(pmemsz, byteorder='little'))

def evaluate_packet(pkt):
    try:
        sha = hash_header(pkt.get_payload())
        sha_list.index(sha)
        pkt.accept()
        print("Packet accepted")
    except ValueError as e:
        #with open("hash_db", "a") as out:
        #    if sha != 0:
        #        out.write(sha + "\n")
        #print(sha)
        pkt.drop()
        #pkt.accept()
        print("Packet dropped")
    except:
        #print(pkt.get_payload())
        print(sys.exc_info())
        pkt.drop()
    



nf = NetfilterQueue()
nf.bind(0, evaluate_packet)
try:
    nf.run()
except KeyboardInterrupt:
    pass

nf.unbind()
