#!/bin/env python

from struct import *
import hashlib
import os
import sys

# walk through a folder and calculate sha512 hash of each ELF file header
def walk(path, hashfile):
    for root, dirs, files in os.walk(path):
        for names in files:
            try:
                with open("/bin/" + names, "rb") as f:
                    mag = unpack('4s', f.read(4))[0]
                    # if file is not ELF, continue with next file
                    if mag != b'\x7fELF':
                        continue
                    # read EI_CLASS field to determine 32/64-bit
                    eiclass = unpack('s', f.read(1))[0]
                    # print(names)
    
                    if eiclass == b'\x01':
                        # 32-bit file
                        # parse ELF header
                        data, eiversion, osabi, abiversion, pad, etype, machine, eversion, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = unpack('ssss7s2s2s4s4s4s4s4s2s2s2s2s2s2s', f.read(47))
                        head = mag + eiclass + data + eiversion + osabi + abiversion + pad + etype + machine + eversion + entry + phoff + shoff + flags + ehsize + phentsize + phnum + shentsize + shnum + shstrndx
                        # parse program header
                        ptype, poffset, pvaddr, ppaddr, pfilesz, pmemsz, pflags, palign = unpack('4s4s4s4s4s4s4s4s', f.read(32))
                        prog = ptype + poffset + pvaddr + ppaddr + pfilesz + pmemsz + pflags + palign
    
                    else:
                        # 64-bit file
                        # parse ELF header
                        data, eiversion, osabi, abiversion, pad, etype, machine, eversion, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = unpack('ssss7s2s2s4s8s8s8s4s2s2s2s2s2s2s', f.read(59))
                        head = mag + eiclass + data + eiversion + osabi + abiversion + pad + etype + machine + eversion + entry + phoff + shoff + flags + ehsize + phentsize + phnum + shentsize + shnum + shstrndx
                        # parse program header
                        ptype, pflags, poffset, pvaddr, ppaddr, pfilesz, pmemsz, palign = unpack('4s4s8s8s8s8s8s8s', f.read(56))
                        prog = ptype + pflags + poffset + pvaddr + ppaddr + pfilesz + pmemsz+ palign
                    
                    # calc hash
                    sha = hashlib.sha512(head + prog).hexdigest()
                    print(sha)
                    hashfile.write(sha + "\n")

            # if something went wrong
            except:
                print(sys.exc_info())
                #pass

# specify all directories for building hash
with open("sha_values", "a") as f:
    walk("~/test", f)
