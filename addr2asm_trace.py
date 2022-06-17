#!/usr/bin/env python3

import os.path
import sys
import argparse
import re

# examples
#address                   perms offset  dev   inode                      pathname
#7ffff7f72000-7ffff7f81000 rw-p 00000000 00:00 0 
#7ffff7fc0000-7ffff7fc4000 r--p 00000000 00:00 0                          [vvar]
#7ffff7ffd000-7ffff7fff000 rw-p 00036000 103:03 25431493                  /usr/lib/ld-linux-x86-64.so.2
maps_re = re.compile("([^-]+)-([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) *(.*)")

def read_maps(path):
    maps=[]
    with open(path, "r") as f:
        for line in f.readlines():
            m = maps_re.fullmatch(line.strip())
            if m != None:
                if m.groups()[5] == '0':
                    continue
                start = int(m.groups()[0], base=16)
                stop = int(m.groups()[1], base=16)
                offset = int(m.groups()[3], base=16)
                name = m.groups()[-1]
                maps.append((start,stop,offset,os.path.basename(name)))
    return maps

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog='addr2asm_trace.py',
        description='Reads an execution address trace and an objdump output and generates an asm trace',
        epilog='Use \'--\' before PATH and PREFIX to separate from options.',
        argument_default=argparse.SUPPRESS
    )
    parser.add_argument(
        '--prepend-bin',
        help='Add before start (given in hex)'
    )   
    parser.add_argument(
        '--append-bin',
        help='Add after end (given in hex)'
    )
    parser.add_argument(
        '--prepend-address',
        action='store_true',
        help='Add address to output'
    )
    parser.add_argument(
        '--print-opcodes-hex',
        action='store_true',
        help='Print opcodes as hex'
    )
    parser.add_argument(
        '--print-opcodes-bin',
        metavar='OUTFILE',
        nargs='?',
        help='Print opcodes as binary (Not compatible with other print options.)'
    )
    parser.add_argument(
        '--print-instructions',
        action='store_true',
        help='Print instructions'
    )
    parser.add_argument(
        'maps',
        metavar='MAPS',
        nargs=1,
        help='Maps file'
    )
    parser.add_argument(
        'addrtrace',
        metavar='ADDRTRACE',
        nargs=1,
        help='Address trace'
    )
    parser.add_argument(
        'objdump',
        metavar='OBJDUMP',
        nargs='+',
        help='Objdump output'
    )


    args = parser.parse_args()
    args = vars(args)

    preaddr = True if "prepend_address" in args else False
    maps_file = args["maps"][0]
    objdump_files = args["objdump"]
    addrtrace_file = args["addrtrace"][0]
    opcodes_file = None
    print_op_bin = False
    if "print_opcodes_bin" in args:
        opcodes_file = args["print_opcodes_bin"]
        print_op_bin = True
    print_op_hex = True if "print_opcodes_hex" in args else False
    print_instr = True if "print_instructions" in args else False
    prepend_bin = bytes() if "prepend_bin" not in args else bytes.fromhex(args["prepend_bin"])
    append_bin = bytes() if "append_bin" not in args else bytes.fromhex(args["append_bin"])
    #print(objdump_files)

    maps = read_maps(maps_file)

    objdump = {}

    for of in objdump_files:
        oname = os.path.basename(of)
        alist = []
        for m in maps:
            if m[3] in oname:
                alist.append(m)
        olist = {}
        ilist = {}
        with open(of,"r") as f:
            for l in f:
                if l[0] != " ":
                    continue
                la = l.split("\t")
                addr = la[0].strip().strip(":")
                addr = int(addr, base=16)
                opc = la[1].strip()
#                col_index = l.find(":")
#                if col_index == -1:
#                    continue
#                addr = int(l[0:col_index].strip(), base=16)
#                instr = l[col_index+1:].strip()
                instr = la[2].strip()
                if print_op_bin == True:
                    olist[addr] = bytes.fromhex(opc)
                else:
                    olist[addr] = opc
                ilist[addr] = instr
        if len(alist) == 0:
            continue
        objdump[oname] = (alist,olist,ilist)

    of = None
    if print_op_bin:
        of = open(opcodes_file, "wb" )
        of.write(prepend_bin)
    with open(addrtrace_file, "r" ) as f:
#        if preaddr == True:
        for l in f:
            if l[0] == "#":
                continue
            windex = l.find(" ")
            addr = l[:windex].lstrip("0x").strip()
            ins = l[windex+1:] if windex != -1 else None
            iaddr = int(addr, base=16)
            raddr = None
            olist = None
            ilist = None
            opc = None
            for oname in objdump:
                o = objdump[oname]
                infos = o[0]
                for info in infos:
                    #print(oname, addr, iaddr, info[0],"-",info[1])
                    if iaddr >= info[0] and iaddr <= info[1]:
                        raddr = iaddr - info[0] + info[2]
                        olist = o[1]
                        ilist = o[2]
                    #    print("found")
                        break
                if olist != None:
                    break
            if raddr == None:
                instr = None
            else:
                #print(olist)
                #if ins == None:
                #    print(iaddr, addr, raddr, hex(raddr))
                #else:
                #    print(iaddr, addr, raddr, hex(raddr), ins)
                opc = olist[raddr] if raddr in olist else bytes()
                instr = ilist[raddr] if raddr in ilist else None
            if print_op_bin == True:
                of.write(opc)
            else:
                if preaddr == True:
                    if print_op_hex == True:
                        print(addr+":    ",opc,instr)
                    else:
                        print(addr+":    ",instr)
                else:
                    if print_op_hex:
                        print(opc,instr)
                    else:
                        print(instr)
#        else:
#            for l in f:
#                if l[0] == "#":
#                    continue
#                addr = l.lstrip("0x").strip()
#                instr = objdump[addr] if addr in objdump else None
#                print(instr)
    if print_op_bin == True:
        of.write(append_bin)
        of.close()
