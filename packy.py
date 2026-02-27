from pwn import ELF
from pwn import asm
from pwn import p8,p16,p32,p64,u8,u16,u32,u64
from pwnlib.elf.datatypes import *
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_p_flags
from elftools.elf.constants import (P_FLAGS, RH_FLAGS, SH_FLAGS, SUNW_SYMINFO_FLAGS, VER_FLAGS)

import matplotlib.pyplot as plt
import argparse
from io import SEEK_SET, SEEK_CUR, SEEK_END
from types import SimpleNamespace


def set_offsets(bits):
    global ehdr_offsets, phdr_offsets, phdr_size, pword, paddr, poff
    # first item of tuple is offset, second is packing method
    if bits == 32:
        ehdr_offsets = SimpleNamespace(**{"e_ident": (0,p16),
            "e_type": (16,p16),
            "e_machine": (18,p16),
            "e_version": (20,p32),
            "e_entry": (24,p32),
            "e_phoff": (28,p32),
            "e_shoff": (32,p32),
            "e_flags": (36,p32),
            "e_ehsize": (40,p16),
            "e_phentsize": (42,p16),
            "e_phnum": (44,p16),
            "e_shentsize": (46,p16),
            "e_shnum": (48,p16),
            "e_shstrndx": (50,p16)})        

        phdr_offsets = SimpleNamespace(**{"p_type": (0,p32),
            "p_offset": (4,p32),
            "p_vaddr": (8,p32),
            "p_paddr": (12,p32),
            "p_filesz": (16,p32),
            "p_memsz": (20,p32),
            "p_flags": (24,p32),
            "p_align": 28})
        phdr_size = 32

        shdr_offsets = SimpleNamespace(**{
          "sh_name": (0,p32),
          "sh_type": (4,p32),
          "sh_flags": (8,p32),
          "sh_addr": (12,p32),
          "sh_offset": (16,p32),
          "sh_size": (20,p32),
          "sh_link": (24,p32),
          "sh_info": (28,p32),
          "sh_addralign": (32,p32),
          "sh_entsize": (36,p32)})
        shdr_size = 40
    else:
        ehdr_offsets = SimpleNamespace(**{"e_ident": (0,p16),
            "e_type": (16,p16), 
            "e_machine": (18,p16), 
            "e_version": (20,p32), 
            "e_entry": (24,p64),
            "e_phoff": (32,p64), 
            "e_shoff": (40,p64),
            "e_flags": (48,p32),
            "e_ehsize": (52,p16),
            "e_phentsize": (54,p16),
            "e_phnum": (56,p16),
            "e_shentsize": (58,p16),
            "e_shnum": (60,p16),
            "e_shstrndx": (62,p16)})
        
        phdr_offsets = SimpleNamespace(**{"p_type": (0,p32),
            "p_flags": (4,p32),
            "p_offset": (8,p64),
            "p_vaddr": (16,p64),
            "p_paddr": (24,p64),
            "p_filesz": (32,p64),
            "p_memsz": (40,p64),
            "p_align": 48})
        phdr_size = 56
        
        shdr_offsets = SimpleNamespace(**{
          "sh_name": (0,p32),
          "sh_type": (4,p32),
          "sh_flags": (8,p64),
          "sh_addr": (16,p64),
          "sh_offset": (24,p64),
          "sh_size": (32,p64),
          "sh_link": (40,p32),
          "sh_info": (44,p32),
          "sh_addralign": (48,p64),
          "sh_entsize": (56,p64)})
        shdr_size = 64



################################### entropy ################################### 
def check_freq(data):
    freq = {}
    for byte in data:
        if byte in freq:
            freq[byte] += 1
        else:
            freq[byte] = 1

    return freq

def draw_plot(segDatTouple, sampleLength = 256, threshold=92):
    #print(segDatTouple)
    groups = []
    for (segment,data,_) in segDatTouple:
        samples = [data[i:i+sampleLength] for i in range(0, len(data), sampleLength)]
        entropy_bars = []
        for sample in samples:
            ent = get_entropy(sample)
            ent = 1.0 - (ent / min(sampleLength, len(sample)))
            ent *= 100.0
            entropy_bars.append(ent)
        groups.append(entropy_bars)
    
    x_values = None
    for idx, group in enumerate(groups):
        if x_values == None:
            x_values = range(len(group))
        else:
            x_values = range(x_values.stop, x_values.stop + len(group))
       # col = ['red' if h > 98 else 'blue' for h in entropy_bars]
        plt.bar(x_values, group, width=1, label=f"{describe_p_flags(segDatTouple[idx].segment['p_flags'])}")
        
    plt.xticks([])
    plt.yticks(range(0, 100, 2))
    plt.ylabel('Entropy')
    plt.xlabel('Segments')
    plt.legend()
    plt.show()

# https://nfsec.pl/hakin9/entropy.pdf
def get_entropy(data):
    array = [0] * 256
    for i in range(len(data)):
        array[data[i]] += 1
    entropy = 0.0
    for i in range(256):
        entropy += (array[i] / len(data)) * array[i]

    return entropy

################################### /entropy ################################### 

class SegmentDataTuple:
    def __init__(self, segment, data, phdr_idx):
        self.segment = segment
        self.data = data
        self.phdr_idx = phdr_idx
    def __iter__(self):
        yield self.segment
        yield self.data
        yield self.phdr_idx

def seek_write(f, offset, value):
    f.seek(offset)
    f.write(value)

def create_loader(base_addr, text_seg_addr, text_seg_size, oep_addr):
    # x64 just for now
    # also pwntools use gas by default so only gas for now
    if bits == 32:
        # https://blog.xenoscr.net/2019/12/01/Finding-EIP.html
        return asm(f"""
        jmp label2
    label1:
        jmp getEIP
    label2:
        call label1
    getEIP:
        pop esi
        sub esi, {base_addr - text_seg_addr + 9}
        mov ecx, {text_seg_size}
        decrypt:
            xor byte ptr [esi+ecx-1], 0x55
            loop decrypt
        add esi, {oep_addr - text_seg_addr}
        jmp esi
    """,arch="i386")
    else:
        return asm(f"""
        lea rsi, [rip - {base_addr - text_seg_addr + 7}]
        mov rcx, {text_seg_size}
        decrypt:
            xor byte ptr [rsi+rcx-1], 0x55
            loop decrypt
        add rsi, {oep_addr - text_seg_addr}
        jmp rsi
    """,arch="amd64")


# TODO
# at the moment i'm stripping everything after segments
# other types of stripping may be implemented later cause why not
def strip_binary(f):
#    for name in ("SHT_SYMTAB", "SHT_STRTAB"):
#        for section in elf.iter_sections(name):
#            f_patched.seek(section["sh_offset"], SEEK_SET)
#            f_patched.write(b'\xff' * section["sh_size"])
    seek_write(f, ehdr_offsets.e_shoff[0], ehdr_offsets.e_shoff[1](0))
    seek_write(f, ehdr_offsets.e_shnum[0], ehdr_offsets.e_shnum[1](0))
    seek_write(f, ehdr_offsets.e_shstrndx[0], ehdr_offsets.e_shstrndx[1](0))
    seek_write(f, ehdr_offsets.e_shentsize[0], ehdr_offsets.e_shentsize[1](0))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pack binary files")
    parser.add_argument("path", type=str, help="path to the binary")
    parser.add_argument("-e", "--entropy", action='store_true',help="show entropy of text segment")
    args = parser.parse_args()

    with open(args.path, 'rb') as f:
        elf = ELFFile(f)
        bits = elf.elfclass
        # structures offsets on the current platform
        set_offsets(bits)

        needed_size = -1
        load_segments = []
        for idx, segment in enumerate(elf.iter_segments()):
            if segment['p_type'] == "PT_LOAD":
                f.seek(segment["p_offset"])
                data = f.read(segment["p_filesz"])
                load_segments.append(SegmentDataTuple(segment,data,idx))
                if segment['p_flags'] & P_FLAGS.PF_X:
                    text_seg_t = SegmentDataTuple(segment,data,idx)
                    text_free_space = elf.get_segment(idx+1)["p_offset"] - (segment["p_offset"] + segment["p_filesz"])
            if segment['p_type'] == "PT_NOTE":
                note_seg_t = SegmentDataTuple(segment,data,idx)


            # Removes everything not needed for program execution from the binary, note
            # that this differs from the standard system strip utility which just discards
            # the .symtab section. This strips everything not covered by a segment as
            # described in the program header table to ensure absolutely no debugging
            # information is left over to aid a reverse engineer
            seg_end = segment["p_offset"] + segment["p_filesz"]                
            if seg_end > needed_size:
                needed_size = seg_end

        if args.entropy:
            draw_plot(load_segments)
            exit(0) 

        #print(dict(sorted(check_freq(load_segments[1].data).items(), key=lambda item: item[1], reverse=True)))
        text_seg =     text_seg_t.segment
        text_filesz =  text_seg_t.segment["p_filesz"]
        text_poff =    text_seg_t.segment["p_offset"]
        loader =       create_loader(text_poff+text_filesz, text_poff, text_filesz, elf.header.e_entry)
        # FIXME hardcoded encryption method
        patched_data = bytes([b ^ 0x55 for b in text_seg_t.data])


        # if our code cave is too small, then our plan is ol' good PT_NOTE to PT_LOAD injection 
        # https://www.symbolcrash.com/2019/03/27/pt_note-to-pt_load-injection-in-elf/
        if text_free_space < len(loader):
            with open(args.path + "_patched", 'wb') as f_patched:
                # write original binary to "_patched" file
                f.seek(0, SEEK_SET)
                fsize = f_patched.write(f.read()[0:needed_size])
                # create a new loader
                loader = create_loader(0xc000000+fsize, text_poff, text_filesz, elf.header.e_entry)
                # go to text_seg in binary and write encrypted code
                seek_write(f_patched, text_seg["p_offset"], patched_data)
                # get phoff
                f.seek(ehdr_offsets.e_phoff[0])
                e_phoff = u32(f.read(4)) if bits == 32 else u64(f.read(8))
                note_phdr_off = e_phoff + note_seg_t.phdr_idx*phdr_size
                # edit phdr
                seek_write(f_patched, note_phdr_off + phdr_offsets.p_type  [0],  phdr_offsets.p_type  [1] (constants.PT_LOAD))
                seek_write(f_patched, note_phdr_off + phdr_offsets.p_flags [0],  phdr_offsets.p_flags [1] (P_FLAGS.PF_R | P_FLAGS.PF_X))
                seek_write(f_patched, note_phdr_off + phdr_offsets.p_vaddr [0],  phdr_offsets.p_vaddr [1] (0xc000000+fsize))
                seek_write(f_patched, note_phdr_off + phdr_offsets.p_offset[0],  phdr_offsets.p_offset[1] (fsize))
                seek_write(f_patched, note_phdr_off + phdr_offsets.p_filesz[0],  phdr_offsets.p_filesz[1] (len(loader)))
                seek_write(f_patched, note_phdr_off + phdr_offsets.p_memsz [0],  phdr_offsets.p_memsz [1] (len(loader)))
                # write loader to the end of file
                f_patched.seek(0, SEEK_END)
                f_patched.write(loader)
                # change entry point
                seek_write(f_patched, ehdr_offsets.e_entry[0], ehdr_offsets.e_entry[1](0xc000000+fsize))
                # change text segment flags to rwx
                seek_write(f_patched, e_phoff + text_seg_t.phdr_idx*phdr_size + phdr_offsets.p_flags[0],
                phdr_offsets.p_flags[1](7))
                strip_binary(f_patched)
        # code cave method
        else:
            with open(args.path + "_patched", 'wb') as f_patched:
                # write original binary to "_patched" file
                f.seek(0, SEEK_SET)
                fsize = f_patched.write(f.read()[0:needed_size])
                # go to text_seg in binary and write encrypted code
                seek_write(f_patched, text_seg["p_offset"], patched_data)
                # go to end of segment (e.g. code cave) and write our loder
                seek_write(f_patched, text_seg["p_offset"] + text_seg["p_filesz"], loader)
                # change entry address to the code cave
                seek_write(f_patched, ehdr_offsets.e_entry[0], ehdr_offsets.e_entry[1](text_seg["p_offset"] + text_seg["p_filesz"]))
                # go to program headers table
                f.seek(ehdr_offsets.e_phoff[0])
                e_phoff = u32(f.read(4)) if bits == 32 else u64(f.read(8))
                text_phdr_off = e_phoff + text_seg_t.phdr_idx*phdr_size
                # edit phdr                
                seek_write(f_patched, text_phdr_off + phdr_offsets.p_filesz[0], phdr_offsets.p_filesz[1](text_seg["p_filesz"] + len(loader)))
                seek_write(f_patched, text_phdr_off + phdr_offsets.p_memsz[0],  phdr_offsets.p_memsz[1](text_seg["p_filesz"] + len(loader)))
                seek_write(f_patched, text_phdr_off + phdr_offsets.p_flags[0],  phdr_offsets.p_flags[1](7)) # PF_X | PF_W | PF_R
                strip_binary(f_patched)
