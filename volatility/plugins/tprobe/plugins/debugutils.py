import volatility.plugins.tprobe.core as tprobe
import volatility.utils as utils
import volatility.obj as obj
import struct
import gdb
import sys
import distorm3
from volatility.plugins.tprobe.core import Breakpoint

import pickle

def get_reg(reg):
    return (reg, int(gdb.execute('info register {0}'.format(reg),False, True).split('\t')[0].split(' ')[-1],0))

class ViewRegisters(tprobe.AbstractTProbePlugin):
    name = 'regs'

    def calculate(self):
        regs = {}
        for reg in ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip"]:
#            regs.append(get_reg(reg))
            regs[reg] = self.functions.gr.calculate(reg)
        return regs

    def render_text(self, regs):
        for reg in regs.keys():
            print("%s: 0x%08x" % (reg, regs[reg]))

class ViewRegisters2(tprobe.AbstractTProbePlugin):
    name = 'regs2'

    def calculate(self):
        regs = {}
        for reg in ["cs", "ss", "ds", "es", "fs", "gs"]:
#            regs.append(get_reg(reg))
            regs[reg] = self.functions.gr.calculate(reg)
        return regs

    def render_text(self, regs):
        for reg in regs.keys():
            print("%s: 0x%08x" % (reg, regs[reg]))

class ViewRegisters3(tprobe.AbstractTProbePlugin):
    name = 'regs3'

    def calculate(self):
        eflags = self.functions.gr.calculate("eflags")
        regs = {}

        regs["CF"] = eflags & 0x1
        eflags >>= 1
        #reserved
        eflags >>= 1
        regs["PF"] = eflags & 0x1
        eflags >>= 1
        #reserved
        eflags >>= 1
        regs["AF"] = eflags & 0x1
        eflags >>= 1
        #reserved
        eflags >>= 1
        regs["ZF"] = eflags & 0x1
        eflags >>= 1
        regs["SF"] = eflags & 0x1
        eflags >>= 1
        regs["TF"] = eflags & 0x1
        eflags >>= 1
        regs["IF"] = eflags & 0x1
        eflags >>= 1
        regs["DF"] = eflags & 0x1
        eflags >>= 1
        regs["OF"] = eflags & 0x1
        eflags >>= 1
        return regs

    def render_text(self, regs):
        for reg in regs.keys():
            print("%s: 0x%08x" % (reg, regs[reg]))

class ViewRegisters4(tprobe.AbstractTProbePlugin):
    name = 'regs4'

    def calculate(self):
        regs = []
        for reg in ["cr3"]:
            regs.append(get_reg(reg))
        return regs

    def render_text(self, regs):
        for reg in regs:
            print("%s: 0x%08x" % (reg[0], reg[1]))

class GetRegister(tprobe.AbstractTProbeApiFunction):
    name = 'gr'

    def calculate(self, regname):
        return int(gdb.execute('info register {0}'.format(regname),False, True).split('\t')[0].split(' ')[-1],0)

class SetBpDtb(tprobe.AbstractTProbeApiFunction):
    name = 'bd'

    def calculate(self, address, cr3 = None):
        if(cr3 is None): cr3 = self.functions.gr("cr3")
        gdb.execute('b *{0} if $cr3=={1}'.format(address, cr3),False, True)


class StackUnwind(tprobe.AbstractTProbePlugin):
    name = 'su'

    def calculate(self):
        esp = self.core.functions.gr("esp")
#        space = (self.core.reading_context or self.core.current_context) # or self.functions.get_context()).get_process_address_space() # to raczej zle
#        space = self.core.addrspace
        space = self.core.current_EPROCESS.get_process_address_space()
        data = space.read(esp, 0x10*0x4)
        entry_count = int(len(data)/4)
        fmts = "<"
        for i in range(0,entry_count):
            fmts += "I"
        stack_entries = struct.unpack(fmts, data)
        return stack_entries

    def render_text(self, stack_entries):
        for entry in stack_entries:
            print("0x%08x" % entry)

class Continue(tprobe.AbstractTProbePlugin):
    name = 'c'

    def calculate(self, location=None, dtb = None):
        gdb.execute('c',False, True)

class LoadBpList(tprobe.AbstractTProbePlugin):
    name = 'bpl'

    def calculate(self, path, eproc):
        f = open(path, "r")
        for bp in f.readlines():
            print("Setting bp on: %s" % bp[:-1])
            self.core.functions.b.calculate(bp[:-1], eproc)
        f.close()

class SetSystemWideBp(tprobe.AbstractTProbePlugin):
    name = 'swb'

    def calculate(self, location = None):
        if(location == None):
            location = self.core.functions.gr("eip")

        if(isinstance(location, int)):
            address = location
        elif(isinstance(location, str)):
            try:
                address = self.core.symbols_by_name[location]
            except KeyError:
                pass
        else:
            try: 
                address = int(location)
            except:
                print('Failed')

        self.core.bp_index.addBpt(Breakpoint(address), None)

class SetBp(tprobe.AbstractTProbePlugin):
    name = 'b'

    def calculate(self, location = None, eproc = None):
        if(location == None):
            location = self.core.functions.gr("eip")

        if(isinstance(location, int)):
            address = location
        elif(isinstance(location, str)):
            try:
                address = self.core.symbols_by_name[location]
            except KeyError:
                pass
        else:
            try: 
                address = int(location)
            except:
                print('Failed')

        if(eproc is not None): 
            if(isinstance(eproc, int)):
                dtb = self.functions.e2d.calculate(eproc)
            else:
                dtb = self.functions.e2d.calculate(eproc.v())
        else:
            dtb = self.functions.e2d.calculate(self.core.current_EPROCESS.v())

        self.core.bp_index.addBpt(Breakpoint(address), dtb)

'''
class SetBp(tprobe.AbstractTProbePlugin):
    name = 'b'

    def calculate(self, location=None, eproc = None):
        if(location == None):
            location = self.core.functions.gr("eip")

        if(isinstance(location, int)):
            address = location
        elif(isinstance(location, str)):
            try:
                address = self.core.symbols_by_name[location]
            except KeyError:
                print("No symbol found")
                return

        if(eproc is not None): 
            dtb = self.functions.e2d.calculate(eproc)
#            gdb.execute('b *{0} if $cr3=={1}'.format(address, dtb),False, True)
        else:
            dtb = None
#            dtb = self.functions.e2d.calculate()
#            gdb.execute('b *{0}'.format(address),False, True)
        self.core.bp_index.addBpt(Breakpoint(address), dtb)

#        gdb.execute('b *{0} if $cr3=={1}'.format(address, dtb),False, True)
#        self.core.bpts[address] = dtb
'''
#class DelBp(tprobe.AbstractTProbePlugin):
#    name = 'db'
#
#    def calculate(self, bp_id):
#        gdb.execute('del {0}'.format(bp_id),False, True)
#        #delete from list

class IterateList(tprobe.AbstractTProbeApiFunction):
    name = 'itl'

    def calculate(self, head, objname, offset = -1, fieldname = None, forward = True):
        """Traverse a _LIST_ENTRY.
 
        Traverses a _LIST_ENTRY starting at virtual address head made up of
        objects of type objname. The value of offset should be set to the
        offset of the _LIST_ENTRY within the desired object."""
 
        vm = self.core.current_EPROCESS.get_process_address_space()
        seen = set()

        if fieldname:
            offset = vm.profile.get_obj_offset(objname, fieldname)
            #if typ != "_LIST_ENTRY":
            #    print ("WARN: given field is not a LIST_ENTRY, attempting to "
            #           "continue anyway.")
 
        lst = obj.Object("_LIST_ENTRY", head, vm)
        seen.add(lst)
        if not lst.is_valid():
            return
        while True:
            if forward:
                lst = lst.Flink
            else:
                lst = lst.Blink
 
            if not lst.is_valid():
                return
 
            if lst in seen:
                break
            else:
                seen.add(lst)
 
            nobj = obj.Object(objname, lst.obj_offset - offset, vm)
            yield nobj

class WaitForRet(tprobe.AbstractTProbePlugin):
    name = 'retWait'

    def calculate(self):
        gdb.execute('finish')
        return

    def render_text(self):
        return

class WaitForRetScan(tprobe.AbstractTProbePlugin):
    name = 'retWaitScan'

    def calculate(self):
        import time
        while True:
            opcode = gdb.execute('x/bx $eip', False, True).split('\t')[1].strip()
            if(opcode in ['0xc2', '0xc3']):
                break
            if(opcode in ['0xe8', '0x9a', '0xff']):
                self.core.functions.ni()
            else:
                self.core.functions.ni()
        gdb.execute('si')
        return

    def render_text(self):
        return

class Eproc2Kthreads(tprobe.AbstractTProbePlugin):
    name = 'eproc2kthreads'

    def calculate(self, eproc):
        print('Generating locations')

        locations = []

        from volatility.obj import Object

        EPROCESS = Object('_EPROCESS', eproc, self.core.addrspace)
        thread_list = EPROCESS.ThreadListHead

        list_head = list_entry = thread_list
        list_entry = list_head.Flink

        while(list_entry.v() != list_head.v()):
            kthreado = list_entry.v() - 0x1b0
            KTHREAD = Object('_KTHREAD', kthreado, self.core.addrspace)
            print('KTHREAD 0x%08x: Eip: 0x%08x, DbgEip: 0x%08x, Esp: 0x%08x' % (KTHREAD.v(), KTHREAD.TrapFrame.Eip, KTHREAD.TrapFrame.DbgEip, KTHREAD.TrapFrame.TempEsp))

            locations.append(KTHREAD.TrapFrame.Eip)
            list_entry = list_entry.Flink

        return None

    def render_text(self, data):
            return

class ProcessName2Eproc(tprobe.AbstractTProbePlugin):
    name = 'pn2e'

    def calculate(self, process_name = "System"):
        processes = self.core.functions.ps.calculate()
        for process in processes:
            if(process_name in process.ImageFileName.v()):
                return process.v()

    def render_text(self, eproc):
        print('EPROC: 0x%x' % (eproc))


class Eproc2Dtb(tprobe.AbstractTProbePlugin):
    name = 'e2d'

    def calculate(self, eproc_addr = None):
        if(eproc_addr == None):
            if(self.core.current_EPROCESS == None):
                self.core.functions.cc.calculate()
            EPROCESS = self.core.current_EPROCESS
        else:
            EPROCESS = self.functions.get_EPROCESS(eproc_addr)
        dtb = EPROCESS.Pcb.DirectoryTableBase.v()
        return dtb

    def render_text(self, dtb):
        print('DTB: 0x%x' % (dtb))

class Eproc2Peb(tprobe.AbstractTProbePlugin):
    name = 'e2peb'
    
    def calculate(self, eproc_addr):
        eproc = self.functions.offset_to_EPROCESS(eproc_addr)
        peb = eproc.Peb
        return peb

    def render_text(self, peb):
        print('PEB: 0x%x' % (peb.v()))


class Eproc2ImageBase(tprobe.AbstractTProbePlugin):
    name = 'e2ib'

    def calculate(self, eproc_addr):
        peb = self.functions.e2peb.calculate(eproc_addr)
        return peb.ImageBaseAddress
        
    def render_text(self, ib):
        print('ImageBase: 0x%x' % (ib.v()))

class Eproc2InMemoryOrderModuleList(tprobe.AbstractTProbePlugin):
    name = 'e2imoml'

    def calculate(self, eproc_addr):
        try:
            eproc = self.functions.offset_to_EPROCESS(eproc_addr)
        except:
            eproc = eproc_addr
        modules = eproc.get_mem_modules()
        return modules
        
    def render_text(self, modules):
        print("Process modules (in memory order):")
        modules.next() # drop first empty
        for module in modules:
            print("[0x%x]\t%s" % (module.DllBase, module.BaseDllName))

class ImageName2DosHeader(tprobe.AbstractTProbePlugin):
    name = 'in2dh'

    def calculate(self, name):
        modules = self.functions.e2imoml.calculate(self.core.current_EPROCESS.v())
        found = None
        for module in modules:
            if(str(module.BaseDllName).upper() == name.upper()):
                found = module
                break

        if(found == None or not module.is_valid()): return None # maybe we should change to NoneObject?
        dh = obj.Object("_IMAGE_DOS_HEADER", offset = found.DllBase.v(), vm = self.core.current_EPROCESS.get_process_address_space())
        return dh

    def render_text(self, dh):
        print("0x%x" % dh.v())

"""
class ImageBase2Module(tprobe.AbstractTProbePlugin):
    name = 'ib2mod'

    def calculate(self, ib_addr):
        modules = self.functions.e2imoml.calculate(self.core.current_EPROCESS.v())
        found = None
        for module in modules:
            if(module.DllBase == ib_addr):
                found = module
                break

        if(found == None or not module.is_valid()): return None # maybe we should change to NoneObject?
        return found

    def render_text(self, mod):
        print("0x%x" % mod.v())
"""

class ImageBase2DosHeader(tprobe.AbstractTProbePlugin):
    name = 'ib2dh'

    def calculate(self, ib_addr):
        dh = obj.Object("_IMAGE_DOS_HEADER", offset = ib_addr, vm = self.core.current_EPROCESS.get_process_address_space())
        return dh

    def render_text(self, dh):
        print('_IMAGE_DOS_HEADER off: 0x%x' % (dh.v()))

class ImageBase2NtHeaders(tprobe.AbstractTProbePlugin):
    name = 'ib2nth'

    def calculate(self, ib_addr):
        dh = self.functions.ib2dh.calculate(ib_addr)
        nth = obj.Object("_IMAGE_NT_HEADERS", offset = ib_addr + dh.e_lfanew.v(), vm = self.core.current_EPROCESS.get_process_address_space())
        return nth
        
    def render_text(self, nth):
        print('_IMAGE_NT_HEADERS off: 0x%x' % (nth.v()))

class ImageBase2OptionalHeader(tprobe.AbstractTProbePlugin):
    name = 'ib2oh'

    def calculate(self, ib_addr):
        nth = self.functions.ib2nth.calculate(ib_addr)
        oh = nth.OptionalHeader
        return oh
        
    def render_text(self, oh):
        print('_IMAGE_OPTIONAL_HEADER off: 0x%x' % (oh.v()))

class ImageBase2EntryPointOffset(tprobe.AbstractTProbePlugin):
    name = 'ib2epo'

    def calculate(self, ib_addr):
        oh = self.functions.ib2oh.calculate(ib_addr)
        ep = oh.AddressOfEntryPoint.v()
        epo = ib_addr + ep
        return epo
        
    def render_text(self, epo):
        print('EP off: 0x%x' % (epo))

class ReloadTargetSymbols(tprobe.AbstractTProbePlugin):
    name = 'reload_target_symbols'

    def calculate(self, eproc):
        symbols_by_name = {}
        symbols_by_offset = {}
        print("Resolving symbols, patience")
        for mod in self.core.functions.e2imoml.calculate(eproc):
            base = mod.DllBase
            name = mod.BaseDllName
            for export in mod.exports():
                if(not export[2].is_valid()): continue
                resolvedName = "%s!%s" % (name, str(export[2]))
                resolvedOffset = base.v() + export[1]
                symbols_by_name[resolvedName] = resolvedOffset
                symbols_by_offset[resolvedOffset] = resolvedName
        self.core.symbols_by_name = symbols_by_name
        self.core.symbols_by_offset = symbols_by_offset
        self.core.symbols_by_name.update(self.core.kernel_symbols_by_name)
        self.core.symbols_by_offset.update(self.core.kernel_symbols_by_offset)

    def render_text(self, sth):
        pass

class ReloadModuleSymbols(tprobe.AbstractTProbePlugin):
    name = 'reload_module_symbols'

    def calculate(self, module_name):
        module = self.core.current_modules[module_name]
        self.core.current_symbols[module_name] = {}

        for export in module.exports():
            if(not export[2].is_valid()): continue
            resolvedOffset = module.DllBase.v() + export[1]
            self.core.current_symbols[module_name][export[2]] = resolvedOffset

        return self.core.current_symbols

    def render_text(self, sth):
        pass

class ReloadCurrentModules(tprobe.AbstractTProbePlugin):
    name = 'reload_current_modules'

    def calculate(self):
        self.core.current_modules = {}

        eproc = self.core.current_EPROCESS

        for module in self.core.functions.e2imoml.calculate(eproc):
            self.core.current_modules[module.BaseDllName] = module
            self.core.current_symbols[module.BaseDllName] = {}

        return self.core.current_modules

    def render_text(self, sth):
        pass

class ReloadSymbols(tprobe.AbstractTProbePlugin):
    name = 'reload_symbols'

    def calculate(self):
        symbols_by_name = {}
        symbols_by_offset = {}
        module = self.core.functions.get_EPROCESS(self.core.current_EPROCESS.v())
        for mod in self.core.functions.e2imoml.calculate(module):
            base = mod.DllBase
            name = mod.BaseDllName
            for export in mod.exports():
                if(not export[2].is_valid()): continue
                resolvedName = "%s!%s" % (name, str(export[2]))
                resolvedOffset = base.v() + export[1]
                symbols_by_name[resolvedName] = resolvedOffset
                symbols_by_offset[resolvedOffset] = resolvedName
        self.core.symbols_by_name = symbols_by_name
        self.core.symbols_by_offset = symbols_by_offset
        self.core.symbols_by_name.update(self.core.kernel_symbols_by_name)
        self.core.symbols_by_offset.update(self.core.kernel_symbols_by_offset)

    def render_text(self, sth):
        pass

import volatility.win32 as win32

class ReloadKernelSymbols(tprobe.AbstractTProbePlugin):
    name = 'reload_kernel_symbols'

    def calculate(self):
        kernel_symbols_by_name = {}
        kernel_symbols_by_offset = {}
        for mod in win32.modules.lsmod(self.core.addrspace):
            base = mod.DllBase
            name = mod.BaseDllName
            for export in mod.exports():
                if(not export[2].is_valid()): continue
                resolvedName = "%s!%s" % (name, str(export[2]))
                resolvedOffset = base.v() + export[1]
                kernel_symbols_by_name[resolvedName] = resolvedOffset
                kernel_symbols_by_offset[resolvedOffset] = resolvedName
        self.core.kernel_symbols_by_name = kernel_symbols_by_name
        self.core.kernel_symbols_by_offset = kernel_symbols_by_offset
        self.core.symbols_by_name.update(self.core.kernel_symbols_by_name)
        self.core.symbols_by_offset.update(self.core.kernel_symbols_by_offset)

    def render_text(self, sth):
        pass

class DecodeOp1(tprobe.AbstractTProbeApiFunction):
    name = 'dec_op1'

    def calculate(self, op1):
        return self.decode_op1(op1)

    def get_register(self, reg):
        return self.core.functions.gr(reg)

    def read(self, addr, length):
        space = self.core.current_EPROCESS.get_process_address_space() 
        return space.read(addr, length)

    def decode_op1(self, op1):
        regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]

        my_op = op1
        if(my_op[0] == '['):
            my_op = self.decode_op1(my_op[1:-1])
            my_op = int(struct.unpack("<i", "".join(self.read(my_op, 4)))[0]) & 0xffffffff
            return my_op
        for reg in regs:
            if(my_op.upper() == reg):
                my_op = self.get_register(reg.lower())
                return my_op & 0xffffffff
        if(len(my_op.split("+")) >1):
            (a,b) = my_op.split("+")
            a = self.decode_op1(a)
            b = self.decode_op1(b)
            my_op = a+b
            return my_op & 0xffffffff
        if(len(my_op.split("-")) >1):
            (a,b) = my_op.split("-")
            a = self.decode_op1(a)
            b = self.decode_op1(b)
            my_op = a-b
            return my_op & 0xffffffff
        if(len(my_op.split("*")) >1):
            (a,b) = my_op.split("*")
            a = self.decode_op1(a)
            b = self.decode_op1(b)
            my_op = a*b
            return my_op & 0xffffffff
        return int(my_op, 16) & 0xffffffff

class Si(tprobe.AbstractTProbePlugin):
    name = 'si'

    def calculate(self):
        gdb.execute("si")
        self.core.functions.uce.calculate()

class Ni(tprobe.AbstractTProbePlugin):
    name = 'ni'

    def calculate(self):
        eip = self.core.functions.gr("eip")
        space = self.core.current_EPROCESS.get_process_address_space() 
        factor = 0x20
#        while(factor > 0x0):
#            try:
        data = space.read(eip, factor)
        iterable = distorm3.DecodeGenerator(eip, data, distorm3.Decode32Bits)
        _, size, instruction, _ = iterable.next()
#            except Exception:
#                print("reducing")
#                factor -= 0x1
#                continue
        if(instruction.find("CALL ") > -1):
#        if True:
            neip = eip + size
#            self.core.functions.update_EPROCESS.calculate()
#            self.core.gshell.log("test")
#            self.core.bp_index.addBpt(Breakpoint(neip), self.core.current_EPROCESS)
#            gdb.execute("cont")
#            self.core.bp_index.delBpt(neip)
            gdb.execute("until *0x%x" % neip)
        else:
            self.core.functions.si()
        # we need to update EPROCESS
        self.core.functions.uce.calculate()

class Until(tprobe.AbstractTProbePlugin):
    name = 'until'
    
    def calculate(self, addr):
        gdb.execute("until *0x%x" % addr)
        self.core.functions.uce.calculate()

class SiAndDis(tprobe.AbstractTProbePlugin):
    name = 'sd'

    def calculate(self):
        self.core.functions.si()
        self.core.functions.dism(None)

class Disassemble(tprobe.AbstractTProbePlugin):
    name = 'dis'
    dependencies = ['get_EPROCESS', 'dec_op1']

    def calculate(self, address = None, length = 128, space = None, mode = None):
        """Disassemble code at a given address.

        Disassembles code starting at address for a number of bytes
        given by the length parameter (default: 128).

        Note: This feature requires distorm, available at
            http://www.ragestorm.net/distorm/

        The mode is '32bit' or '64bit'. If not supplied, the disasm
        mode is taken from the profile. 
        """
        if(address == None):
            address = self.core.functions.gr("eip")

        if not space:
            space = self.core.current_EPROCESS.get_process_address_space() 

        if not sys.modules.has_key("distorm3"):
            print "ERROR: Disassembly unavailable, distorm not found"
            return
        if not space:
            space = self.eproc.get_process_address_space()

        if not mode:
            mode = space.profile.metadata.get('memory_model', '32bit')

        if mode == '32bit':
            distorm_mode = distorm3.Decode32Bits
        else:
            distorm_mode = distorm3.Decode64Bits

        data = space.read(address, length)
        iterable = distorm3.DecodeGenerator(address, data, distorm_mode)

        lines = []
        for (offset, _size, instruction, hexdump) in iterable:
            if(instruction.find("CALL ") > -1):
                try:
                    op1 = instruction[5:]
                    if(op1.find("DWORD ") == 0):
                        op1 = op1[6:]
                    dst = self.functions.dec_op1(op1)
                    if(self.core.symbols_by_offset.has_key(int(dst))):
                        target = self.core.symbols_by_offset[int(dst)]
                        instruction = "CALL %s" % target
                except Exception:
                    print(instruction)
#            lines.append((offset, hexdump, instruction))
            lines.append((offset, instruction))
        return lines

    def render_text(self, lines):
#        for offset, hexdump, instruction in lines:
        for offset, instruction in lines:
            print "{0:<#8x} {1}".format(offset, instruction)


class DisassembleMid(Disassemble):
    name = 'dism'
    dependencies = ['get_EPROCESS', 'dec_op1']

    def calculate(self, address = None, line_count = 30, lines_prev=10, length = 356, space = None, mode = None):
        if(address == None):
            address = self.core.functions.gr("eip")

        try_start = address - lines_prev*5

        lines = []
        lineno = 0
        self.line_cur = 0
        self.line_start = 0
        for offset, instruction in Disassemble.calculate(self, try_start, length, space, mode):
            if(offset == address): 
                self.line_cur = lineno
                self.line_start = lineno - lines_prev
            lines.append((offset, instruction))
            if(lineno > self.line_start + line_count): break
            lineno += 1
        return lines, self.line_start, self.line_cur

    def render_text(self, code):
        lines, _, _ = code
        lineno = 0
#        for offset, hexdump, instruction in lines:
        for offset, instruction in lines:
            if(lineno >= self.line_start):
                if(lineno == self.line_cur):
                    print "{0}{1:<#8x} {2}{3}".format('\033[94m', offset, instruction, '\033[0m')
                else:
                    print "{0:<#8x} {1}".format(offset, instruction)
            lineno += 1
                
class Nop(tprobe.AbstractTProbePlugin):
    name = 'nop'

    def calculate(self):
        pass

    def render_text(self, sth):
        pass

class RestoreSymbols(tprobe.AbstractTProbePlugin):
    name = 'restore_symbols'

    def calculate(self, filee):
        f = open(filee, "r")
        symbols_by_name, symbols_by_offset, kernel_symbols_by_name, kernel_symbols_by_offset = pickle.load(f)
        self.core.symbols_by_name = symbols_by_name
        self.core.symbols_by_offset = symbols_by_offset
        self.core.kernel_symbols_by_name = kernel_symbols_by_name
        self.core.kernel_symbols_by_offset = kernel_symbols_by_offset
        f.close()

    def render_text(self, sth):
        print("Restored")

class StoreSymbols(tprobe.AbstractTProbePlugin):
    name = 'store_symbols'

    def calculate(self, filee):
        f = open(filee, "w")
        symbols_by_name = self.core.symbols_by_name
        symbols_by_offset = self.core.symbols_by_offset
        kernel_symbols_by_name = self.core.kernel_symbols_by_name
        kernel_symbols_by_offset = self.core.kernel_symbols_by_offset
        symbols = [symbols_by_name, symbols_by_offset, kernel_symbols_by_name, kernel_symbols_by_offset]
        pickle.dump(symbols, f)
        f.close()

    def render_text(self, sth):
        print("Stored")


                


