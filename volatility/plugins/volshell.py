# Volatility
# Copyright (C) 2008 Volatile Systems
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

import struct
import sys
import volatility.plugins.common as common 
import volatility.win32 as win32
import volatility.win32 as win32
import volatility.utils as utils
import volatility.obj as obj
import volatility.registry as registry
import volatility.commands as commands
import volatility.exceptions as exceptions

try:
    import distorm3 #pylint: disable-msg=F0401
except ImportError:
    pass

class volshell(commands.Command):
    """Shell in the memory image"""

    # Declare meta information associated with this plugin

    meta_info = {}
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.3'

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)

        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'EPROCESS Offset (in hex) in kernel address space',
                          action = 'store', type = 'int')
        config.add_option('IMNAME', short_option = 'n', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')

        self.addrspace = None
        self.eproc = None
        self.plugin_cfg = []
        self.argv = sys.argv

    def getlinuxpidlist(self):
        init_task_addr = self.addrspace.profile.get_profile_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)

        for task in init_task.tasks:
            yield task


    def getpidlist(self):
        if self.os == 'linux':
            return self.getlinuxpidlist()
        return win32.tasks.pslist(self.addrspace)

    def context_display(self):
        print "Current context: process {0}, pid={1}, ppid={2} DTB={3:#x}".format(self.eproc.ImageFileName,
                                                                                  self.eproc.UniqueProcessId.v(),
                                                                                  self.eproc.InheritedFromUniqueProcessId.v(),
                                                                                  self.eproc.Pcb.DirectoryTableBase.v())

    def ps(self, procs = None):
        print "{0:16} {1:6} {2:6} {3:8}".format("Name", "PID", "PPID", "Offset")
        for eproc in procs or self.getpidlist():
            print "{0:16} {1:<6} {2:<6} {3:#08x}".format(eproc.ImageFileName,
                                                       eproc.UniqueProcessId.v(),
                                                       eproc.InheritedFromUniqueProcessId.v(),
                                                       eproc.obj_offset)

    def set_context(self, offset = None, pid = None, name = None):
        if pid is not None:
            offsets = []
            for p in self.getpidlist():
                if p.UniqueProcessId.v() == pid:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching pid {0}".format(pid)
                return
            elif len(offsets) > 1:
                print "Multiple processes match {0}, please specify by offset".format(pid)
                print "Matching processes:"
                self.ps(offsets)
                return
            else:
                offset = offsets[0].v()
        elif name is not None:
            offsets = []
            for p in self.getpidlist():
                if p.ImageFileName.find(name) >= 0:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching name {0}".format(name)
                return
            elif len(offsets) > 1:
                print "Multiple processes match name {0}, please specify by PID or offset".format(name)
                print "Matching processes:"
                self.ps(offsets)
                return
            else:
                offset = offsets[0].v()
        elif offset is None:
            print "Must provide one of: offset, name, or pid as a argument."
            return

        self.eproc = obj.Object("_EPROCESS", offset = offset, vm = self.addrspace)

        self.context_display()

    ##TODO: now its copy-paste from vol.py
    def list_plugins(self):
        result = "\n\tSupported Plugin Commands:\n\n"
        cmds = registry.get_plugin_classes(commands.Command, lower = True)
        profs = registry.get_plugin_classes(obj.Profile)

        profile = profs[self._config.PROFILE]()
        wrongprofile = ""
        for cmdname in sorted(cmds):
            command = cmds[cmdname]
            helpline = command.help() or ''
            ## Just put the title line (First non empty line) in this
            ## abbreviated display
            for line in helpline.splitlines():
                if line:
                    helpline = line
                    break
            if command.is_valid_profile(profile):
                result += "\t\t{0:15}\t{1}\n".format(cmdname, helpline)
            else:
                wrongprofile += "\t\t{0:15}\t{1}\n".format(cmdname, helpline)

        if wrongprofile and self._config.VERBOSE:
            result += "\n\tPlugins requiring a different profile:\n\n"
            result += wrongprofile

        return result

    def render_text(self, _outfd, _data):
        self.addrspace = utils.load_as(self._config)
        self.os = self.addrspace.profile.metadata.get('os', 'unknown')

        if not self._config.OFFSET is None:
            self.set_context(offset = self._config.OFFSET)

            self.context_display()

        elif self._config.PID is not None:
            self.set_context(pid = self._config.PID)
        elif self._config.IMNAME is not None:
            self.set_context(name = self._config.IMNAME)
        else:
            # Just use the first process, whatever it is
            for p in self.getpidlist():
                self.set_context(offset = p.v())
                break

        # Functions inside the shell
        def cc(offset = None, pid = None, name = None):
            """Change current shell context.

            This function changes the current shell context to to the process
            specified. The process specification can be given as a virtual address
            (option: offset), PID (option: pid), or process name (option: name).

            If multiple processes match the given PID or name, you will be shown a
            list of matching processes, and will have to specify by offset.
            """
            self.set_context(offset = offset, pid = pid, name = name)

        def db(address, length = 0x80, space = None):
            """Print bytes as canonical hexdump.
            
            This function prints bytes at the given virtual address as a canonical
            hexdump. The address will be translated in the current process context
            (see help on cc for information on how to change contexts).
            
            The length parameter (default: 0x80) specifies how many bytes to print,
            the width parameter (default: 16) allows you to change how many bytes per
            line should be displayed, and the space parameter allows you to
            optionally specify the address space to read the data from.
            """
            if not space:
                space = self.eproc.get_process_address_space()
            #if length % 4 != 0:
            #    length = (length+4) - (length%4)
            data = space.read(address, length)
            if not data:
                print "Memory unreadable at {0:08x}".format(address)
                return

            for offset, hexchars, chars in utils.Hexdump(data):
                print "{0:#010x}  {1:<48}  {2}".format(address + offset, hexchars, ''.join(chars))

        def dd(address, length = 0x80, space = None):
            """Print dwords at address.

            This function prints the data at the given address, interpreted as
            a series of dwords (unsigned four-byte integers) in hexadecimal.
            The address will be translated in the current process context
            (see help on cc for information on how to change contexts).
            
            The optional length parameter (default: 0x80) controls how many bytes
            to display, and space allows you to optionally specify the address space
            to read the data from.
            """
            if not space:
                space = self.eproc.get_process_address_space()
            # round up to multiple of 4
            if length % 4 != 0:
                length = (length + 4) - (length % 4)
            data = space.read(address, length)
            if not data:
                print "Memory unreadable at {0:08x}".format(address)
                return
            dwords = []
            for i in range(0, length, 4):
                (dw,) = struct.unpack("<L", data[i:i + 4])
                dwords.append(dw)

            if len(dwords) % 4 == 0: lines = len(dwords) / 4
            else: lines = len(dwords) / 4 + 1

            for i in range(lines):
                ad = address + i * 0x10
                lwords = dwords[i * 4:i * 4 + 4]
                print ("{0:08x}  ".format(ad)) + " ".join("{0:08x}".format(l) for l in lwords)

        def dq(address, length = 0x80, space = None):
            """Print qwords at address.

            This function prints the data at the given address, interpreted as
            a series of qwords (unsigned eight-byte integers) in hexadecimal.
            The address will be translated in the current process context
            (see help on cc for information on how to change contexts).
            
            The optional length parameter (default: 0x80) controls how many bytes
            to display, and space allows you to optionally specify the address space
            to read the data from.
            """
            if not space:
                space = self.eproc.get_process_address_space()

            # round up 
            if length % 8 != 0:
                length = (length + 8) - (length % 8)

            qwords = obj.Object("Array", targetType = "unsigned long long",
                offset = address, count = length / 8, vm = space)

            if not qwords:
                print "Memory unreadable at {0:08x}".format(address)
                return

            for qword in qwords:
                print "{0:#x} {1:#x}".format(qword.obj_offset, qword.v())

        def ps():
            """Print a process listing.

            Prints a process listing with PID, PPID, image name, and offset.
            """
            self.ps()

        def list_entry(head, objname, offset = -1, fieldname = None, forward = True):
            """Traverse a _LIST_ENTRY.

            Traverses a _LIST_ENTRY starting at virtual address head made up of
            objects of type objname. The value of offset should be set to the
            offset of the _LIST_ENTRY within the desired object."""

            vm = self.eproc.get_process_address_space()
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

        def dt(objct, address = None, address_space = None):
            """Describe an object or show type info.

            Show the names and values of a complex object (struct). If the name of a
            structure is passed, show the struct's members and their types.

            You can also pass a type name and an address in order to on-the-fly
            interpret a given address as an instance of a particular structure.

            Examples:
                # Dump the current process object
                dt(self.eproc)
                # Show the _EPROCESS structure
                dt('_EPROCESS')
                # Overlay an _EPROCESS structure at 0x81234567
                dt('_EPROCESS', 0x81234567)
            """

            profile = (address_space or self.eproc.obj_vm).profile

            if address is not None:
                objct = obj.Object(objct, address, address_space or self.eproc.get_process_address_space())

            if isinstance(objct, str):
                size = profile.get_obj_size(objct)
                membs = [ (profile.get_obj_offset(objct, m), m, profile.vtypes[objct][1][m][1]) for m in profile.vtypes[objct][1] ]
                print repr(objct), "({0} bytes)".format(size)
                for o, m, t in sorted(membs):
                    print "{0:6}: {1:30} {2}".format(hex(o), m, t)
            elif isinstance(objct, obj.BaseObject):
                membs = [ (o, m) for m, (o, _c) in objct.members.items() ]
                print repr(objct)
                offsets = []
                for o, m in sorted(membs):
                    val = getattr(objct, m)
                    if isinstance(val, list):
                        val = [ str(v) for v in val ]

                    # Handle a potentially callable offset
                    if callable(o):
                        o = o(objct) - objct.obj_offset

                    offsets.append((o, m, val))

                # Deal with potentially out of order offsets
                offsets.sort(key = lambda x: x[0])

                for o, m, val in offsets:
                    print "{0:6}: {1:30} {2}".format(hex(o), m, val)
            elif isinstance(objct, obj.NoneObject):
                print "ERROR: could not instantiate object"
                print
                print "Reason: ", objct.reason
            else:
                print "ERROR: first argument not an object or known type"
                print
                print "Usage:"
                print
                hh(dt)

        def dis(address, length = 128, space = None, mode = None):
            """Disassemble code at a given address.

            Disassembles code starting at address for a number of bytes
            given by the length parameter (default: 128).

            Note: This feature requires distorm, available at
                http://www.ragestorm.net/distorm/

            The mode is '32bit' or '64bit'. If not supplied, the disasm
            mode is taken from the profile. 
            """
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
            for (offset, _size, instruction, hexdump) in iterable:
                print "{0:<#8x} {1:<32} {2}".format(offset, hexdump, instruction)

        def g(command):
            """Execute GDB command.
            """
            if self._config.GDB:
                try:
                    gdb.execute(command)
                except e:
                    print "{0}".format(e)

        def pl(command = None, execute = True):
            """Run volatility plugin. If execute is set to false returns plugin generator.
            """
            if command is not None:
                cmds = registry.get_plugin_classes(commands.Command, lower = True)
                try:
                    if command in cmds.keys():
                        command = cmds[command](self._config)
                        if execute:
                            command.execute()
                        else:
                            return command.calculate()
                    else:
                        print "Plugin {0} does not exist".format(command)
                except exceptions.VolatilityException, e:
                    print e
            else:
                ## TODO: print plugins list
                print self.list_plugins()

        shell_funcs = { 'pl':pl, 'g':g, 'cc': cc, 'dd': dd, 'db': db, 'ps': ps, 'dt': dt, 'list_entry': list_entry, 'dis': dis, 'dq': dq}
        def hh(cmd = None):
            """Get help on a command."""
            shell_funcs['hh'] = hh
            import pydoc
            from inspect import getargspec, formatargspec
            if not cmd:
                for f in shell_funcs:
                    doc = pydoc.getdoc(shell_funcs[f])
                    synop, _full = pydoc.splitdoc(doc)
                    print "{0:40} : {1}".format(f + formatargspec(*getargspec(shell_funcs[f])), synop)
                print
                print "For help on a specific command, type 'hh(<command>)'"
            elif type(cmd) == str:
                try:
                    doc = pydoc.getdoc(shell_funcs[cmd])
                except KeyError:
                    print "No such command: {0}".format(cmd)
                    return
                print doc
            else:
                doc = pydoc.getdoc(cmd)
                print doc

        # Break into shell
        banner = "Welcome to volshell! Current memory image is:\n{0}\n".format(self._config.LOCATION)
        banner += "To get help, type 'hh()'"
        try:
            from IPython.Shell import IPShellEmbed #pylint: disable-msg=W0611,F0401
            shell = IPShellEmbed([], banner = banner)
            shell()
        except ImportError:
            import code, inspect

            class GdbConsole(code.InteractiveConsole): 
                def runsource(self, source, filename="<input>", symbol="single"):
                    try:
                        code = self.compile(source, filename, symbol)
                    except (OverflowError, ValueError):
                        # Case 1
                        self.showsyntaxerror(filename)
                        return False
                    #hook syntax error exception
                    except (SyntaxError):
                        g(source)
                        return False

                    if code is None:
                        # Case 2
                        return True

                    # Case 3
                    self.runcode(code)
                    return False

            frame = inspect.currentframe()

            # Try to enable tab completion
            try:
                import rlcompleter, readline #pylint: disable-msg=W0612
                readline.parse_and_bind("tab: complete")
            except ImportError:
                pass

            #replaced code.interact with this so we can hook SyntaxException
            readfunc = None
            namespace = frame.f_globals.copy()
            namespace.update(frame.f_locals)

            console = GdbConsole(namespace)
            if readfunc is not None:
                console.raw_input = readfunc
            else:
                try:
                    import readline
                except ImportError:
                    pass
            console.interact(banner)

            
