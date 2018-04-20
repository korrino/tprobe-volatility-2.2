import volatility.plugins.tprobe.core as tprobe
import volatility.win32 as win32
import volatility.obj as obj

class GetWindowsProcessList(tprobe.AbstractTProbeApiFunction):
    name = 'get_process_list'

    def calculate(self):
    	return win32.tasks.pslist(self.core.addrspace)

class GetWindowsProcessName(tprobe.AbstractTProbeApiFunction):
    name = 'get_process_name'

    def calculate(self, proc = None):
    	if proc == None:
            proc = self.core.current_context
        return proc.ImageFileName

class GetWindowsProcessId(tprobe.AbstractTProbeApiFunction):
    name = 'get_process_id'

    def calculate(self, proc = None):
    	if proc == None:
            proc = self.core.current_context
        return proc.UniqueProcessId.v()

class GetWindowsProcessParentId(tprobe.AbstractTProbeApiFunction):
    name = 'get_process_parent_id'

    def calculate(self, proc = None):
    	if proc == None:
            proc = self.core.current_context
        return proc.InheritedFromUniqueProcessId.v()

class WindowsPs(tprobe.AbstractTProbePlugin):
    name = 'ps'
    dependencies = ['get_process_list','get_process_name', 'get_process_id', 'get_process_parent_id']

    def calculate(self, procs = None):
    	return procs or self.functions.get_process_list()

    def render_text(self, objects):
    	f = self.functions
    	for eproc in objects:
            print "{0:16} {1:<6} {2:<6} {3:#08x}".format(
				f.get_process_name(eproc),
				f.get_process_id(eproc),
				f.get_process_parent_id(eproc),
				eproc.obj_offset
			)

class WindowsChangeContext(tprobe.AbstractTProbePlugin):
    name = 'cc'
    dependencies = ['get_context', 'get_process_name','get_process_id','get_process_parent_id']

    def calculate(self, offset = None, pid = None, name = None, dtb = None):
        self.core.current_context = self.functions.get_context(offset = offset, pid = pid, name = name, dtb = dtb)
    	return self.core.current_context

    def render_text(self, context):
    	f = self.functions
    	print "Current context: process {0}, pid={1}, ppid={2} DTB={3:#x}".format(
    		f.get_process_name(context),
			f.get_process_id(context),
			f.get_process_parent_id(context),
			context.Pcb.DirectoryTableBase.v()
		)

class UpdateCurrentContext(tprobe.AbstractTProbeApiFunction):
    name = 'update_context'
    dependencies = ['get_context', 'gr']

    def calculate(self):
        dtb = int(self.core.functions.gr("cr3"))
        self.core.current_context = self.core.functions.get_context(dtb = dtb)
        self.core.addrspace = self.core.current_context.get_process_address_space()
        return self.core.current_context

class GetWindowsContext(tprobe.AbstractTProbeApiFunction):
    name = 'get_context'
    dependencies = ['create_process_object','get_process_list','get_process_name', 'get_process_id', 'get_process_parent_id']

    def calculate(self, offset = None, pid = None, name = None, dtb = None):
    	f = self.functions
    	if pid is not None:
            offsets = []
            for p in f.get_process_list():
                if f.get_process_id(p) == pid:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching pid {0}".format(pid)
                return
            elif len(offsets) > 1:
                print "Multiple processes match {0}, please specify by offset".format(pid)
                print "Matching processes:"
                f.ps(offsets)
                return
            else:
                offset = offsets[0].v()
        elif name is not None:
            offsets = []
            for p in f.get_process_list():
                if f.get_process_name(p).find(name) >= 0:
                    offsets.append(p)
            if not offsets:
                print "Unable to find process matching name {0}".format(name)
                return
            elif len(offsets) > 1:
                print "Multiple processes match name {0}, please specify by PID or offset".format(name)
                print "Matching processes:"
                f.ps(offsets)
                return
            else:
                offset = offsets[0].v()
        # TODO remove or enable only for windows 
        elif dtb is not None:
            offsets = []
            for p in f.get_process_list(): #previously was _id, this was a mistake?
                if dtb == p.Pcb.DirectoryTableBase.v():
                    offsets.append(p)
            if not offsets:
#                print "Unable to find process matching name {0}".format(name)
                return self.calculate(name="System")
            else:
                offset = offsets[0].v()
        elif offset is None:
            for p in f.get_process_list():
                return p

        return f.create_process_object(offset)

class CreateWindowsProcessObject(tprobe.AbstractTProbeApiFunction):
    name = 'create_process_object'

    def calculate(self, offset):
    	return obj.Object("_EPROCESS", offset = offset, vm = self.core.addrspace)



