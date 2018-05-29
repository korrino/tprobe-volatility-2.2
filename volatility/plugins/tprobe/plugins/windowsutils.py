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
            proc = self.core.current_EPROCESS
        return proc.ImageFileName

class GetWindowsProcessId(tprobe.AbstractTProbeApiFunction):
    name = 'get_process_id'

    def calculate(self, proc = None):
    	if proc == None:
            proc = self.core.current_EPROCESS
        return proc.UniqueProcessId.v()

class GetWindowsProcessParentId(tprobe.AbstractTProbeApiFunction):
    name = 'get_process_parent_id'

    def calculate(self, proc = None):
    	if proc == None:
            proc = self.core.current_EPROCESS
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

class WindowsChangeEPROCESS(tprobe.AbstractTProbePlugin):
    name = 'ce'
    dependencies = ['get_EPROCESS', 'get_process_name','get_process_id','get_process_parent_id']

    def calculate(self, offset = None, pid = None, name = None, dtb = None):
        self.core.current_EPROCESS = self.functions.get_EPROCESS(offset = offset, pid = pid, name = name, dtb = dtb)
    	return self.core.current_EPROCESS

    def render_text(self, EPROCESS):
    	f = self.functions
    	print "Current EPROCESS: process {0}, pid={1}, ppid={2} DTB={3:#x}".format(
    		f.get_process_name(EPROCESS),
			f.get_process_id(EPROCESS),
			f.get_process_parent_id(EPROCESS),
			EPROCESS.Pcb.DirectoryTableBase.v()
		)

class UpdateCurrentEPROCESS(tprobe.AbstractTProbeApiFunction):
    name = 'uce'
    dependencies = ['get_EPROCESS', 'gr']

    def calculate(self):
        dtb = int(self.core.functions.gr("cr3"))
        self.core.current_EPROCESS = self.core.functions.get_EPROCESS(dtb = dtb)
        self.core.addrspace = self.core.current_EPROCESS.get_process_address_space()
        return self.core.current_EPROCESS

class GetWindowsEPROCESSByPID(tprobe.AbstractTProbeApiFunction):
    name = 'get_EPROCESS_by_pid'
    dependencies = ['offset_to_EPROCESS','get_process_list','get_process_name', 'get_process_id', 'get_process_parent_id']

    def calculate(self, pid):
    	functions = self.functions
        offsets = []
        for process in functions.get_process_list():
            if functions.get_process_id(process) == pid:
                offsets.append(process)
        if not offsets:
            print "Unable to find process matching pid {0}".format(pid)
            return
        elif len(offsets) > 1:
            print "Multiple processes match {0}, please specify by offset".format(pid)
            print "Matching processes:"
            functions.ps(offsets)
            return
        else:
            offset = offsets[0].v()
            return offset

class GetWindowsEPROCESSByName(tprobe.AbstractTProbeApiFunction):
    name = 'get_EPROCESS_by_name'
    dependencies = ['offset_to_EPROCESS','get_process_list','get_process_name', 'get_process_id', 'get_process_parent_id']

    def calculate(self, name):
    	functions = self.functions
        offsets = []
        for process in functions.get_process_list():
            if functions.get_process_name(process).find(name) >= 0:
                offsets.append(process)
        if not offsets:
            print "Unable to find process matching name {0}".format(name)
            return
        elif len(offsets) > 1:
            print "Multiple processes match name {0}, please specify by PID or offset".format(name)
            print "Matching processes:"
            functions.ps(offsets)
            return
        else:
            offset = offsets[0].v()
            return offset

class GetWindowsEPROCESSByDTB(tprobe.AbstractTProbeApiFunction):
    name = 'get_EPROCESS_by_dtb'
    dependencies = ['offset_to_EPROCESS','get_process_list','get_process_name', 'get_process_id', 'get_process_parent_id']

    def calculate(self, dtb):
    	functions = self.functions
        offsets = []
        for process in functions.get_process_list(): #previously was _id, this was a mistake?
            if dtb == process.Pcb.DirectoryTableBase.v():
                offsets.append(process)
        if not offsets:
#            print "Unable to find process matching name {0}".format(name)
            return self.calculate(name="System")
        else:
            offset = offsets[0].v()
            return offset

class GetWindowsEPROCESS(tprobe.AbstractTProbeApiFunction):
    name = 'get_EPROCESS'
    dependencies = ['offset_to_EPROCESS','get_process_list','get_process_name', 'get_process_id', 'get_process_parent_id']

    def calculate(self, offset = None, pid = None, name = None, dtb = None):
    	functions = self.functions
    	if pid is not None:
            offset = self.functions.get_EPROCESS_by_pid(pid)
        elif name is not None:
            offset = self.functions.get_EPROCESS_by_name(name)
        # TODO remove or enable only for windows 
        elif dtb is not None:
            offset = self.functions.get_EPROCESS_by_dtb(dtb)
        elif offset is None:
            for process in functions.get_process_list():
                return process

        return functions.offset_to_EPROCESS(offset)

class OffsetToEPROCESS(tprobe.AbstractTProbeApiFunction):
    name = 'offset_to_EPROCESS'

    def calculate(self, offset):
    	return obj.Object("_EPROCESS", offset = offset, vm = self.core.addrspace)



