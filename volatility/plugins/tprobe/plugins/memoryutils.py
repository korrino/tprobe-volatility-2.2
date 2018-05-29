import volatility.plugins.tprobe.core as tprobe
import volatility.utils as utils
import volatility.obj as obj
import struct

class CanonicalHexDump(tprobe.AbstractTProbePlugin):
	name = 'db'
	dependencies = ['get_EPROCESS']

	def calculate(self, address, length = 0x80, space = None):
		if not space:
                        space = self.core.current_EPROCESS.get_process_address_space() 
		
		data = space.read(address, length)
		if not data:
			print "Memory unreadable at {0:08x}".format(address)
			return 

		for offset, hexchars, chars in utils.Hexdump(data):
			print "{0:#010x}  {1:<48}  {2}".format(address + offset, hexchars, ''.join(chars))

class PrintDwords(tprobe.AbstractTProbePlugin):
	name = 'dd'
	dependencies = ['get_EPROCESS']

	def calculate(self, address, length = 0x80, space = None):
		if not space:
                        space = self.core.current_EPROCESS.get_process_address_space() 
		
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

class PrintQwords(tprobe.AbstractTProbePlugin):
	name = 'dq'
	dependencies = ['get_EPROCESS']

	def calculate(self, address, length = 0x80, space = None):
		if not space:
                        space = self.core.current_EPROCESS.get_process_address_space() 
		
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

class DescribeObjectType(tprobe.AbstractTProbePlugin):
	name = 'dt'
	dependencies = ['get_EPROCESS']

	def calculate(self, objct, address = None, address_space = None, return_object = False):
		EPROCESS = self.core.current_EPROCESS
		profile = (address_space or EPROCESS.obj_vm).profile

		if address is not None:
			objct = obj.Object(objct, address, address_space or EPROCESS.get_process_address_space())
		if return_object is True:
			return objct

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

