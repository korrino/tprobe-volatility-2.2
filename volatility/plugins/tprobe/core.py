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
@author:       Maciej Szawlowski and Tomasz Salacinski
@license:      GNU General Public License 2.0 or later
@contact:      contact@korrino.com  
@organization: Korrino
"""

import sys
import volatility.registry as registry
import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj
import volatility.conf as conf
cfg = conf.ConfObject()

# temporary debug
from pprint import pprint

import shlex
import copy
import gdb


#from debugutils import BptIndex

class Breakpoint(object):
    def __init__(self, address=0x0, num=None, type=None, disp=None, enb=None, what=None, cond=None):
        self.num = num
        self.type = type
        self.disp = disp
        self.enb = enb
        self.address = address
        self.what = what
        self.cond = cond

class BptIndex(object):
    def __init__(self):
        self.bpts = {}
        self.readBpts()
        
    def addBpt(self, bp, dtb=None):
        if(dtb is None): 
            gdb.execute('b *{0}'.format(bp.address),False, True)
        else:
            gdb.execute('b *{0} if $cr3=={1}'.format(bp.address, dtb),False, True)
        self.readBpts()

    def delBpt(self, address):
        bpt = self.bpts["0x%08x" % address]
        gdb.execute('del {0}'.format(bpt.num),False, True)
        self.readBpts()

    def readBpts(self):
        self.bpts = {}
        data = gdb.execute("info break", False, True)
        if(data == None): return

        bp = Breakpoint()
        for line in data.split("\n"):
            print line
            if(line.find("No breakpoints")>=0): return
            if(len(line) >0):
                if(line[0] != "\t"):
                    if(bp.num != None and bp.num != "Num"):
#                        self.addBpt(bp, False, True)
                        self.bpts[bp.address] = bp
                    try:
                        bp.num, bp.type, bp.disp, bp.enb, bp.address, bp.what = line.split()
                    except:
                        bp.num, bp.type, bp.disp, bp.enb, bp.address = line.split()
                else:
                    cond = line.find("stop")
                    if(cond <0): cond = None
                    bp.cond = cond
        self.bpts[bp.address] = bp

class TProbeVolatilityDTB(obj.VolatilityMagic):
    def generate_suggestions(self):
        offset = 0x0
        found = self.obj_vm.find(offset, constants.SCAN_BLOCKSIZE, str(self.obj_parent.DTBSignature))
        while (found != None):
                proc = obj.Object("_EPROCESS", offset = found, vm = self.obj_vm)
                if 'Idle' in proc.ImageFileName.v():
                    yield proc.Pcb.DirectoryTableBase.v()
                found = self.obj_vm.find(found+1, constants.SCAN_BLOCKSIZE, str(self.obj_parent.DTBSignature))

class TProbeDTBModification(obj.ProfileModification):
    after = ["BasicObjectClasses"]
    conditions = {'os': lambda x: x == 'windows' and cfg.GDB}
    def modification(self, profile):
        print "loading dtb scanner modification"
        profile.object_classes.update({
            'VolatilityDTB': TProbeVolatilityDTB
            })


class FunctionDict(object):
    def __init__(self):
        self.dict = {}

    def __getattribute__(self, name):
        if name in ['dict']:
            return object.__getattribute__(self,name)
        return self.dict[name]

class OptionParserCopy(conf.PyFlagOptionParser):
    def __init__(self, base_parser):
        conf.PyFlagOptionParser.__init__(self, add_help_option = False, version = False)
        self.base_parser = base_parser
        self.add_options(base_parser.option_list)


class LocalConfig(conf.ConfObject):
    def __init__(self, config = None):
        # what to do with this object??
        # get current optparser options and set on new object to copy
        self.optparser = OptionParserCopy(config.optparser) 
        # conf.PyFlagOptionParser(
        #     add_help_option = False,
        #     version = False)

        self.initialised = False
        self.g_dict = dict(__builtins__ = None)
        self.cnf_opts = {}
        self.opts = {}
        self.args = None
        self.default_opts = {}
        self.docstrings = {}
        self.optparse_opts = None
        self._filename = config.CONF_FILE
        self._filenames = []
        self.readonly = {}
        self._absolute = {}
        self.options = []
        self.cache_invalidators = {} 

        # add just one file so that filename is not None
        # self.add_file(self._filename)
        
        if config is not None:
        #     self.optparser = copy.copy(config.optparser)
        #     self.g_dict = dict(config.g_dict)
        #     self.cnf_opts = dict(config.cnf_opts)
        #     self.opts = dict(config.opts)
            self.default_opts = dict(config.default_opts)
            self.docstrings = dict(config.docstrings)
        #     # self.optparse_opts = copy.deepcopy(config.optparse_opts) 
            self._filename = config._filename 
            self._filenames = config._filenames 
            self.readonly = dict(config.readonly)
        #     self._absolute = dict(config._absolute)
            self.options = list(config.options) 




class AbstractTProbePlugin(object):
    # lower is better
    after_validation_priority = 10
    priority = 10
    name = ''
    dependencies = []

    def __init__(self, tprobe_core, name = None):
        self.core = tprobe_core
        self.functions = tprobe_core.functions
        
        if name is not None:
            self.name = name

        if self.name in self.functions.dict:
            if self.functions.dict[self.name].priority < self.priority:
                self.functions.dict[self.name] = self
            elif self.functions.dict[self.name].priority == self.priority:
                print "Two plugins with same name [{0}], valid profile and priority - something is wrong.".format(self.name)
        else:
            self.functions.dict[self.name] = self   


    def __call__(self, *args, **kwargs):
        return self.execute(*args, **kwargs)

    def calculate(self, *args, **kwargs):
        # if time consuming return generator
        pass

    def render_text(self, objects):
        # render output
        pass

    def execute(self, *args, **kwargs):
        self.render_text(self.calculate(*args, **kwargs))

    def after_validation(self):
        # init plugin somehow
        pass

    def check_dependencies(self):
        for dep in self.dependencies:
            if not dep in self.functions.dict:
                raise Exception("Module with name value [{0}] not found while loading {1} - dependencies are broken.".format(dep, self.__class__.__name__))
                # return False
        return True

    def help(self):
        # help text to render while listing
        pass

    @staticmethod
    def is_valid_profile(profile):
        return True

class AbstractTProbeApiFunction(AbstractTProbePlugin):
    def execute(self, *args, **kwargs):
        return self.calculate(*args, **kwargs)


class AbstractVolatilityPluginWrapper(AbstractTProbePlugin):
    def __init__(self, tprobe_core, config, plugin_class, *args, **kwargs):
        AbstractTProbePlugin.__init__(self, tprobe_core, name = plugin_class.__name__.lower())

        self.volatility_plugin = plugin_class(config, args, kwargs)
        self.config = config

    def calculate(self):
        self.volatility_plugin.calculate()

    def execute(self, new_argv = None):
        #  dirty hack
        if new_argv is not None:
            print "Executing plugin:   ./vol.py {0} ".format(self.name) + new_argv
            sys.argv = shlex.split("./vol.py {0} ".format(self.name) + new_argv)

        self.config.parse_options()
        self.volatility_plugin.execute()

    def dump_config(self):
        config = self.config
        print "g_dict"
        pprint(config.g_dict)
        print "cnf_opts"
        pprint(config.cnf_opts) 
        print "opts"
        pprint(config.opts)
        print "args"
        pprint(config.args)
        print "default_opts"
        pprint(config.default_opts)
        print "docstrings"
        pprint(config.docstrings)
        print "optparse_opts"
        pprint(config.optparse_opts)
        print "_filename"
        pprint(config._filename)
        print "_filenames"
        pprint(config._filenames)
        print "readonly"
        pprint(config.readonly)
        print "_absolute"
        pprint(config._absolute)
        print "options"
        pprint(config.options)



class tprobe(commands.Command):
    """Shell in the memory image"""

    #TODO
    # Declare meta information associated with this plugin

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)

        config.update("CACHED_AS", None)

        # TODO register options somwhere else since it is polluting optionspace
        # possible SOLVE: copy config object as a template for others
        # config.add_option('OFFSET', short_option = 'o', default = None,
        #                   help = 'EPROCESS Offset (in hex) in kernel address space',
        #                   action = 'store', type = 'int')
        # config.add_option('IMNAME', short_option = 'n', default = None,
        #                   help = 'Operate on these Process IDs (comma-separated)',
        #                   action = 'store', type = 'str')
        # config.add_option('PID', short_option = 'p', default = None,
        #                   help = 'Operate on these Process IDs (comma-separated)',
        #                   action = 'store', type = 'str')

        self.addrspace = None
        # self.eproc = None
        self.plugin_cfg = []
        self.argv = sys.argv
        self.functions = FunctionDict()
        self.config = config
        self.current_context = None
        self.reading_context = None
        self.symbols_by_name = {}
        self.symbols_by_offset = {}
        self.kernel_symbols_by_name = {}
        self.kernel_symbols_by_offset = {}
#        self.bpts = {}
        self.bp_index = BptIndex()

    def load_volatility_plugins(self):
        cmds = registry.get_plugin_classes(commands.Command, lower = True)
        for plugin_name in cmds:
            if cmds[plugin_name].is_valid_profile(self.addrspace.profile) and plugin_name is not 'tprobe':
                # TODO: passing config causes option overlapping so we need class similiar to config but not a singleton, rather a copy of config per each plugin
                # AbstractVolatilityPluginWrapper(self.functions, self.config, cmds[plugin_name])
                AbstractVolatilityPluginWrapper(self, LocalConfig(self.config), cmds[plugin_name])
                # break

    def load_tprobe_plugins(self):
        cmds = registry.get_plugin_classes(AbstractTProbePlugin, lower = True)
        for plugin_name in cmds:
            if cmds[plugin_name].is_valid_profile(self.addrspace.profile):
                cmds[plugin_name](self)

    def render_text(self, _outfd, _data):
        print "Loading AS"
        self.addrspace = utils.load_as(self._config)
        self.os = self.addrspace.profile.metadata.get('os', 'unknown')
 
        print "Loading plugins"
        self.load_volatility_plugins()
        self.load_tprobe_plugins()

        for plugin in self.functions.dict.values():
            plugin.check_dependencies()

        plugins_to_init = self.functions.dict.values()
        print "Plugins:"
        print plugins_to_init
        plugins_to_init.sort(cmp=(lambda x,y: 1 if x.after_validation_priority > y.after_validation_priority else -1))
        
        for plugin in plugins_to_init:
            plugin.after_validation()


   
