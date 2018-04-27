import volatility.plugins.tprobe.core as tprobe
import volatility.utils as utils
import volatility.obj as obj
import code, inspect
from cStringIO import StringIO
#import gtk
#import gtk.gdk 

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk as gtk
from gi.repository import Gdk as gdk


import sys
#from debugutils import BptIndex,Breakpoint
import struct
from gdb import execute
import volatility.conf as conf
cfg = conf.ConfObject()
from shell import GdbConsole
from volatility.plugins.tprobe.core import Breakpoint
from threading import Thread

"""
class GdbConsole(code.InteractiveConsole): 
    def runsource(self, source, filename="<input>", symbol="single"):
        if(source == ""): return False
        try:
            cmds = source.split()
            if(self.shell.functions.dict.has_key(cmds[0])): 
                source = cmds[0] + "("
                for cmd in cmds[1:]:
                    source += "%s," % cmd
                source += ")"
            code = self.compile(source, filename, symbol)
        except (OverflowError, ValueError):
            # Case 1
            self.showsyntaxerror(filename)
            return False
        #hook syntax error exception
        except (SyntaxError):
            try:
                execute(source)
                return False
            except (RuntimeError):
                print("Runtime error, check your syntax. Try: help")
                return False

        if code is None:
            # Case 2
            return True

        # Case 3
        self.runcode(code)
        return False
"""

class TProbeShell(object):
    def __init__(self, gshell):
        self.gshell = gshell

        #load from file if exists
        self.history = []
        self.history_pos = 0x0
        self.history_size = 0x0

        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)
        self.window.connect("key_press_event", self.key_pressed)

        self.textBuffer = gtk.TextBuffer()
        self.output = gtk.TextView()
        self.output.set_buffer(self.textBuffer)
        self.output.connect("size-allocate", self.scrollDown)
        self.swh = gtk.ScrolledWindow()
        self.swh.add(self.output)

        self.input = gtk.Entry()
        self.input.connect("activate", self.enter_callback)

        vbox = gtk.VBox(False, 0)
        vbox.pack_start(self.swh, True, True, 0)
        vbox.pack_start(self.input, False, True, 0)

        self.window.add(vbox)
        self.window.show_all()
        self.stdout = StringIO()
        sys.stdout = self.stdout

    def scrollDown(self, widget, data=None):
        adj = self.swh.get_vadjustment()
        adj.set_value( adj.get_upper() - adj.get_page_size() )

    def enter_callback(self, widget, data=None):
        bp = sys.stdout
        sys.stdout = StringIO()

        cmd = self.input.get_text()
        if(cmd == ""):
            return 

        self.history_pos = 0x0
        self.history.append(cmd)
        self.history_size += 1

#        self.gshell.log("History size: %d" % self.history_size)
#        self.gshell.log("History content: %s" % self.history)

        self.input.set_text("")
        self.gshell.console.runsource(cmd)
        out = sys.stdout.getvalue()
        self.textBuffer.insert(self.textBuffer.get_end_iter(), out)
        sys.stdout = bp

    def key_pressed(self, widget, data):
#        self.gshell.log(str(data.keyval)+"\n")
        if(data.keyval == 65362):
            if(self.history_pos < self.history_size):
                self.history_pos += 1
                self.input.set_text(self.history[self.history_size-self.history_pos])
            return True
        if(data.keyval == 65364):
            if(self.history_pos > 0x0):
                self.history_pos -= 1
                if(self.history_pos > 0x0):
                    self.input.set_text(self.history[self.history_size-self.history_pos])
                else:
                    self.input.set_text("")
                return True
        return False

class MemoryView(object):
    def __init__(self, gshell, address=None):
        self.gshell = gshell
        if(address == None):
            self.sync_reg = "esi"
            self.offset = self.gshell.functions.gr(self.sync_reg)
            self.data = self.gshell.core.addrspace.read(self.offset, 0x100)
        else:
            self.sync_reg = None
            self.offset = address
            self.data = self.gshell.core.addrspace.read(self.offset, 0x100)

        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)

        self.width = 0
        self.height = 0

        self.menu = gtk.Menu()
        menu_item1 = gtk.MenuItem("Sync with eax")
        menu_item1.connect("activate", self.activate_sync, "eax")
        self.menu.append(menu_item1)
        menu_item1.show()
        menu_item2 = gtk.MenuItem("Sync with ebx")
        menu_item2.connect("activate", self.activate_sync, "ebx")
        self.menu.append(menu_item2)
        menu_item2.show()
        menu_item3 = gtk.MenuItem("Sync with ecx")
        menu_item3.connect("activate", self.activate_sync, "ecx")
        self.menu.append(menu_item3)
        menu_item3.show()
        menu_item4 = gtk.MenuItem("Sync with edx")
        menu_item4.connect("activate", self.activate_sync, "edx")
        self.menu.append(menu_item4)
        menu_item4.show()
        menu_item5 = gtk.MenuItem("Sync with esi")
        menu_item5.connect("activate", self.activate_sync, "esi")
        self.menu.append(menu_item5)
        menu_item5.show()
        menu_item6 = gtk.MenuItem("Sync with edi")
        menu_item6.connect("activate", self.activate_sync, "edi")
        self.menu.append(menu_item6)
        menu_item6.show()
        menu_item7 = gtk.MenuItem("Sync with ebp")
        menu_item7.connect("activate", self.activate_sync, "ebp")
        self.menu.append(menu_item7)
        menu_item7.show()
        menu_item8 = gtk.MenuItem("Sync with esp")
        menu_item8.connect("activate", self.activate_sync, "esp")
        self.menu.append(menu_item8)
        menu_item8.show()
        menu_item9 = gtk.MenuItem("Sync with eip")
        menu_item9.connect("activate", self.activate_sync, "eip")
        self.menu.append(menu_item9)
        menu_item9.show()

        self.treeview = gtk.TreeView(self.get_model())
        self.offset_col = gtk.TreeViewColumn('Offset')
        self.offset_cell = gtk.CellRendererText()
        self.offset_col.pack_start(self.offset_cell, True)
        self.offset_col.set_attributes(self.offset_cell, text=0)
        self.treeview.append_column(self.offset_col)

        self.treeview.connect_object("button_press_event", self.button_pressed, self.menu)

        self.columns = []
        self.cells = []
        for i in range(0, 0x10):
            col = gtk.TreeViewColumn("+%x" % i)
#            self.columns.append(col)
            cell = gtk.CellRendererText()
            col.pack_start(cell, True)
            col.set_attributes(cell, text=i+1)
            self.treeview.append_column(col)

        col = gtk.TreeViewColumn("ASCII")
        cell = gtk.CellRendererText()
        col.pack_start(cell, True)
        col.set_attributes(cell, text=0x11)
        self.treeview.append_column(col)

        self.window.connect('scroll-event', self.onScroll)
#        self.window.add(self.vbox)
        self.window.add(self.treeview)

        self.window.show_all()

    def activate_sync(self, widget, reg):
        self.sync_reg = reg
        self.offset = self.gshell.functions.gr(self.sync_reg)
        self.data = self.gshell.core.addrspace.read(self.offset, 0x100)
        self.treeview.set_model(self.get_model())
        return True

    def done(self, widget, data=None):
        gtk.main_quit()
        return False

    def onScroll(self, widget, data=None):
        if(data.direction == gdk.SCROLL_UP):
            self.offset -= 0x10
        elif(data.direction == gdk.SCROLL_DOWN):
            self.offset += 0x10
        # like refresh only without updatnig offset
        # update_context not necessary, we might want to scroll other context's memory
        #self.gshell.functions.update_context()
#        space = self.gshell.core.reading_context or self.gshell.core.current_context
        space = (self.gshell.core.reading_context or self.gshell.core.current_context).get_process_address_space()
        self.data = space.read(self.offset, 0x100)
        self.treeview.set_model(self.get_model())

    def refresh(self):
        if(self.sync_reg != None):
            self.offset = self.gshell.functions.gr(self.sync_reg)
        space = (self.gshell.core.reading_context or self.gshell.core.current_context).get_process_address_space()
        self.data = space.read(self.offset, 0x100)
        self.treeview.set_model(self.get_model())

    def sanitize(self, data):
        sanitized = ""
        for byte in data:
            if(ord(byte) < 0x20): byte = "."
            if(ord(byte) > 0x7e): byte = "."
            sanitized += byte
        return sanitized

    def get_model(self):
        self.liststore = gtk.ListStore(str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str)

        for i in range(0, 0x10):
            line = ["0x%08x" % (i + self.offset)]
            try:
                line += ["%02x" % ord(self.data[i*0x10 + x]) for x in range(0, 0x10)]
            except Exception:
                line += ["??" for x in range(0, 0x10)]

            #ASCII col
            try:
                line.append(self.sanitize(self.data[i*0x10:i*0x10+0x10]))
            except Exception:
                line.append("??")

            self.liststore.append(line)
        return self.liststore

    def button_pressed(self, widget, event):
        if(event.button == 3):
            widget.popup(None, None, None, None, event.button, event.time)
            return True
        return False

class MemoryDwordView(MemoryView):
    def __init__(self, gshell):
        self.gshell = gshell
        self.sync_reg = "esp"
        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)

        self.width = 0
        self.height = 0
#        self.vbox = gtk.VBox(False, 0)
        self.offset = self.gshell.functions.gr(self.sync_reg)
        self.data = self.gshell.core.addrspace.read(self.offset, 0x40)

        self.menu = gtk.Menu()
        menu_item1 = gtk.MenuItem("Sync with eax")
        menu_item1.connect("activate", self.activate_sync, "eax")
        self.menu.append(menu_item1)
        menu_item1.show()
        menu_item2 = gtk.MenuItem("Sync with ebx")
        menu_item2.connect("activate", self.activate_sync, "ebx")
        self.menu.append(menu_item2)
        menu_item2.show()
        menu_item3 = gtk.MenuItem("Sync with ecx")
        menu_item3.connect("activate", self.activate_sync, "ecx")
        self.menu.append(menu_item3)
        menu_item3.show()
        menu_item4 = gtk.MenuItem("Sync with edx")
        menu_item4.connect("activate", self.activate_sync, "edx")
        self.menu.append(menu_item4)
        menu_item4.show()
        menu_item5 = gtk.MenuItem("Sync with esi")
        menu_item5.connect("activate", self.activate_sync, "esi")
        self.menu.append(menu_item5)
        menu_item5.show()
        menu_item6 = gtk.MenuItem("Sync with edi")
        menu_item6.connect("activate", self.activate_sync, "edi")
        self.menu.append(menu_item6)
        menu_item6.show()
        menu_item7 = gtk.MenuItem("Sync with ebp")
        menu_item7.connect("activate", self.activate_sync, "ebp")
        self.menu.append(menu_item7)
        menu_item7.show()
        menu_item8 = gtk.MenuItem("Sync with esp")
        menu_item8.connect("activate", self.activate_sync, "esp")
        self.menu.append(menu_item8)
        menu_item8.show()
        menu_item9 = gtk.MenuItem("Sync with eip")
        menu_item9.connect("activate", self.activate_sync, "eip")
        self.menu.append(menu_item9)
        menu_item9.show()
        menu_item10 = gtk.MenuItem("Open new BYTE+ASCII")
        menu_item10.connect("activate", self.open_in_new_ascii)
        self.menu.append(menu_item10)
        menu_item10.show()
        menu_item11 = gtk.MenuItem("Copy to clipboard")
        menu_item11.connect("activate", self.copy_to_clipboard)
        self.menu.append(menu_item11)
        menu_item11.show()

        self.treeview = gtk.TreeView(self.get_model())
        self.offset_col = gtk.TreeViewColumn('Offset')
        self.offset_cell = gtk.CellRendererText()
        self.offset_col.pack_start(self.offset_cell, True)
        self.offset_col.set_attributes(self.offset_cell, text=0)
        self.treeview.append_column(self.offset_col)

        self.treeview.connect_object("button_press_event", self.button_pressed, self.menu)

        self.columns = []
        self.cells = []
        self.value_col =  gtk.TreeViewColumn("Value")
        self.value_cell = gtk.CellRendererText()
        self.value_col.pack_start(self.value_cell, True)
        self.value_col.set_attributes(self.value_cell, text=1)
        self.treeview.append_column(self.value_col)

        self.window.connect('scroll-event', self.onScroll)
#        self.window.add(self.vbox)
        self.window.add(self.treeview)

        self.window.show_all()

    def copy_to_clipboard(self, widget, data=None):
        selection = self.view.get_selection()
        (model, pathlist) = selection.get_selected_rows()
        print(len(pathlist))
        for path in pathlist :
            tree_iter = model.get_iter(path)
            value = "%s" % (model.get_value(tree_iter,1))
            self.gshell.clipboard.set_text(value, -1)
            if(cfg.debug == True): self.gshell.log("Copied")

    def open_in_new_ascii(self, widget, data=None):
        selection = self.treeview.get_selection()
        (model, pathlist) = selection.get_selected_rows()
        print(len(pathlist))
        for path in pathlist :
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter, 1)
            value = int(value, 16)
            self.gshell.log("Opening new ASCII at: 0x%x\n" % value)
            self.gshell.mbs.append(MemoryView(self.gshell, value))
        

    def onScroll(self, widget, data=None):
        if(data.direction == gdk.SCROLL_UP):
            self.offset -= 0x4
        elif(data.direction == gdk.SCROLL_DOWN):
            self.offset += 0x4
        # like refresh only without updatnig offset
        #self.gshell.functions.update_context()
#        space = self.gshell.core.reading_context or self.gshell.core.current_context
        space = (self.gshell.core.reading_context or self.gshell.core.current_context).get_process_address_space()
        self.data = space.read(self.offset, 0x40)
        self.treeview.set_model(self.get_model())

    def refresh(self):
        self.offset = self.gshell.functions.gr(self.sync_reg)
        space = (self.gshell.core.reading_context or self.gshell.core.current_context).get_process_address_space()
        self.data = space.read(self.offset, 0x40)
        self.treeview.set_model(self.get_model())

    def get_model(self):
        self.liststore = gtk.ListStore(str, str)

        for i in range(0, 0x10):
            line = ["0x%08x" % (i + self.offset)]
            try:
                line += ["%08x" % struct.unpack("<I", self.data[i*0x4:i*0x4+0x4])]
            except Exception:
                line += ["??"]
            self.liststore.append(line)
        return self.liststore
"""
    def button_pressed(self, widget, event):
        if(event.button == 3):
            widget.popup(None, None, None, None, event.button, event.time)
            return True
        return False
"""


class RegistersView(object):
    def __init__(self, gshell):
        self.gshell = gshell
        self.functions = gshell.functions

        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)

        self.regs1view = self.generate_view(self.get_regs1_model, "Register", "Value")
        self.regs2view = self.generate_view(self.get_regs2_model, "Register", "Value")
        self.regs3view = self.generate_view(self.get_regs3_model, "F", "V")

        hbox = gtk.HBox(False, 0)
        hbox.pack_start(self.regs1view, False, True, 0)
        hbox.pack_start(self.regs3view, False, True, 0)
        
        self.notebook = gtk.Notebook()
        self.notebook.append_page(hbox, gtk.Label("General"))
        self.notebook.append_page(self.regs2view, gtk.Label("Segment"))
#        self.notebook.append_page(self.regs3view, gtk.Label("Regs3"))


        self.window.add(self.notebook)
        self.window.show_all()

    def generate_view(self, model_func, cap1, cap2):
        view = gtk.TreeView(model_func())
        reg_col = gtk.TreeViewColumn(cap1)
        reg_cell = gtk.CellRendererText()
        reg_col.pack_start(reg_cell, True)
        reg_col.set_attributes(reg_cell, text=0)
        view.append_column(reg_col)
        val_col = gtk.TreeViewColumn(cap2)
        val_cell = gtk.CellRendererText()
        val_col.pack_start(val_cell, True)
        val_col.set_attributes(val_cell, text=1)
        view.append_column(val_col)
        return view

    def refresh(self):
        self.regs1view.set_model(self.get_regs1_model())
        self.regs2view.set_model(self.get_regs2_model())
        self.regs3view.set_model(self.get_regs3_model())

    def get_regs1_model(self):
        self.liststore = gtk.ListStore(str, str)

        regs = self.functions.regs.calculate()

        for reg in ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip"]:
            line = [reg, "%08x" % regs[reg]]
            self.liststore.append(line)
        return self.liststore

    def get_regs2_model(self):
        self.liststore = gtk.ListStore(str, str)

        regs = self.functions.regs2.calculate()

        for reg in ["cs", "ss", "ds", "es", "fs", "gs"]:
            line = [reg, "%08x" % regs[reg]]
            self.liststore.append(line)
        return self.liststore

    def get_regs3_model(self):
        self.liststore = gtk.ListStore(str, str)

        regs = self.functions.regs3.calculate()

        for reg in ["CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"]:
            line = [reg, "%01x" % regs[reg]]
            self.liststore.append(line)
        return self.liststore

    def get_regs4_model(self):
        self.liststore = gtk.ListStore(str, str)

        regs = self.functions.regs4.calculate()

        for reg in regs:
            line = [reg, "%08x" % regs[reg]]
            self.liststore.append(line)
        return self.liststore

class CodeView(object):
    def __init__(self, gshell):
        self.gshell = gshell
        self.dialog = None
        self.offset = None

        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)
        self.window.connect("key_press_event", self.key_pressed)

        self.menu = gtk.Menu()
        menu_item1 = gtk.MenuItem("Insert breakpoint")
        menu_item1.connect("activate", self.activate_insert_bp)
        self.menu.append(menu_item1)
        menu_item1.show()
        menu_item2 = gtk.MenuItem("Delete breakpoint")
        menu_item2.connect("activate", self.activate_delete_bp)
        self.menu.append(menu_item2)
        menu_item2.show()
        menu_item3 = gtk.MenuItem("Run until here")
        menu_item3.connect("activate", self.activate_run_until)
        self.menu.append(menu_item3)
        menu_item3.show()
        menu_item4 = gtk.MenuItem("Goto")
        menu_item4.connect("activate", self.activate_goto_prompt)
        self.menu.append(menu_item4)
        menu_item4.show()
        menu_item5 = gtk.MenuItem("Goto IP")
        menu_item5.connect("activate", self.activate_gotoIp)
        self.menu.append(menu_item5)
        menu_item5.show()
        menu_item6 = gtk.MenuItem("Refresh")
        menu_item6.connect("activate", self.activate_refresh)
        self.menu.append(menu_item6)
        menu_item6.show()
        menu_item7 = gtk.MenuItem("Copy to clipboard")
        menu_item7.connect("activate", self.copy_to_clipboard)
        self.menu.append(menu_item7)
        menu_item7.show()

        self.view = gtk.TreeView(self.get_model())
        self.view.connect_object("button_press_event", self.button_pressed, self.menu)
        off_col = gtk.TreeViewColumn("Offset")
        off_cell = gtk.CellRendererText()

        off_col.pack_start(off_cell, True)
        off_col.set_attributes(off_cell, text=0, background=2)
        self.view.append_column(off_col)
        instr_col = gtk.TreeViewColumn("Instruction")
        instr_cell = gtk.CellRendererText()
        instr_col.pack_start(instr_cell, True)
        instr_col.set_attributes(instr_cell, text=1, background=2)
        self.view.append_column(instr_col)

        swh = gtk.ScrolledWindow()
        swh.add(self.view)
        self.window.add(swh)
        self.window.show_all()

    def copy_to_clipboard(self, widget, data=None):
        selection = self.view.get_selection()
        (model, pathlist) = selection.get_selected_rows()
        print(len(pathlist))
        for path in pathlist :
            tree_iter = model.get_iter(path)
            value = "%s: %s" % (model.get_value(tree_iter,0), model.get_value(tree_iter,1))
            self.gshell.clipboard.set_text(value, -1)
            if(cfg.debug == True): self.gshell.log("Copied")

    def key_pressed(self, widget, data):
#        self.gshell.log(str(data.keyval)+"\n")
        if(gdk.keyval_name(data.keyval) == "F2"):
            self.activate_insert_bp(widget, data)
        if(gdk.keyval_name(data.keyval) == "F8"):
            self.gshell.functions.ni.calculate()
        if(gdk.keyval_name(data.keyval) == "F7"):
            self.gshell.functions.si.calculate()
        if(gdk.keyval_name(data.keyval) == "F9"):
            self.gshell.functions.c.calculate()
        if(gdk.keyval_name(data.keyval) == "g"):
            self.activate_goto_prompt(None)
        self.gshell.refresh()
        return True

    def button_pressed(self, widget, event):
        if(event.button == 3):
            widget.popup(None, None, None, None, event.button, event.time)
            return True
        return False

    def activate_insert_bp(self, widget, data=None):
        selection = self.view.get_selection()
        (model, pathlist) = selection.get_selected_rows()
        print(len(pathlist))
        for path in pathlist :
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter,0)
            self.gshell.log("Setting breakpoint at: %s\n" % value)
            self.gshell.core.bp_index.addBpt(Breakpoint(address=int(value, 16)))
            if(cfg.debug == True): self.gshell.log("Current bp index: %s\n" % self.gshell.core.bp_index.bpts)
        self.refresh()
        
    def activate_delete_bp(self, widget, data=None):
        selection = self.view.get_selection()
        (model, pathlist) = selection.get_selected_rows()
        print(len(pathlist))
        for path in pathlist :
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter,0)
            self.gshell.log("Deleting breakpoint at: %s\n" % value)
            self.gshell.core.bp_index.delBpt(int(value, 16))
        self.refresh()

    def activate_run_until(self, widget, data=None):
        selection = self.view.get_selection()
        (model, pathlist) = selection.get_selected_rows()
        print(len(pathlist))
        for path in pathlist :
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter,0)
        self.gshell.log("Running until: %s\n" % value)
        self.gshell.functions.until.calculate(int(value, 16))
        self.gshell.refresh()

    def activate_goto_prompt(self, widget, data=None):
        hbox = gtk.HBox()
        label = gtk.Label("Offset: ")
        entry = gtk.Entry()
        entry.connect("activate", self.activate_goto)
        button = gtk.Button("Go")
        hbox.pack_start(label, False, True, 0)
        hbox.pack_start(entry, False, True, 0)
#        hbox.pack_start(button, False, 0)
        self.dialog = gtk.Dialog(title="Goto", parent=None, flags=0)
        self.dialog.action_area.pack_start(hbox, True, True, 0)
        self.dialog.show_all()
        return True

    def activate_goto(self, widget, data=None):
        try:
            self.offset = int(widget.get_text(), 16)
        except Exception:
            self.offset = None
        self.gshell.log("Goto: 0x%x" % self.offset)
        self.view.set_model(self.get_model())
        self.dialog.hide()

    def activate_gotoIp(self, widget, data=None):
        self.refresh()
        return True

    def activate_refresh(self, widget, data=None):
        self.refresh()
        return True

    def refresh(self):
        self.offset = None
        self.view.set_model(self.get_model())

    def get_model(self):
        liststore = gtk.ListStore(str, str, str)
    
        space = (self.gshell.core.reading_context or self.gshell.core.current_context).get_process_address_space()
        for line in self.gshell.functions.dis.calculate(self.offset, space = space):
            addr = "0x%08x" % line[0]
            if(addr in self.gshell.core.bp_index.bpts.keys()):
                liststore.append([addr, line[1], "red"])
            elif(int(addr, 16) == self.gshell.functions.regs.calculate()["eip"]):
                liststore.append([addr, line[1], "blue"])
            else:
                liststore.append([addr, line[1], "white"])

        return liststore

class ProcessView(object):
    def __init__(self, gshell):
        self.gshell = gshell

        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)

        self.view = gtk.TreeView(self.get_model())
        off_col = gtk.TreeViewColumn("Process Name")
        off_cell = gtk.CellRendererText()
        off_col.pack_start(off_cell, True)
        off_col.set_attributes(off_cell, text=0, background=2)
        self.view.append_column(off_col)
        instr_col = gtk.TreeViewColumn("_EPROCESS")
        instr_cell = gtk.CellRendererText()
        instr_col.pack_start(instr_cell, True)
        instr_col.set_attributes(instr_cell, text=1, background=2)
        self.view.append_column(instr_col)

        self.menu = gtk.Menu()
        menu_item1 = gtk.MenuItem("Wait for task switch")
        menu_item1.connect("activate", self.activate_wait_for_task_switch, "test")
        self.menu.append(menu_item1)
        menu_item1.show()
        menu_item2 = gtk.MenuItem("Set reading context")
        menu_item2.connect("activate", self.activate_set_reading_context, "test")
        self.menu.append(menu_item2)
        menu_item2.show()

        self.view.connect_object("button_press_event", self.button_pressed, self.menu)
        self.window.add(self.view)
        self.window.show_all()

    def activate_wait_for_task_switch(self, widget, data):
        selection = self.view.get_selection()
        (model, pathlist) = selection.get_selected_rows()
        print(len(pathlist))
        for path in pathlist :
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter,1)
            self.gshell.log("Waiting for task switch: %s\n" % value)
            self.gshell.functions.eprocWait.calculate(int(value, 16))
        self.gshell.refresh()

    def activate_set_reading_context(self, widget, data):
        selection = self.view.get_selection()
        (model, pathlist) = selection.get_selected_rows()
        print(len(pathlist))
        for path in pathlist :
            tree_iter = model.get_iter(path)
            value = model.get_value(tree_iter,1)
            self.gshell.log("Setting reading context to: %s\n" % value)
#            self.gshell.functions.cc.calculate(int(value, 16))
            self.gshell.core.reading_context = self.gshell.core.functions.get_context(int(value, 16))
            if(cfg.debug == True): self.gshell.log("Reading context: 0x%x\n" % self.gshell.core.current_context.v())
        self.gshell.refresh()

    def refresh(self):
        self.view.set_model(self.get_model())

    def get_model(self):
        liststore = gtk.ListStore(str, str, str)

#        self.gshell.current_context = self.gshell.functions.update_context.calculate()

        for proc in self.gshell.functions.get_process_list.calculate():
            color = "white"
            if(self.gshell.core.reading_context == proc.v()):
                color = "green"
#                liststore.append([self.gshell.functions.get_process_name(proc), "%08x" % proc.v(), "green"])
            if(self.gshell.core.current_context == proc.v()):
#                liststore.append([self.gshell.functions.get_process_name(proc), "%08x" % proc.v(), "blue"])
                color = "blue"
            liststore.append(["%s" % self.gshell.functions.get_process_name(proc), "%08x" % proc.v(), color])
        return liststore

    def button_pressed(self, widget, event):
        if(event.button == 3):
            widget.popup(None, None, None, None, event.button, event.time)
            return True
        return False

class AboutView(object):
    def __init__(self, gshell):
        self.gshell = gshell

        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)

        from gi.repository import GdkPixbuf
        logo = GdkPixbuf.Pixbuf.new_from_file_at_size("korrino.png", 200, 200)

        about = gtk.AboutDialog()
        about.set_title("About TProbe")
        about.set_program_name("TProbe")
        about.set_name("TProbe")
        about.set_version("1.0")
        about.set_comments("sadf sadf asdf sadf asdf asdfa afds a")
        about.set_website("http://www.korrino.com")
        about.set_website_label("http://www.korrino.com")
        about.set_logo(logo)
        about.connect("response", self.destroy)

        self.about = about

        about.run()

    def destroy(self, widget, data):
        self.about.destroy()
        

class PatronsView(object):
    def __init__(self, gshell):
        self.gshell = gshell

        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)
        from gi.repository import GdkPixbuf
        logo = GdkPixbuf.Pixbuf.new_from_file_at_size("korrino.png", 200, 200)

        patrons = gtk.AboutDialog()
        patrons.set_title("Korrino Patrons")
        patrons.set_program_name("Patrons")
        patrons.set_comments("""
Korrino Patrons keep us alive!

We have not Patrons yet. Be the first one!

""")
        patrons.set_website("http://www.korrino.com")
        patrons.set_website_label("http://www.korrino.com")
        patrons.set_logo(logo)
        patrons.connect("response", self.destroy)

        self.patrons = patrons

        patrons.run()

    def destroy(self, widget, data):
        self.patrons.destroy()

class Main(object):
    def __init__(self, gshell):
        self.gshell = gshell
        self.window = gtk.Window(gtk.WindowType.TOPLEVEL)
        self.window.connect("destroy", self.quit)

        # Memory view
        self.mbButton = gtk.Button("Memory (BYTE+ASCII)")
        self.mbButton.connect("clicked", self.toggle, (self.gshell.mbs, MemoryView))

        # Memory DWORD view
        self.mdButton = gtk.Button("Memory (DWORD)")
        self.mdButton.connect("clicked", self.toggle, (self.gshell.mds, MemoryDwordView))

        # Regs view
        self.rButton = gtk.Button("Regs View")
        self.rButton.connect("clicked", self.toggle, (self.gshell.rs, RegistersView))

        # Code view
        self.cButton = gtk.Button("Code View")
        self.cButton.connect("clicked", self.toggle, (self.gshell.cs, CodeView))

        # Process view
        self.pButton = gtk.Button("Process View")
        self.pButton.connect("clicked", self.toggle, (self.gshell.ps, ProcessView))

        # TProbe view
        self.hButton = gtk.Button("TProbe Shell")
        self.hButton.connect("clicked", self.toggle, (self.gshell.hs, TProbeShell))

        # About view
        self.aButton = gtk.Button("About TProbe")
        self.aButton.connect("clicked", self.toggle, (self.gshell.as_, AboutView))

        # Patrons view
        self.ptButton = gtk.Button("Patrons")
        self.ptButton.connect("clicked", self.toggle, (self.gshell.pts, PatronsView))

        self.quitButton = gtk.Button("Exit GShell")
        self.quitButton.connect("clicked", self.quit)

        self.vbox = gtk.VBox(False, 0)
        self.vbox.pack_start(self.mbButton, True, True, 0)
        self.vbox.pack_start(self.mdButton, True, True, 0)
        self.vbox.pack_start(self.rButton, True, True, 0)
        self.vbox.pack_start(self.cButton, True, True, 0)
        self.vbox.pack_start(self.pButton, True, True, 0)
        self.vbox.pack_start(self.hButton, True, True, 0)
        self.vbox.pack_start(self.aButton, True, True, 0)
        self.vbox.pack_start(self.ptButton, True, True, 0)
        self.vbox.pack_start(self.quitButton, True, True, 0)

        self.window.add(self.vbox)
        self.window.show_all()

    def quit(self, widget, data=None):
        for window_list in self.gshell.available:
            for window in window_list:
                window.window.destroy()
        
        self.window.destroy()

        gtk.main_quit()
        return True

    def toggle(self, widget, data):
#        if(target.get_visible()):
#            target.hide()
#        else:
#            target.show()
        (cat, window) = data
        cat.append(window(self.gshell))
        return True

class GConsole(tprobe.AbstractTProbePlugin):
    name = 'gshell'
    w32gshell_list = ['WinXPSP2x86', 'WinXPSP3x86', 'VistaSP0x86', 'VistaSP1x86', 'Win7SP0x86', 'Win7SP1x86']


    def after_validation(self):
        frame = inspect.currentframe()

        self.namespace = frame.f_globals.copy()
        self.namespace.update(frame.f_locals)
        self.namespace.update(self.functions.dict)


    def calculate(self, core = None):
        if self.core.config.opts['profile'] in self.w32gshell_list:
            self.namespace['w32gshell']()
        else:
            print("Graphic shell not implemented for selected profile. \nPlease check for newest version.")

    def render_text(self, shell):
        pass
        

class GtkConsole(tprobe.AbstractTProbePlugin):
    name = 'w32gshell'

    def after_validation(self):
#        pass
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
        namespace.update(self.functions.dict)

#        self.core = core
        self.console = GdbConsole(namespace)
        self.console.shell = self
        self.core.current_context = self.functions.get_context()
        self.core.reading_context = self.core.current_context

        self.clipboard = gtk.Clipboard()

#        self.bp_index = BptIndex()

    def log(self, text):
        if(len(self.hs) > 0):
            txtBuf = self.hs[0].textBuffer
            txtBuf.insert(txtBuf.get_end_iter(), text+"\n")

    def calculate(self, core = None):
#        self.addrspace = self.core.addrspace
#        self.core = core
#        self.console = GdbConsole(self.namespace)
#        self.console.shell = self
        return self

    def refresh(self, component=None, category=None):
        self.core.functions.update_context.calculate()
        if(component != None):
            component.refresh()
        if(category != None):
            for component in category:
                component.refresh()
        else:
            for category in self.refreshable:
                for component in category:
                    component.refresh()

    def render_text(self, shell):
        self.settings = gtk.Settings.get_default()
        self.settings.set_string_property("gtk-font-name", "Courier 8", "")

        mb = MemoryView(self)
        md = MemoryDwordView(self)
        r = RegistersView(self)
        c = CodeView(self)
        p = ProcessView(self)
        h = TProbeShell(self)

        self.mbs = [mb]
        self.mds = [md]
        self.rs = [r]
        self.cs = [c]
        self.ps = [p]
        self.hs = [h]
        self.as_ = []
        self.pts = []

        self.available = [self.mbs, self.mds, self.rs, self.cs, self.ps, self.hs, self.as_, self.pts]
        self.refreshable = [self.mbs,self.mds, self.rs, self.cs, self.ps]
        
        self.m = Main(self)

        #from pudb.remote import set_trace
        #set_trace(term_size=(160, 60))

        gtk.main()

        return False
