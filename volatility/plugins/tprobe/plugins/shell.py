import volatility.plugins.tprobe.core as tprobe
import code, inspect
from gdb import execute
import curses, struct, fcntl, termios
import sys

class GdbConsole(code.InteractiveConsole): 

    def runsource(self, source, filename="<input>", symbol="single"):
        self.stdout = sys.stdout
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
        sys.stdout = self.stdout
        return False


class InteractiveShell(tprobe.AbstractTProbePlugin):
    after_validation_priority = 100
    name = 'shell'
    dependencies = []

    def after_validation(self):
        self.functions.dict.pop(self.name)

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

        console = GdbConsole(namespace)
        console.shell = self

        if readfunc is not None:
            console.raw_input = readfunc
        else:
            try:
                import readline
            except ImportError:
                pass

        import tprobe
        if hasattr(tprobe, 'directly_to_gshell'):
            if(tprobe.directly_to_gshell):
                namespace['gshell']()
        else:
            console.interact("Welcome in TProbe shell plugin.")

