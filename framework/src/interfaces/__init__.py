from cmd2 import Cmd, categorize
from blessed import Terminal

from framework.utils import get_prompt, banner
from framework import config


class InterfaceMixin(Cmd):
    """Interface for Command Line Mixin"""

    prompt = '>> '
    ruler = '-'
    intro = banner()

    CMD_CAT_BROKER_OP = 'Broker Related Operations'
    CMD_CAT_VICTIM_OP = 'Victim Related Operations'
    CMD_CAT_GENERAL = 'General Commands'

    variables_choices = ['victim', 'scan']

    def __init__(self):
        """The class initializer"""

        Cmd.__init__(self, startup_script=config.STARTUP_SCRIPT)

        self.aliases.update({'exit': 'quit'})
        self.hidden_commands.extend(['load', 'pyscript', 'set', 'shortcuts', 'alias', 'unalias', 'py'])

        self.current_targets = []

        self.base_prompt = get_prompt(self)
        self.cl = Terminal()
        self.prompt = self.base_prompt

        categorize((
            InterfaceMixin.do_help,
            InterfaceMixin.do_history,
            InterfaceMixin.do_quit,
            InterfaceMixin.do_shell,
        ), InterfaceMixin.CMD_CAT_GENERAL)

    def print_error(self, text, end='\n', start=''):
        """Prints an error message with colors"""

        self.poutput(start + self.cl.blink_bold_red('[!]') + ' ' + self.cl.red(text), end=end)

    def print_info(self, text, end='\n', start=''):
        """Prints an information message with colors"""

        self.poutput(start + self.cl.bold_blue('[i]') + ' ' + self.cl.blue(text), end=end)

    def print_ok(self, text, end='\n', start=''):
        """Prints a successful message with colors"""

        self.poutput(start + self.cl.bold_green('[+]') + ' ' + self.cl.green(text), end=end)

    def print_verbose(self, text, args, end='\n', start=''):
        """Prints verbose message with colors if verbose flag is true"""
        if args.verbose:
            self.poutput(start + self.cl.bold_darkorange4('[**]') + ' ' + self.cl.darkorange4(str(text)), end=end)

    def print_question(self, text, end='\n', start=''):
        """Prints a question message with colors"""

        self.poutput(start + self.cl.blink_bold_yellow('[?]') + ' ' + self.cl.yellow(text), end=end)


class InterfaceCLI:
    pass
