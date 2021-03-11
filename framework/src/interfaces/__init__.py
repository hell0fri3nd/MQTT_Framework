from cmd2 import Cmd, categorize

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

        self.current_victim = None
        self.mqtt_client = None
        self.current_scan = None

        self.base_prompt = get_prompt(self)
        self.prompt = self.base_prompt

        categorize((
            InterfaceMixin.do_edit,
            InterfaceMixin.do_help,
            InterfaceMixin.do_history,
            InterfaceMixin.do_quit,
            InterfaceMixin.do_shell,
        ), InterfaceMixin.CMD_CAT_GENERAL)

    def print_error(self, text, end='\n', start=''):
        """Prints an error message with colors"""

        self.poutput(start + '[-]' + ' ' + text, end=end)

    def print_info(self, text, end='\n', start=''):
        """Prints an information message with colors"""

        self.poutput(start + '[!]' + ' ' + text, end=end)

    def print_ok(self, text, end='\n', start=''):
        """Prints a successful message with colors"""

        self.poutput(start + '[+]' + ' ' + text, end=end)

    def print_pairs(self, title, body):
        """Prints a message that contains pairs for data"""

        self.poutput(title)

        for key, value in body.items():
            k = key + ':'
            self.poutput(f' - {k} {value}')

    def update_prompt(self):
        """Updates the command prompt"""

        self.prompt = get_prompt(self)


class InterfaceCLI:
    pass
