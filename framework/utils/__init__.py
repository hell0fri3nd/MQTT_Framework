import time
from datetime import datetime
import sys
import itertools
from .data_handler import *
from .interface_handlers import *


def banner():
    """The banner we want to display"""

    return ("""
    
███╗   ███╗ ██████╗ ████████╗████████╗    ████████╗███████╗███████╗████████╗███████╗██████╗ 
████╗ ████║██╔═══██╗╚══██╔══╝╚══██╔══╝    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██╔████╔██║██║   ██║   ██║      ██║          ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
██║╚██╔╝██║██║▄▄ ██║   ██║      ██║          ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
██║ ╚═╝ ██║╚██████╔╝   ██║      ██║          ██║   ███████╗███████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝ ╚══▀▀═╝    ╚═╝      ╚═╝          ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝


    """) + f"""
        {"Customizable framework for IoT devices implementing MQTT"}
    """


def get_prompt(cli):
    """Handles the prompt line with colors"""
    end_prompt = ">> "
    parts = []

    not_empty_parts = [p for p in parts if p]

    if len(not_empty_parts) == 0:
        return end_prompt

    return ' '.join(not_empty_parts) + ' ' + end_prompt


def now():
    """Returns the current time in iso format"""
    return datetime.now().isoformat()


done_loading = False


def waiting_animation():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done_loading:
            break
        sys.stdout.write('\r[' + c + '] .. loading .. [' + c + ']')
        sys.stdout.flush()
        time.sleep(0.1)


def set_done(d):
    global done_loading
    done_loading = d
