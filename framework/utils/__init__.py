import time
from datetime import datetime
import sys
import itertools
from .data_handler import *


def banner():
    """The banner we want to display"""

    return ("""
    MQTT-Framework
    """) + f"""
        {"MQTT-Framework Security testing"}
    """


def get_prompt(cli):
    """Handles the prompt line with colors"""
    client = cli.mqtt_client
    end_prompt = ">> "
    parts = []

    if client:
        client_part = client.host + ':' + str(client.port)
        parts.append(client_part)

    if cli.current_victim:
        victim_part = f"[Victim #{cli.current_victim.id}]"
        parts.append(victim_part)

    if cli.current_scan:
        scan_part = f"[Scan #{cli.current_scan.id}]"
        parts.append(scan_part)

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
