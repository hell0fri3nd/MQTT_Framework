from datetime import datetime


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
