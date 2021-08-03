import os
import netifaces
import scapy.all as scapy
from prettytable import PrettyTable


def get_client_netdata(self):
    try:
        # Checks interfaces based on os (netifaces returns interfaces ids on windows)
        if os.name == 'nt':
            list = scapy.get_windows_if_list()
            win_show_ifaces(self, list)
        else:
            list = netifaces.interfaces()
            gen_show_ifaces(self, list)

        self.print_question(f'Choose the device number, type \\q to quit')
        while True:
            iface_num = input(f"Input: ")
            try:
                if iface_num == '\\q':
                    return "quit"
                var = list[int(iface_num)]
                break
            except Exception as e:
                self.print_error("Invalid input")

        return [list, iface_num]
    except Exception as e:
        self.print_error(f"get_client_netdata: " + e.__str__())


def win_show_ifaces(self, ifaces):
    try:
        ifaces_table = PrettyTable(field_names=[
            '#', 'Name', 'IP Address', 'MAC Address', 'Description'
        ])

        self.print_ok(f"Network interfaces on your device:")

        i = 0
        for iface in ifaces:
            ifaces_table.add_row(
                [i, iface.get('name'), iface.get('ips')[1], iface.get('mac'), iface.get('description')])
            i += 1

        self.ppaged(msg=str(ifaces_table))
    except Exception as e:
        self.print_error(f"win_show_ifaces: " + e.__str__())


def gen_show_ifaces(self, ifaces):
    try:

        ifaces_table = PrettyTable(field_names=[
            '#', 'Identifiers'
        ])

        self.print_ok(f"Network interfaces on your device:")

        i = 0
        for iface in ifaces:
            ifaces_table.add_row([i, iface])
            i += 1

        self.ppaged(msg=str(ifaces_table))
    except Exception as e:
        self.print_error(f"win_show_ifaces: " + e.__str__())


def extract_net_addresses(list, iface_num):
    iface = extract_iface_id(list, iface_num)
    addrs = netifaces.ifaddresses(iface)

    ip_address = addrs[netifaces.AF_INET][0]['addr']
    netmask = addrs[netifaces.AF_INET][0]['netmask']

    return [ip_address, netmask]


def extract_iface_id(list, iface_num):
    if os.name == 'nt':
        return list[int(iface_num)]['guid']
    else:
        return list[int(iface_num)]
