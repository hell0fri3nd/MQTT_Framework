import scapy
from cmd2 import with_argparser, with_category
from prettytable import PrettyTable
import argparse
import nmap
import ipaddress
import netifaces
import os
import scapy.all as scapy
from tinydb import TinyDB, Query

from framework.src.interfaces import InterfaceMixin


class NetworkScannerMixin(InterfaceMixin):
    """Mixin Class to scan the network"""

    def __init__(self):
        super().__init__()
        self.hosts = []
        self.db = TinyDB('./framework/database/db.json')
        self.args = None

    scans_parser = argparse.ArgumentParser(
        description="Scan the network for active hosts and inspect mqtt common ports")
    scans_parser.add_argument('-c', '--cached', help='select the results of the last network scan performed',
                              action="store_true")
    scans_parser.add_argument('--verbose', help='increase output verbosity',
                              action="store_true")

    @with_category(InterfaceMixin.CMD_CAT_BROKER_OP)
    @with_argparser(scans_parser)
    def do_scan(self, args):
        self.hosts = []
        self.args = args

        if args.cached:
            self.handle_cache()
        else:
            # Gets client net specs
            netdata = self.get_client_netdata()
            # Stops execution at user's request
            if netdata == "quit":
                return

            # Resolving ipaddress in CIDR notation
            ipaddr_cidr = ipaddress.ip_network(
                netdata[0] + '/' +
                netdata[1], strict=False)
            self.print_verbose(ipaddr_cidr, args)

            # ARP requests to find up hosts
            hlist = self.resolve_up_hosts(str(ipaddr_cidr))

            # Scanning each hosts ports
            self.print_info("Port scanning started")
            for elem in hlist:
                self.host_scan(elem)

            self.print_ok("Port scanning executed")

            # Save hosts data
            for h in self.hosts:
                self.db.insert(h)

            # Showing result formatted
            self.show_clients(self.hosts)

    def show_clients(self, hosts):
        try:
            chosen_h = {}
            interacting = True

            self.show_hosts_table(hosts)

            while interacting:
                self.print_question('Choose host number to investigate its ports, type \\q to quit')
                # Select the wanted host
                while True:
                    ans = input(f"Input: ")
                    try:
                        if ans == '\\q':
                            interacting = False
                            self.print_ok(f"Exited from network scanner\n")
                            break
                        chosen_h = hosts[int(ans)]
                        break
                    except Exception as e:
                        self.print_error("Invalid input")
                # Cheking if users wants to quit
                if not interacting:
                    break
                # Show port tables
                self.show_ports_table(chosen_h)
                # Setting target
                self.print_question(f"Type \\y if you want to add the host to the target list")
                ans = input(f"Input: ")
                if ans == '\\y':
                    self.current_targets.append(chosen_h)
                    self.print_ok(f"Target added to list")
                else:
                    self.print_ok(f"Host discarded")

        except Exception as e:
            self.print_error("show_clients error: " + e.__str__())

    def show_hosts_table(self, hosts):
        try:
            scans_table = PrettyTable(field_names=[
                '#', 'IP Address', 'MAC Address', 'Possible Open Ports', 'Name'
            ])

            # print hosts
            self.print_ok("Available devices in the network:")

            i = 0
            for client in hosts:
                ipaddr = []

                # implementing a list, an host can have multiple ips
                for key in client['scan']:
                    ipaddr.append(key)

                inner_dict = client['scan'][str(ipaddr[0])]
                open_ports = [p for p in inner_dict['tcp']]
                try:
                    mac_addr = inner_dict['addresses']['mac']
                except Exception:
                    mac_addr = 'x'

                scans_table.add_row([
                    i,
                    ipaddr[0],
                    mac_addr,
                    open_ports,
                    inner_dict['hostnames'][0]['name']
                ])
                i += 1

            self.ppaged(msg=str(scans_table))

        except Exception as e:
            self.print_error("show_hosts_table error: " + e.__str__())

    def show_ports_table(self, host):
        try:
            port_table = PrettyTable(field_names=[
                'Port number', 'State', 'Reason', 'Name', 'Product', 'Version', 'Extrainfo',
            ])

            self.print_ok("Ports for the selected host:")
            ipaddr = []

            # implementing a list, an host can have multiple ips
            for key in host['scan']:
                ipaddr.append(key)

            ports = host['scan'][str(ipaddr[0])]['tcp']

            for key in ports:
                port_table.add_row([
                    key,
                    ports[key]['state'],
                    ports[key]['reason'],
                    ports[key]['name'],
                    ports[key]['product'],
                    ports[key]['version'],
                    ports[key]['extrainfo']
                ])

            self.ppaged(msg=str(port_table))
        except Exception as e:
            self.print_error("show_ports_table error: " + e.__str__())

    def host_scan(self, host):
        try:
            nm = nmap.PortScanner()
            arg = '-sV -p T:1883,8883'
            res = nm.scan(hosts=str(host), arguments=arg)
            self.print_verbose(res, self.args)
            active_p = []
            port_list = res['scan'][str(host)]['tcp']
            # Excludes closed ports
            for key in port_list:
                self.print_verbose(str(key) + ': ' + str(port_list[key]), self.args)
                if port_list[key] != 'closed':
                    active_p.append({key: port_list[key]})
            if len(active_p) != 0:
                self.hosts.append(res)

        except Exception as e:
            self.print_error("host_scan error: " + e.__str__())

    def handle_cache(self):
        # TODO: Add retrival from file
        pass

    def get_client_netdata(self):
        try:
            # Checks interfaces based on os (netifaces returns interfaces ids on windows)
            if os.name == 'nt':
                list = scapy.get_windows_if_list()
                self.win_show_ifaces(list)
            else:
                list = netifaces.interfaces()
                self.gen_show_ifaces(list)

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

            self.print_info(f"Retrieving IP Address & Netmask")
            if os.name == 'nt':
                iface = list[int(iface_num)]['guid']
            else:
                iface = list[int(iface_num)]

            addrs = netifaces.ifaddresses(iface)

            ip_address = addrs[netifaces.AF_INET][0]['addr']
            netmask = addrs[netifaces.AF_INET][0]['netmask']

            self.print_ok(f"Network data found\n IP: {ip_address}\n Netmask: {netmask}")

            return [ip_address, netmask]
        except Exception as e:
            self.print_error(f"get_client_netdata: " + e.__str__())

    def resolve_up_hosts(self, ip):
        self.print_info(f'Resolving up hosts')
        arp_req_frame = scapy.ARP(pdst=ip)

        broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

        answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
        self.print_verbose(answered_list, self.args)
        result = []
        for i in range(0, len(answered_list)):
            result.append(answered_list[i][1].psrc)

        self.print_info(f'Up hosts resolved')
        return result

    def win_show_ifaces(self, ifaces):
        try:

            ifaces_table = PrettyTable(field_names=[
                '#', 'Name', 'IP Address', 'MAC Address', 'Description'
            ])

            self.print_ok(f"Network interfaces on your device:")

            i = 0
            for iface in ifaces:
                ifaces_table.add_row([i, iface['name'], iface['ips'][1], iface['mac'], iface['description']])
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
