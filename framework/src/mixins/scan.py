import threading
import scapy
import argparse
import nmap
import ipaddress
import netifaces
import os
import scapy.all as scapy
from tinydb import TinyDB, Query
from shodan import Shodan
from cmd2 import with_argparser, with_category
from prettytable import PrettyTable

from framework.src.interfaces import InterfaceMixin
from framework.utils import waiting_animation, set_done, nmap_shodan_data_merger
from framework.utils.constants import SHODAN_API_KEY_SERVICE


class NetworkScannerMixin(InterfaceMixin):
    """Mixin Class to scan the network"""

    def __init__(self):
        super().__init__()
        self.db = TinyDB('./framework/database/db.json')
        self.args = None

    scans_parser = argparse.ArgumentParser(
        description="Scan the network for active hosts and inspect mqtt common ports")
    scans_parser.add_argument('-c', '--cached', help='select the results of the last network scan performed',
                              action="store_true")
    scans_parser.add_argument('--verbose', help='increase output verbosity',
                              action="store_true")
    scans_parser.add_argument('-os', '--os_scan', help='display os details of targets',
                              action="store_true")
    scans_parser.add_argument('-a', '--auto',
                              help='automatic scanning of the local network, the framework will find automatically '
                                   'the possible hosts running mqtt and display the results',
                              action="store_true")
    scans_parser.add_argument('-t', '--target',
                              help='run a scan on the specified target, one host\' ip address either a list in cidr '
                                   'notation')

    @with_category(InterfaceMixin.CMD_CAT_BROKER_OP)
    @with_argparser(scans_parser)
    def do_scan(self, args):
        self.args = args
        shodan = Shodan(SHODAN_API_KEY_SERVICE)

        # Retrieve old scans from db
        if args.cached:
            self.handle_cache()

        # Target ip scan
        elif args.target is not None:
            target = args.target.strip()
            # LAN scan
            self.print_ok("Started scanning with Nmap\n Target: " + target)
            # Showing waiting animation
            set_done(False)
            if not args.verbose:
                t = threading.Thread(target=waiting_animation)
                t.start()
            res_nmap = self.host_scan(target)
            set_done(True)
            self.print_verbose(res_nmap, args)
            print('\n')
            self.print_ok("Nmap scanning executed")
            # Shodan scan
            self.print_ok("Started crawling with Shodan\n Target: " + target)
            try:
                res_shodan = shodan.host(target)
                self.print_verbose(res_shodan, args)
            except Exception as e:
                self.print_error("Shodan error: " + str(e))
            self.print_ok("Finished Shodan scanning")

            # Save target object
            self.print_verbose(nmap_shodan_data_merger(target, res_nmap, res_shodan), args)
            self.db.insert(nmap_shodan_data_merger(target, res_nmap, res_shodan))
            self.print_ok("Results added to database")
            # Show target details
            # self.show_clients(self.hosts)

        # Auto LAN scan
        elif args.auto:
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
            scanned_h = []
            # Showing waiting animation
            set_done(False)
            if not args.verbose:
                t = threading.Thread(target=waiting_animation)
                t.start()
            for elem in hlist:
                r = self.host_scan(elem)
                if r is not None:
                    scanned_h.append(r)
            set_done(True)
            print('\n')
            self.print_ok("Port scanning executed")

            # Save hosts data
            # TODO: Filter data
            for h in scanned_h:
                self.db.insert(h)

            # Showing result formatted
            self.show_clients(scanned_h)

    def show_clients(self, hosts):
        try:
            chosen_h = {}
            interacting = True

            self.show_hosts_table(hosts)

            while interacting:
                self.print_question('Choose host number to investigate its details, type \\q to quit')
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
                # Show port and os tables
                self.show_ports_table(chosen_h)
                if self.args.os_scan:
                    self.show_os_table(chosen_h)
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
            self.print_ok("Available devices in the network with at least one open port:")

            i = 0
            for client in hosts:
                ipaddr = []

                # implementing a list, an host can have multiple ips
                for key in client['scan']:
                    ipaddr.append(key)

                inner_dict = client['scan'][str(ipaddr[0])]
                ports = inner_dict['tcp']
                open_ports = []
                # shows open ports only
                for p in ports:
                    if ports[p]['state'] != 'closed':
                        open_ports.append(p)
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
                'Port number', 'State', 'Reason', 'Name', 'Product', 'Version', 'Extrainfo', 'Scripts'
            ])

            self.print_ok("Ports for the selected host:")
            ipaddr = []

            # implementing a list, an host can have multiple ips
            for key in host['scan']:
                ipaddr.append(key)

            ports = host['scan'][str(ipaddr[0])]['tcp']

            for key in ports:
                try:
                    scripts = ports[key]['script']
                except Exception as e:
                    scripts = ''

                port_table.add_row([
                    key,
                    ports[key]['state'],
                    ports[key]['reason'],
                    ports[key]['name'],
                    ports[key]['product'],
                    ports[key]['version'],
                    ports[key]['extrainfo'],
                    scripts
                ])

            self.ppaged(msg=str(port_table))
        except Exception as e:
            self.print_error("show_ports_table error: " + e.__str__())

    def show_os_table(self, host):
        try:
            port_table = PrettyTable(field_names=[
                'Name', 'Accuracy', 'Type list', 'Cpe list'
            ])

            self.print_ok("OS details:")
            ipaddr = []

            # implementing a list, an host can have multiple ips
            for key in host['scan']:
                ipaddr.append(key)

            os_array = host['scan'][str(ipaddr[0])]['osmatch']

            for elem in os_array:
                try:
                    type_list = []
                    for obj in elem['osclass']:
                        type_list.append(obj['type'])
                except Exception as e:
                    type_list = 'Error: ' + str(e)

                try:
                    cpe_list = []
                    for obj in elem['osclass']:
                        cpe_list.append(obj['cpe'])
                except Exception as e:
                    cpe_list = 'Error: ' + str(e)

                port_table.add_row([
                    elem['name'],
                    elem['accuracy'],
                    type_list,
                    cpe_list
                ])

            self.ppaged(msg=str(port_table))
        except Exception as e:
            self.print_error("show_ports_table error: " + e.__str__())

    def host_scan(self, host):
        # TODO: Add error handling for not valid host
        try:
            self.print_verbose(str(host), self.args)
            nm = nmap.PortScanner()
            arg = '-sV -A -p T:1883,8883 --reason'
            res = nm.scan(hosts=str(host), arguments=arg)
            self.print_verbose(res, self.args)
            active_p = []
            port_list = res['scan'][str(host)]['tcp']
            # Excludes closed ports
            for key in port_list:
                self.print_verbose(str(key) + ': ' + str(port_list[key]), self.args)
                if port_list[key]['state'] != 'closed':
                    active_p.append({key: port_list[key]})
            self.print_verbose(str(len(active_p)) + ' - ' + str(active_p), self.args)
            # Returns host if it has at least one open port
            if len(active_p) != 0:
                return res
            else:
                return None

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

        answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=10, verbose=False)[0]
        self.print_verbose(answered_list, self.args)
        result = []
        for i in range(0, len(answered_list)):
            result.append(answered_list[i][1].psrc)

        self.print_info(f'Up hosts resolved\n Number of up hosts: {len(result)}')
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
