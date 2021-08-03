import threading
import argparse
import nmap
import ipaddress
import scapy.all as scapy
from tinydb import TinyDB, Query
from shodan import Shodan
from cmd2 import with_argparser, with_category
from prettytable import PrettyTable

from framework.src.interfaces import InterfaceMixin
from framework.utils import waiting_animation, set_done, nmap_shodan_data_merger, nmap_data_parser, get_client_netdata, \
    extract_net_addresses
from framework.utils.constants import SHODAN_API_KEY_SERVICE


class NetworkScannerMixin(InterfaceMixin):
    """Mixin Class to scan the network"""

    def __init__(self):
        super().__init__()
        self.db = TinyDB('./framework/database/targets.json')
        self.args = None

    scans_parser = argparse.ArgumentParser(
        description="Scan the network for active hosts and inspect mqtt common ports")
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

        # If no target specified it runs auto scan
        if args.target is None:
            args.auto = True
            self.print_info('Target not supplied, switching to automatic scanning')

        # Target ip scan
        if args.target is not None:
            target = args.target.strip()
            # LAN scan
            self.print_ok("Started scanning with Nmap\n Target: " + target)
            # Showing waiting animation
            set_done(False)
            if not args.verbose:
                t = threading.Thread(target=waiting_animation)
                t.start()

            try:
                res_nmap = self.host_scan(target)
            except Exception as e:
                self.print_error("host_scan error: " + e.__str__())

            set_done(True)
            self.print_verbose(res_nmap, args)
            print('\n')
            self.print_ok("Nmap scanning executed")
            # Shodan scan
            self.print_ok("Started analyzing with Shodan\n Target: " + target)
            set_done(False)
            if not args.verbose:
                t = threading.Thread(target=waiting_animation)
                t.start()
            res_shodan = None
            try:
                res_shodan = shodan.host(target)
                self.print_verbose(res_shodan, args)
            except Exception as e:
                self.print_error("Shodan error: " + str(e))
                res_shodan = None
            set_done(True)
            print('\n')
            self.print_ok("Finished Shodan scanning")
            # Save target object
            res = {}
            if res_shodan is not None:
                res = nmap_shodan_data_merger(target, res_nmap, res_shodan)
                self.print_verbose(res, args)
                self.db.insert(res)
            else:
                res = nmap_data_parser(res_nmap)
                self.print_verbose(res, args)
                self.db.insert(res)
            self.print_ok("Results added to database")
            # Show target details
            self.show_target_ports_det(res)

        # Auto LAN scan
        elif args.auto:
            # Gets client net interface specs
            interface_data = get_client_netdata(self)
            # Stops execution at user's request
            if interface_data == "quit":
                self.print_ok(f"Quitted from scan\n")
                return
            # Gets client net data
            netdata = extract_net_addresses(interface_data[0], interface_data[1])
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
            # Showing result formatted
            self.show_clients(scanned_h, args)

    def show_clients(self, hosts, args):
        try:
            chosen_h = {}
            interacting = True

            self.show_hosts_table(hosts)

            while interacting:
                self.print_question('Choose host number to investigate its details, type \\q to quit')
                # Select the wanted host based by number
                while True:
                    ans = input(f"Input: ")
                    try:
                        if ans == '\\q':
                            interacting = False
                            self.print_ok(f"Quitted from scan\n")
                            break
                        # Parsing the chosen host
                        chosen_h = nmap_data_parser(hosts[int(ans)])
                        self.print_verbose(chosen_h, args)
                        break
                    except Exception as e:
                        self.print_error("Invalid input")
                        self.print_verbose(e, args)
                # Cheking if users wants to quit
                if not interacting:
                    break
                # Show port tables
                self.show_target_ports_det(chosen_h)
                # Setting target
                self.print_question(
                    f"Type \\y if you want to add the host to the target list, \\s to save it in the database, "
                    f"anything else to quit")
                ans = input(f"Input: ")
                if ans == '\\y':
                    self.current_targets.append(chosen_h)
                    self.print_ok(f"Target added to list")
                elif ans == '\\s':
                    self.db.insert(chosen_h)
                    self.print_ok(f"Target added to database")
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

                scans_table.add_row([
                    i,
                    ipaddr[0],
                    inner_dict['addresses'].get('mac'),
                    open_ports,
                    inner_dict['hostnames'][0].get('name')
                ])
                i += 1

            self.ppaged(msg=str(scans_table))

        except Exception as e:
            self.print_error("show_hosts_table error: " + e.__str__())

    def show_target_ports_det(self, host):
        try:
            port_table1 = PrettyTable(field_names=[
                '#', 'Port number', 'State', 'Reason', 'Name'
            ])

            self.print_ok("Ports for the selected host:")

            ports = host.get('mqtt_ports')

            i = 0
            for key in ports:
                port_table1.add_row([
                    i,
                    key.get('port'),
                    key.get('state'),
                    key.get('reason'),
                    key.get('name'),
                ])
                i += 1

            self.ppaged(msg=str(port_table1))

            self.print_info("Details found: \n" +
                            "Nmap command used: " + host.get('nmap_command') +
                            "\nHostname: " + str(host.get('hostnames')[0].get('name')) +
                            "\nVendor: " + str(host.get('vendor')) +
                            "\nUptime: " + str(host.get('uptime')) +
                            "\nOther open ports: " + str(host.get('ports'))
                            + "\n")
            # Table 2 details
            port_table2 = PrettyTable(field_names=[
                'City', 'Postal Code', 'Country', 'Organization', 'Last update'
            ])

            if host.get('location') is not None:
                loc = host.get('location')
                port_table2.add_row([
                    loc.get('city'),
                    loc.get('postal_code'),
                    loc.get('country_name'),
                    loc.get('org'),
                    loc.get('last_update')
                ])
                self.ppaged(msg=str(port_table2))

            # Select the desired port to inspect
            while True:
                self.print_question(f"Select the desired port to inspect it, type \\q to quit: ")
                ans = input(f"Input: ")
                try:
                    if ans == '\\q':
                        break

                    port_table3 = PrettyTable(field_names=[
                        'Topic name', 'Payload'
                    ])
                    msgs = ports[int(ans)].get('messages')
                    if msgs is not None:
                        for key in msgs:
                            port_table3.add_row([
                                key.get('topic'),
                                key.get('payload')
                            ])

                        self.ppaged(msg=str(port_table3))

                    if self.args.os_scan:
                        self.show_os_table(host)

                    self.print_info("Data for port %d: \n" % ports[int(ans)].get('port') +
                                    "MQTT response code: " + str(ports[int(ans)].get('mqtt_code')) +
                                    "\nPort hostnames: " + str(ports[int(ans)].get('additional').get('hostnames')) +
                                    "\nProduct: " + str(ports[int(ans)].get('additional').get('product')) +
                                    "\nVersion: " + str(ports[int(ans)].get('additional').get('version')) +
                                    "\nExtrainfo: " + str(ports[int(ans)].get('additional').get('extrainfo')) + '\n' +
                                    "\nAdditional data: " + str(ports[int(ans)].get('data')) + '\n'
                                    )

                    scripts = ports[int(ans)].get('script')
                    if scripts is not None:
                        self.print_info("Scripts: ")
                        for key in scripts:
                            print(key + ": \n" +
                                  ports[int(ans)].get('script').get(key))
                        print('\n')

                except Exception as e:
                    self.print_error("Invalid input")

        except Exception as e:
            self.print_error("show_target_ports_det error: " + str(e))

    def show_os_table(self, host):
        # TODO: Fix OS table
        try:
            port_table = PrettyTable(field_names=[
                'Name', 'Accuracy', 'Type list', 'Cpe list'
            ])

            self.print_ok("OS details:")

            os_array = host.get('osmatch')

            for elem in os_array:
                type_list = []
                cpe_list = []
                for obj in elem.get('osclass'):
                    type_list.append(obj.get('type'))
                    cpe_list.append(obj.get('cpe'))

                port_table.add_row([
                    elem.get('name'),
                    elem.get('accuracy'),
                    type_list,
                    cpe_list
                ])

            self.ppaged(msg=str(port_table))
        except Exception as e:
            self.print_error("show_os_table error: " + e.__str__())

    def host_scan(self, host):
        self.print_verbose(str(host), self.args)
        nm = nmap.PortScanner()
        arg = '-sV --version-all -A -p T:1883,8883 --reason'
        res = nm.scan(hosts=str(host), arguments=arg)
        self.print_verbose(res, self.args)
        active_p = []
        try:
            port_list = res.get('scan').get(str(host)).get('tcp')
            # Excludes closed ports
            for key in port_list:
                self.print_verbose(str(key) + ': ' + str(port_list.get(key)), self.args)
                if port_list.get(key).get('state') != 'closed':
                    active_p.append({key: port_list[key]})
            self.print_verbose(str(len(active_p)) + ' - ' + str(active_p), self.args)
            # Returns host if it has at least one open port
            if len(active_p) != 0:
                return res
            else:
                return None
        except Exception as e:
            self.print_verbose("Host error: " + str(e), self.args)
            return None

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
