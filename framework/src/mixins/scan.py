import scapy
from cmd2 import with_argparser, with_category
from prettytable import PrettyTable
import argparse
import nmap
import ipaddress
import netifaces
import os
import scapy.all as scapy

from framework.src.interfaces import InterfaceMixin


class NetworkScannerMixin(InterfaceMixin):
    """Mixin Class to scan the network"""

    def __init__(self):
        # list of clients in the network
        super().__init__()
        self.clients = []

    scans_parser = argparse.ArgumentParser(description="Scan the network for ip addresses")
    scans_parser.add_argument('-c', '--cached', help='select the results of the last network scan performed')

    @with_category(InterfaceMixin.CMD_CAT_BROKER_OP)
    @with_argparser(scans_parser)
    def do_scan(self, args):
        if args.cached:
            self.handle_cache()
        else:
            # Gets client net specs
            netdata = self.get_client_netdata()
            # Resolving ipaddress in CIDR notation
            hosts = ipaddress.ip_network(
                netdata[0] + '/' +
                netdata[1], strict=False)
            print(hosts)
            # hlist = self.get_host_list(netdata[0], netdata[1])
            # ARP requests to find up hosts
            hlist = self.resolve_up_hosts(str(hosts))
            # Scanning each hosts ports
            self.print_info("Port scanning started")
            for elem in hlist:
                self.host_scan(elem)

            self.print_ok("Port scanning executed")
            print(self.clients)

    def show_clients(self):

        scans_table = PrettyTable(field_names=[
            'IP Address', 'MAC Address'
        ])

        # print clients
        print("Available devices in the network:")
        for client in self.clients:
            scans_table.add_row([client['ip'], client['mac']])

        self.ppaged(msg=str(scans_table))

    def host_scan(self, host):
        # TODO: Add saving result from file
        try:
            nm = nmap.PortScanner()
            arg = '-sV -p T:1883,443,8883,80'
            res = nm.scan(hosts=str(host), arguments=arg)
            print(res)
            active_p = []
            port_list = res['scan'][str(host)]['tcp']
            for key in port_list:
                if port_list[key] != 'closed':
                    print(port_list[key])
                    active_p.append({key: port_list[key]})
            if len(active_p) != 0:
                self.clients.append(res)
            """
            for sent, received in result:
                # for each response, append ip and mac address to `clients` list
                self.clients.append({'ip': received.psrc, 'mac': received.hwsrc})
            """
            # self.show_clients()

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

            while True:
                iface_num = input("[!] Choose the device number: ")
                try:
                    var = list[int(iface_num)]
                    break
                except Exception as e:
                    self.print_error("Choose an existing number")

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

    def get_host_list(self, local_ip, netmask):
        try:
            self.print_info(f"Computing possible")

            # Generating CIDR notation
            cidr = ipaddress.ip_network(local_ip + '/' + netmask, strict=False)
            net = ipaddress.ip_interface(cidr).network
            host_list = []
            for x in net:
                host_list.append(x)

            self.print_ok(f"Finished computing")
            return host_list
        except Exception as e:
            self.print_error(f"get_lan_list: " + e.__str__())

    def resolve_up_hosts(self, ip):
        self.print_info(f'Resolving up hosts')
        arp_req_frame = scapy.ARP(pdst=ip)

        broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

        answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
        print(answered_list)
        result = []
        for i in range(0, len(answered_list)):
            result.append(answered_list[i][1].psrc)

        self.print_info(f'Up hosts resolved')
        return result

    def win_show_ifaces(self, ifaces):
        try:

            scans_table = PrettyTable(field_names=[
                '#', 'Name', 'IP Address', 'MAC Address', 'Description'
            ])

            self.print_ok(f"Network interfaces on your device:")

            i = 0
            for iface in ifaces:
                scans_table.add_row([i, iface['name'], iface['ips'][1], iface['mac'], iface['description']])
                i += 1

            self.ppaged(msg=str(scans_table))
        except Exception as e:
            self.print_error(f"win_show_ifaces: " + e.__str__())

    def gen_show_ifaces(self, ifaces):
        try:

            scans_table = PrettyTable(field_names=[
                '#', 'Identifiers'
            ])

            self.print_ok(f"Network interfaces on your device:")

            i = 0
            for iface in ifaces:
                scans_table.add_row([i, iface])
                i += 1

            self.ppaged(msg=str(scans_table))
        except Exception as e:
            self.print_error(f"win_show_ifaces: " + e.__str__())
