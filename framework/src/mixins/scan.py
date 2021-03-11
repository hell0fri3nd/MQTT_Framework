from cmd2 import with_argparser, with_category
import argparse

from prettytable import PrettyTable
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

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
    def do_net_scan(self, args):
        if args.cached:
            self.handle_cache()
        else:
            self.run_arp_scan()

    def show_clients(self):

        scans_table = PrettyTable(field_names=[
            'IP Address', 'MAC Address'
        ])

        # print clients
        print("Available devices in the network:")
        for client in self.clients:
            scans_table.add_row([client['ip'], client['mac']])

        self.ppaged(msg=str(scans_table))

    def run_arp_scan(self):
        # TODO: Add retrival from file

        target_ip = "192.168.1.1/24"  # IP Address for the destination
        arp = ARP(pdst=target_ip)  # create ARP packet
        # create the Ether broadcast packet
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
        packet = ether / arp  # stack them

        result = srp(packet, timeout=5, verbose=True)[
            0]  # result is list of pairs with format (sent_packet, received_packet)

        for sent, received in result:
            # for each response, append ip and mac address to `clients` list
            self.clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        self.show_clients()

    def handle_cache(self):
        # TODO: Add retrival from file
        pass
