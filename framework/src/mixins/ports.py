from cmd2 import with_argparser, with_category
import argparse

from nmap import nmap
from prettytable import PrettyTable

from framework.src.interfaces import InterfaceMixin


class PortScannerMixin(InterfaceMixin):
    """Mixin Class to scan the ports of a target"""

    def __init__(self):
        super().__init__()

    port_parser = argparse.ArgumentParser(description="Discover open ports of a specified device")
    port_parser.add_argument('-i', '--ip', help='select a specific target by ip address')

    @with_category(InterfaceMixin.CMD_CAT_BROKER_OP)
    @with_argparser(port_parser)
    def do_scan(self, args):
        l_ports = self.connect_scan(args.id)
        self.show_results(l_ports)

    def show_results(self, ports):

        scans_table = PrettyTable(field_names=[
            'IP Address', 'Port', 'State', 'Reason', 'Name', 'Product'
        ])

        # print clients
        print("Available ports:")
        for port in ports:
            scans_table.add_row(port)

        self.ppaged(msg=str(scans_table))

    def connect_scan(self, target):
        # take the range of ports to
        # be scanned
        begin = 79
        end = 80

        # instantiate a PortScanner object
        scanner = nmap.PortScanner()

        ans = []

        for i in range(begin, end + 1):
            # scan the target port
            res = scanner.scan(target, str(i))

            port = res['scan'][target]['tcp'][i]

            ans = [port['state'], port['reason'], port['name'], port['product']]

        return ans

    def stealth_scan(self):
        pass

    def xmas_scan(self):
        pass

    def tcp_ack_scan(self):
        pass
