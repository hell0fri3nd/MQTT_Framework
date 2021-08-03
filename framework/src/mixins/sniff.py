import argparse
import asyncio
import ctypes
import threading

import pyshark
from tinydb import TinyDB
from datetime import datetime
from cmd2 import with_argparser, with_category

from framework.src.interfaces import InterfaceMixin
from framework.utils import get_client_netdata, extract_iface_id

conack_pkt_list = []
conn_pkt_list = []


def general_callback(pkt):
    pkt.pretty_print()


class SnifferMixin(InterfaceMixin):
    """Mixin class for the sniffer module"""

    def __init__(self):
        super().__init__()
        self.db = TinyDB('./framework/database/sniffed_pkts.json')
        self.target_db = TinyDB('./framework/database/targets.json')
        self.args = None

    sniffer_parser = argparse.ArgumentParser(
        description="Sniff mqtt packets in the connected local network. When no filter is specified, it automatically "
                    "looks for CONNECT and CONACK packets to find brokers credentials")
    sniffer_parser.add_argument('-t', '--timeout', help='the timeout required to sniff the network')
    sniffer_parser.add_argument('-b', '--broker', help='broker\'s IP address to target its credentials')
    sniffer_parser.add_argument('-f', '--display_filter', help='the display filters  to filter packets')
    sniffer_parser.add_argument('-iflag', '--interface_flag',
                                help='flag to signal if a choice of interfaces is desired', action="store_true")
    sniffer_parser.add_argument('--verbose', help='increase output verbosity',
                                action="store_true")

    @with_category(InterfaceMixin.CMD_CAT_BROKER_OP)
    @with_argparser(sniffer_parser)
    def do_sniff(self, args):
        global conack_pkt_list, conn_pkt_list
        look_for_cred = False
        conack_pkt_list = []
        conn_pkt_list = []

        if args.broker is None and args.display_filter is None:
            args.broker = self.target_db.get(doc_id=len(self.target_db)).get('ip')
            self.print_info(
                'No target-broker specified in credentials lookup mode, retrieving last target inserted in database')

        if args.display_filter is None:
            args.display_filter = 'ip.addr == %s and (mqtt.conflags or (mqtt.conack.val == 0))' % str(args.broker)
            look_for_cred = True
            self.print_info('No filter specified, looking for credentials in CONNECT/CONACK packets')

        if args.timeout is None:
            args.timeout = 60
            self.print_info('No timeout specified, setting timeout to %d seconds' % args.timeout)

        # Let a choice of interface, if not given, takes the first available.
        if args.interface_flag:
            interface_data = get_client_netdata(self)
            self.print_verbose(interface_data, args)
            iface = extract_iface_id(interface_data[0], interface_data[1])
            self.print_verbose(str(iface), args)
            capture = pyshark.LiveCapture(interface=iface, display_filter=args.display_filter)
        else:
            # Takes first available interface
            capture = pyshark.LiveCapture(
                display_filter=args.display_filter)
            self.print_info('Using first available interface automatically')

        start_time = datetime.now().strftime("%A,%d %b - %H:%M:%S")
        self.print_ok('DETAILS' +
                        '\nDISPLAY FILTER => [ %s ]' % str(args.display_filter) +
                        '\nTIMEOUT => %s seconds' % str(args.timeout) +
                        '\nSTARTING TIME ==> ' + str(start_time))

        self.print_info("Sniffing")
        try:
            if look_for_cred:
                usrname = None
                psw = None
                cred_found = False
                try:
                    t = Tshark(self.credentials_callback, timeout=int(args.timeout), capture=capture)
                    t.setDaemon(True)
                    t.start()

                    while t.is_alive() and not cred_found:
                        for ack_pkt in conack_pkt_list:
                            for conn_pkt in conn_pkt_list:
                                if conn_pkt.ip.src == ack_pkt.ip.dst:
                                    usrname = conn_pkt.mqtt.username
                                    psw = conn_pkt.mqtt.passwd
                                    broker = ack_pkt.ip.src

                                    t.raise_exception()
                                    cred_found = True
                                    break

                            if cred_found:
                                break

                    if usrname is not None and psw is not None:
                        self.print_ok(f"Credentials found for broker: %s!" % broker)
                        self.print_ok(' > USERNAME: %s - PASSWORD: %s\r' % (usrname, psw))
                    else:
                        self.print_error("Sorry, no credential found sniffing your LAN")

                except KeyboardInterrupt:
                    t.raise_exception()
                    print("\nExiting...")

            else:
                capture.apply_on_packets(general_callback, timeout=int(args.timeout))

        except asyncio.TimeoutError:
            pass

        self.print_info("Finished sniffing")
        self.print_ok(f"Quitted from sniffing module\n")

    def credentials_callback(self, packet):
        global conack_pkt_list, conn_pkt_list
        # TODO: Add save in database sniffed_pkts.json
        try:
            val = packet.mqtt.conack_val
            conack_pkt_list.append(packet)
        except AttributeError:
            if packet.mqtt.username is not None:
                conn_pkt_list.append(packet)


class Tshark(threading.Thread):
    def __init__(self, callback, timeout, capture):
        threading.Thread.__init__(self)
        self.callback = callback
        self.timeout = timeout
        self.capture = capture
        self._stop_event = threading.Event()

    def get_id(self):
        # returns id of the respective thread
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def raise_exception(self):
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id,
                                                         ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            print('Exception raise failure')

    def run(self):
        try:
            self.capture.apply_on_packets(self.callback, timeout=self.timeout)
        except asyncio.TimeoutError:
            pass
