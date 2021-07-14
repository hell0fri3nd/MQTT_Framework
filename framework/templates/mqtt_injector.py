import random
import subprocess
import time
from framework.src.mixins.mqtt_logger import mqtt_args, load_messages, MQTTLogger

RADAMSA_CMD = 'radamsa'


def fuzzer(valid_input, n_cases=10):
    '''
    :param valid_input =  bytes to be fuzzed
    :param n_cases = number of fuzzed cases to generate
    :return: list of fuzzed cases
    '''
    import tempfile
    import os
    import shutil
    fuzz_case_dir = tempfile.mkdtemp()  # creating temporary directory
    valid_case_file = 'radamsa_input.txt'

    with open(valid_case_file, 'wb') as f:
        f.write(valid_input)
    try:
        subprocess.check_call(
            [RADAMSA_CMD, "-o", os.path.join(fuzz_case_dir, "%n.fuzz"), "-n",
             str(n_cases), valid_case_file, '-v'])
    except subprocess.CalledProcessError as error:
        raise error

    # Read the fuzz cases from the output directory and return as list
    fuzzlist = []
    for filename in os.listdir(fuzz_case_dir):
        filehandle = open(os.path.join(fuzz_case_dir, filename), "rb")
        fuzzlist.append(filehandle.read())
        filehandle.close()
    shutil.rmtree(fuzz_case_dir)

    return fuzzlist


class MQTTInjector(MQTTLogger):
    def set_replay_params(self, fuzz=0, randomise=False, qos=0, delay_ms=100):
        self.fuzz = int(fuzz)
        self.randomise = randomise
        self.qos = int(qos)
        self.delay_ms = int(delay_ms)

    def do_delay(self):
        if self.randomise:
            time.sleep(random.randint(0, self.delay_ms) / 1000)
        else:
            time.sleep(self.delay_ms / 1000)

    def get_qos(self):
        if self.randomise:
            return random.choice([0, 1, 2])
        else:
            return self.qos

    def republish_messages(self, messages):
        if self.randomise:
            random.shuffle(messages)

        for topic, payload in messages:
            payload = bytes(payload, 'utf-8')
            fuzzed = False
            if self.fuzz > 0 and random.randint(0, 100) < self.fuzz:
                modded_payloads = fuzzer(payload, n_cases=5)
                fuzzed = True
            else:
                modded_payloads = [payload]

            for p in modded_payloads:
                qos = self.get_qos()
                self.do_delay()

                if fuzzed:  # print a different colour
                    self.msg_logger.bind(topic=topic, qos=qos).error(p)
                else:
                    self.msg_logger.bind(topic=topic, qos=qos).warning(p)
                publisher = self.client.publish(topic, p, qos=qos)
                if self.delay_ms > 0:
                    publisher.wait_for_publish()

    def run(self, messages, loop=False):
        self._connect(topics=[])
        self.client.loop_start()

        keep_going = True
        try:
            while keep_going:
                self.republish_messages(messages)
                keep_going = loop
        except KeyboardInterrupt:
            pass
        finally:
            self.client.loop_stop()


if __name__ == '__main__':
    parser = mqtt_args()

    parser.add_argument('-m', '--message-file', action='store',
                        default=None,
                        help='CSV file with captured messages: use this for topics to subscribe to and messages to replay')
    parser.add_argument('-f', '--fuzz', action='store',
                        default=0,
                        help='Percentage chance (i.e. 0-100) of a given packet being fuzzed')
    parser.add_argument('-r', '--randomise', action='store_true',
                        help='Randomise packet order, QoS and timing')
    parser.add_argument('-q', '--qos', action='store',
                        default=0,
                        help='Default QoS')
    parser.add_argument('-l', '--loop', action='store_true',
                        help='Keep looping through and publishing packets forever')
    parser.add_argument('-d', '--delay', action='store',
                        default=100,
                        help='average delay between messages, ms')

    args = parser.parse_args()

    injector = MQTTInjector(args.client_id, args.broker, args.port, args.username, args.password)

    messages = [('test/echo', 'hello')]
    if args.message_file is not None:
        messages, topics = load_messages(args.message_file)

    injector.set_replay_params(args.fuzz, args.randomise, args.qos, args.delay)
    injector.run(messages, args.loop)
