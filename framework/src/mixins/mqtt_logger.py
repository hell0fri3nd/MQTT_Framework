from loguru import logger
from cmd2 import with_argparser, with_category
import random
import csv
import argparse

import paho.mqtt.client as mqtt

from framework.src.interfaces import InterfaceMixin


def create_msg_logger():
    import sys
    # Configure a logger specifically for MQTT message logging
    logger.configure(handlers=[{'sink': sys.stdout, 'colorize': True,
                                'format': '<green>{time:HH:mm:ss.SSS}</green>  | <cyan>{extra[qos]:<3}</cyan> | <blue>{extra[topic]:<25}</blue> | <lvl>{message}</lvl>'}])
    msg_logger = logger.bind(topic='', qos='')
    msg_logger.bind(topic='topic', qos='qos').info('message')
    return msg_logger


def load_messages(file_name):
    # messages is a list of: (topic, content)
    messages = []

    with open(file_name, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        for line in reader:
            if reader.line_num == 1:
                # this is the header row, check it's as expected
                expected_header = ['id', 'topic', 'message']
                for h, e in zip(line, expected_header):
                    if h != e:
                        print(f'Invalid CSV header, \n\texpected: {expected_header}\n\tgot: {line}')
                        raise ValueError
            else:
                messages.append((line[1], line[2]))

    # topics found
    topics = set([m[0] for m in messages])

    return messages, topics


def mqtt_args(desc):
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-b', '--broker', action='store',
                        default='0.0.0.0',
                        help='Broker URL')
    parser.add_argument('-p', '--port', action='store',
                        default=1883, type=int,
                        help='Broker port')
    parser.add_argument('-c', '--client-id', action='store',
                        default=f'tester_{random.getrandbits(32):02x}',
                        help='client ID')
    parser.add_argument('-u', '--username', action='store',
                        default=None,
                        help='username')
    parser.add_argument('-z', '--password', action='store',
                        default=None,
                        help='password')
    return parser


class LoggerMixin(InterfaceMixin):
    logger_parser = mqtt_args("Listen to messages broadcasted for the selected topics and reply")
    logger_parser.add_argument('-m', '--message-file', action='store',
                               default=None,
                               help='CSV file with captured messages: use this for topics to subscribe to and messages to replay')
    args = logger_parser.parse_args()

    @with_category(InterfaceMixin.CMD_CAT_VICTIM_OP)
    @with_argparser(logger_parser)
    def do_log(self, args):
        mqtt_logger = MQTTLogger(args.client_id, args.broker, args.port, args.username, args.password)

        topics = ['#']
        if args.message_file is not None:
            _, topics = load_messages(args.message_file)

        mqtt_logger.run(topics)


class MQTTLogger:
    def __init__(self, client_id, host='localhost', port=1883, username=None, password=None):
        self.client_id = client_id
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.msg_logger = create_msg_logger()
        self.warn = self.msg_logger.bind(topic='', qos='').warning
        self.error = self.msg_logger.bind(topic='', qos='').error

        self.client = mqtt.Client(client_id=client_id, clean_session=True)
        if self.username is not None:
            self.client.username_pw_set(self.username, self.password)

        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc):
        self.warn(f'Connected with result code {rc}')
        if len(self.topics) > 0:
            self.warn(f'Subscribing to {self.topics}')

        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        for t in self.topics:
            client.subscribe(t)

    def _on_message(self, client, userdata, msg):
        print(msg.timestamp)
        self.msg_logger.bind(topic=msg.topic, qos=msg.qos).info(msg.payload)

    def _connect(self, topics=[]):
        self.topics = topics
        self.client.connect(self.host, self.port, 60)

    def run(self, topics=[]):
        self._connect(topics)
        try:
            self.client.loop_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.client.loop_stop()
