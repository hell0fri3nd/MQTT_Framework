import os


def get_base_path():
    return os.getcwd()


BASE_PATH = os.getenv('FRAMEWORK_BASE_PATH', get_base_path())

# Word lists
DEFAULT_USERNAME_LIST = BASE_PATH + 'resources/wordlists/usernames.txt'
DEFAULT_PASSWORD_LIST = BASE_PATH + 'resources/wordlists/passwords.txt'

# Connection Related
DEFAULT_BROKER_HOST = 'test.mosquitto.org'
DEFAULT_BROKER_PORT = 1883
DEFAULT_BROKER_USERNAME = None
DEFAULT_BROKER_PASSWORD = None

# C2 Related
C2_BASE_TOPIC = '$SYS/test123'

# Other
DEFINITIONS_PATH = BASE_PATH + 'resources/definitions.json'
STARTUP_SCRIPT = BASE_PATH + 'resources/shell_startup.rc'
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
