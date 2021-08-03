import os


def get_base_path():
    return os.getcwd()


BASE_PATH = os.getenv('FRAMEWORK_BASE_PATH', get_base_path())

# Radamsa execute command
RADAMSA_CMD = 'radamsa.exe'

# Word lists
DEFAULT_USERNAME_LIST = BASE_PATH + '/assets/dicts/xato-net-10-million-usernames.txt'
DEFAULT_PASSWORD_LIST = BASE_PATH + 'framework/assets/dicts/xato-net-10-million-passwords.txt'

# Other
STARTUP_SCRIPT = BASE_PATH + 'resources/shell_startup.rc'
