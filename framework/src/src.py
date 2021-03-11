from framework.src.interfaces import InterfaceCLI
from framework.src.mixins import NetworkScannerMixin

_mixins = [
    NetworkScannerMixin,
]


class MqttCLI(InterfaceCLI, *_mixins):
    """Command Line Interface that includes plugins"""
