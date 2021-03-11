from framework.src.interfaces import InterfaceCLI
from framework.src.mixins import NetworkScannerMixin
from framework.src.mixins import PortScannerMixin

_mixins = [
    NetworkScannerMixin,
    PortScannerMixin,
]


class MqttCLI(InterfaceCLI, *_mixins):
    """Command Line Interface that includes plugins"""
