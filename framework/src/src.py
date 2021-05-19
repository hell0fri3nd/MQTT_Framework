from framework.src.interfaces import InterfaceCLI
from framework.src.mixins import NetworkScannerMixin, CredentialsBruteforceMixin, PortScannerMixin

_mixins = [
    NetworkScannerMixin,
    PortScannerMixin,
    CredentialsBruteforceMixin,
]


class MqttCLI(InterfaceCLI, *_mixins):
    """Command Line Interface that includes plugins"""
