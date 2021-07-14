from framework.src.interfaces import InterfaceCLI
from framework.src.mixins import NetworkScannerMixin, CredentialsBruteforceMixin, SnifferMixin, InjectorMixin, LoggerMixin

_mixins = [
    NetworkScannerMixin,
    CredentialsBruteforceMixin,
    SnifferMixin,
    InjectorMixin,
    LoggerMixin,
]


class MqttCLI(InterfaceCLI, *_mixins):
    """Command Line Interface that includes plugins"""
