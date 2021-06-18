#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Start the sniff of the network packets.
"""
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sniff

# pylint: disable=import-error
from .core.game import Game
from .core.settings import Settings


# pylint: disable=too-few-public-methods
class NetworkSniffer:
    """
    Init the sniff of the network for spy the packets.
    """

    def __init__(self, settings_path: str) -> None:
        """
        Init the sniff of the network for spy the packets.

        :type settings_path: dict
        :param settings_path: The path of the YAML file with settings.

        :rtype: None
        :return: Nothing.
        """
        self.settings_path = settings_path
        print()
        print('=== Settings ===')
        settings = Settings(settings_path).get_dictionary()
        print(settings)

        self.interface = settings.get('Network').get('interface')
        protocol = settings.get('Server').get('protocol') or 'tcp'
        self.protocol = protocol.lower()
        self.host_ip = settings.get('Server').get('ip') or None
        self.host_port = settings.get('Server').get('port') or None
        print()
        print('=== Network Sniffer ===')
        print(f'Interface: {self.interface}')
        print(f'Protocol:  {self.protocol}')
        print(f'Host IP:   {self.host_ip}')
        print(f'Host Port: {self.host_port}')
        print()

    def start(self) -> None:
        """
        Start the sniffer.

        :rtype: None
        :return: Nothing.
        """
        sniffer_filter = self.protocol
        if self.host_ip:
            sniffer_filter += f' and host {self.host_ip}'
        if self.host_port:
            sniffer_filter += f' and port {self.host_port}'

        sniff(
            iface=self.interface,
            filter=sniffer_filter,
            count=0,
            prn=self._sniff_data
        )

    def _sniff_data(self, packet: Ether) -> None:
        """
        Process data provided by the Sniffer.

        :type packet: Ether
        :param packet: The sniffed packet.

        :rtype: None
        :return: Nothing.
        """
        ip_layer = packet.getlayer(IP)
        if not ip_layer:
            raise Exception('Error: The IP layer not exists in this package.')

        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            raise Exception('Error: The protocol layer (TCP or UDP) not exists in this package.')

        layer_type = packet.getlayer(UDP) if self.protocol == 'udp' else packet.getlayer(TCP)

        if self.host_ip and self.host_port:
            is_host = self.host_ip == ip_layer.src and self.host_port == layer_type.sport
        else:
            is_host = self.host_ip == ip_layer.src or self.host_port == layer_type.sport

        if packet.haslayer(Raw):
            Game(self.settings_path, is_host, packet).start()
