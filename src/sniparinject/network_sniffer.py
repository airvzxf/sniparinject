#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Start the sniff of the network packets.
"""
from pathlib import Path

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

        network = settings.get('Network') or {}
        self.interface = network.get('interface')
        self.offline = self._resolve_offline_path(settings_path, network.get('offline'))
        protocol = settings.get('Server').get('protocol') or 'tcp'
        self.protocol = protocol.lower()
        self.host_ip = settings.get('Server').get('ip') or None
        self.host_port = settings.get('Server').get('port') or None
        print()
        print('=== Network Sniffer ===')
        if self.offline:
            print(f'Offline:   {self.offline}')
        else:
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
        if self.offline:
            # A BPF filter on a capture file needs tcpdump, so the packets
            # read from the file are filtered in _sniff_data instead.
            sniff(
                offline=self.offline,
                count=0,
                store=False,
                prn=self._sniff_data
            )
            return

        sniffer_filter = self.protocol
        if self.host_ip:
            sniffer_filter += f' and host {self.host_ip}'
        if self.host_port:
            sniffer_filter += f' and port {self.host_port}'

        sniff(
            iface=self.interface,
            filter=sniffer_filter,
            count=0,
            store=False,
            prn=self._sniff_data
        )

    @staticmethod
    def _resolve_offline_path(settings_path: str, offline: str | None) -> str | None:
        """
        Resolve the capture file path, relative to the settings file.

        :type settings_path: str
        :param settings_path: The path of the YAML file with settings.

        :type offline: str | None
        :param offline: The capture file (pcap or pcapng) from the settings.

        :rtype: str | None
        :return: The capture file path, or None to sniff the network interface.
        """
        if not offline:
            return None

        offline_path = Path(offline)
        if not offline_path.is_absolute():
            offline_path = Path(settings_path).parent / offline_path

        return str(offline_path)

    def _is_server_packet(self, ip_layer: IP, layer_type: TCP | UDP) -> bool:
        """
        Check if the packet goes to or comes from the configured server.

        :type ip_layer: IP
        :param ip_layer: The IP layer of the packet.

        :type layer_type: TCP | UDP
        :param layer_type: The protocol layer of the packet.

        :rtype: bool
        :return: True if the packet matches the server IP and port.
        """
        if self.host_ip and self.host_ip not in (ip_layer.src, ip_layer.dst):
            return False

        if self.host_port and self.host_port not in (layer_type.sport, layer_type.dport):
            return False

        return True

    def _sniff_data(self, packet: Ether) -> None:
        """
        Process data provided by the Sniffer.
        Packets without an IP layer or without the configured protocol layer
        (TCP or UDP) are skipped, so they do not stop the sniffer.

        :type packet: Ether
        :param packet: The sniffed packet.

        :rtype: None
        :return: Nothing.
        """
        ip_layer = packet.getlayer(IP)
        layer_type = packet.getlayer(UDP) if self.protocol == 'udp' else packet.getlayer(TCP)
        if not ip_layer or not layer_type:
            return

        if self.offline and not self._is_server_packet(ip_layer, layer_type):
            return

        if self.host_ip and self.host_port:
            is_host = self.host_ip == ip_layer.src and self.host_port == layer_type.sport
        else:
            is_host = self.host_ip == ip_layer.src or self.host_port == layer_type.sport

        if packet.haslayer(Raw):
            Game(self.settings_path, is_host, packet).start()
