#!/usr/bin/python
# -*- coding: utf-8 -*-

# Heavily inspired by modules/processing/network.py, this module will
# decrypt the RC4 traffic between your Sandbox and a remote IP.
# Of course, you need to know the passphrase.
# You can also force an encoding. The default os utf-8 but if the
# processing crashes, you should try with Windows-1252.

# Example:
# utils/submit.py --options "rc4_server_ip=<C&C_IP>,rc4_passphrase=<passphrase>,rc4_encoding=Windows-1252" path


import pyRC4
import socket
import logging
import os
import ConfigParser


try:
    import dpkt
    IS_DPKT = True
except ImportError, why:
    IS_DPKT = False

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config

class PCAP(object):
    """
    Network PCAP.
    """

    def __init__(self, filepath, server_ip, passphrase, encoding='utf-8'):
        """
        Creates a new instance.
        @param filepath: path to PCAP file
        """
        self.filepath = filepath
        self.server_ip = server_ip
        self.passphrase = passphrase
        self.encoding = encoding

        self.decrypted_tcp_connections = []
        self.results = {}

    def run(self):
        """
        Process PCAP.
        @return: dict with decrypted network data
        """
        log = logging.getLogger("Processing.DecryptPcap")

        if not IS_DPKT:
            log.error("Python DPKT is not installed, aborting PCAP analysis.")
            return None

        if not os.path.exists(self.filepath):
            log.warning("The PCAP file does not exist at path \"%s\"." % self.filepath)
            return None

        if os.path.getsize(self.filepath) == 0:
            log.error("The PCAP file at path \"%s\" is empty." % self.filepath)
            return None

        file = open(self.filepath, "rb")

        try:
            pcap = dpkt.pcap.Reader(file)
        except dpkt.dpkt.NeedData:
            log.error("Unable to read PCAP file at path \"%s\"." % self.filepath)
            return None

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data

                connection = {}
                if isinstance(ip, dpkt.ip.IP):
                    connection["src"] = socket.inet_ntoa(ip.src)
                    connection["dst"] = socket.inet_ntoa(ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):
                    connection["src"] = socket.inet_ntop(socket.AF_INET6, ip.src)
                    connection["dst"] = socket.inet_ntop(socket.AF_INET6, ip.dst)
                else:
                    continue
                if self.server_ip not in [connection["src"], connection["dst"]]:
                    continue

                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if len(tcp.data) > 0:
                        connection["sport"] = tcp.sport
                        connection["dport"] = tcp.dport

                        try:
                            connection["content"] = (True,
                                    pyRC4.decrypt(self.passphrase,
                                        tcp.data).decode(self.encoding))
                        except:
                            connection["content"] = (False, tcp.data)
                        self.decrypted_tcp_connections.append(connection)
            except AttributeError, why:
                continue
            except dpkt.dpkt.NeedData, why:
                continue
        file.close()

        self.results["tcp"] = self.decrypted_tcp_connections
        return self.results



class DecryptNetworkTraffic(Processing):

    def prepare(self):
        config = Config(cfg=self.conf_path)
        options = {}
        if config.analysis is not None:
            try:
                fields = config.analysis.options.strip().split(",")
                for field in fields:
                    try:
                        key, value = field.strip().split("=")
                    except ValueError as e:
                        log.warning("Failed parsing option (%s): %s" % (field, e))
                        continue

                    options[key.strip()] = value.strip()
            except ValueError:
                pass

        self.server_ip = options.get("rc4_server_ip")
        self.passphrase = options.get("rc4_passphrase")
        if options.get("rc4_encoding") is not None:
            self.encoding = options.get("rc4_encoding")


    def run(self):
        self.key = "network_decrypt"
        self.encoding = "utf-8"
        self.prepare()
        if self.server_ip is None or self.passphrase is None:
            return None
        results = PCAP(self.pcap_path,
                self.server_ip, self.passphrase, self.encoding).run()
        return results
