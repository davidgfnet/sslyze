#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginTLS_Fallback_Support.py
# Purpose:      Tests the target server for TLS_FALLBACK_SCSV support.
#
# Author:       David Guillen Fandos
#
# Copyright:    2015 David Guillen Fandos
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import socket, new
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils import PySSL
from utils.SSLyzeSSLConnection import create_sslyze_connection, SSLHandshakeRejected
from nassl._nassl import OpenSSLError, WantX509LookupError, WantReadError
from nassl import TLSV1, TLSV1_1, TLSV1_2, SSLV23, SSLV3
import socket, struct, time, random

class PluginTLS_Fallback_Support(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface("PluginTLS_Fallback_Support",  "")
    interface.add_command(
        command="tls_fallback_scsv",
        help=(
            "Tests the server(s) for TLS_FALLBACK_SCSV support"))

    def process_task(self, target, command, args):
        (self._host, self._ip, self._port, self._sslVersion) = target
        self._timeout = self._shared_settings['timeout']

        # First try all SSL versions
        ssl_versions = [SSLV3, TLSV1, TLSV1_1, TLSV1_2]
        support = { k:False for k in ssl_versions }
        for self._sslVersion in ssl_versions:
            self._pyssl = PySSL.PySSL(self._ip, self._port, self._timeout, self._sslVersion)

            # Send hello and wait for server hello & cert
            self._pyssl.send(self._pyssl.makeHello())
            end = False
            while not end:
                try:
                    if not self._pyssl.srecv(): break
                except:
                    break

                rs = self._pyssl.parseRecords()
                for record in rs:
                    if record['type'] == 22:
                        for p in record['proto']:
                            if p['type'] == 2:
                                support[self._sslVersion] = True
                                end = True
                    if record['type'] == 21:
                        end = True

        # Pick the largest version-1, if there are more than 2 obviously
        num_supported = sum([ 1 for x in support if support[x]])
        hasscsv = False
        if num_supported > 1:
            vmax = max([ x for x in support if support[x] ])
            self._sslVersion = max([ x for x in support if support[x] and x != vmax ])

            self._pyssl = PySSL.PySSL(self._ip, self._port, self._timeout, self._sslVersion)

            # Send hello and wait for server hello & cert
            self._pyssl.addCipher("\x56\x00")
            self._pyssl.send(self._pyssl.makeHello())
            end = False
            while not end:
                try:
                    if not self._pyssl.srecv(): break
                except:
                    break

                rs = self._pyssl.parseRecords()
                for record in rs:
                    if record['type'] == 21:
                        hasscsv = True
                        end = True
                    if record['type'] == 22:
                        end = True

        if num_supported == 1:
            scsvsupportTxt = 'N/A - Server only supports one version of the protocol'
            scsvsupportXml = 'False'
        elif hasscsv:
            scsvsupportTxt = 'OK - Server supports TLS_FALLBACK_SCSV'
            scsvsupportXml = 'True'
        else:
            scsvsupportTxt = 'FAILED - Server does not support TLS_FALLBACK_SCSV'
            scsvsupportXml = 'False'

        cmdTitle = 'TLS_FALLBACK_SCSV support'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]
        txtOutput.append(self.FIELD_FORMAT(scsvsupportTxt, ""))

        xmlOutput = Element(command, title=cmdTitle)
        if hasscsv:
            xmlNode = Element('tls_fallback_scsv', support=scsvsupportXml)
            xmlOutput.append(xmlNode)

        return PluginBase.PluginResult(txtOutput, xmlOutput)

