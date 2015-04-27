#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginOpenSSL_CCS_injection.py
# Purpose:      Tests the target server for CVE-2014-0224.
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

class PluginOpenSSL_CCS_injection(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface("PluginOpenSSL_CCS_injection",  "")
    interface.add_command(
        command="openssl_ccs",
        help=(
            "Tests the server(s) for the OpenSSL CCS injection vulnerability (experimental)."))

    def process_task(self, target, command, args):
        (self._host, self._ip, self._port, self._sslVersion) = target
        self._timeout = self._shared_settings['timeout']

        # Although it's kinda redundant, try all proto versions
        vuln = False
        for self._sslVersion in [TLSV1, TLSV1_1, TLSV1_2, SSLV3]:
            self._pyssl = PySSL.PySSL(self._ip, self._port, self._timeout, self._sslVersion)

            # Send hello and wait for server hello & cert
            serverhello, servercert = False, False
            self._pyssl.send(self._pyssl.makeHello())
            while not serverhello: #  or not servercert
                try:
                    if not self._pyssl.srecv(): break
                except:
                    break
                rs = self._pyssl.parseRecords()
                for record in rs:
                    if record['type'] == 22:
                        for p in record['proto']:
                            if p['type'] == 2:
                                serverhello= True
                            if p['type'] == 11:
                                servercert= True

            # Send the CCS
            if serverhello: # and servercert:
                vuln, stop = True, False
                self._pyssl.send(self._pyssl.makeCCS())
                while not stop:
                    try:
                        if not self._pyssl.srecv(): break
                    except socket.timeout:
                        break
                    except:
                        vuln = False
                        stop = True

                    rs = self._pyssl.parseRecords()
                    for record in rs:
                        if record['type'] == 21:
                            for p in record['proto']:
                                if p['level'] == 2 or (p['level'] == 1 and p['desc'] == 0):
                                    vuln = False
                                    stop = True

                # If we receive no alert message check whether it is really vuln
                if vuln:
                    self._pyssl.send('\x15' + PySSL.PySSL.ssl_tokens[self._sslVersion] + '\x00\x02\x01\x00')

                    try:
                        if not self._pyssl.srecv():
                            vuln = False
                    except:
                        vuln = False

            self._pyssl.close()
   
            if vuln:
                break

        if vuln:
            opensslccsTxt = 'VULNERABLE - Server is vulnerable to OpenSSL\'s CCS injection'
            opensslccsXml = 'True'
        else:
            opensslccsTxt = 'OK - Not vulnerable to OpenSSL\'s CCS injection'
            opensslccsXml = 'False'

        cmdTitle = 'Open SSL CVE-2014-0224'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]
        txtOutput.append(self.FIELD_FORMAT(opensslccsTxt, ""))

        xmlOutput = Element(command, title=cmdTitle)
        if vuln:
            xmlNode = Element('openssl_ccs', isVulnerable=opensslccsXml)
            xmlOutput.append(xmlNode)

        return PluginBase.PluginResult(txtOutput, xmlOutput)

