#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PySSL.py
# Purpose:      Includes some generic routines to do SSL testing
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

from nassl import TLSV1, TLSV1_1, TLSV1_2, SSLV23, SSLV3
import socket, struct, time, random

class PySSL():

    ssl_tokens = {
        SSLV3   : "\x03\x00",
        TLSV1   : "\x03\x01",
        TLSV1_1 : "\x03\x02",
        TLSV1_2 : "\x03\x03",
    }

    ssl3_cipher = [
        '\x00\x00', '\x00\x01', '\x00\x02', '\x00\x03',
        '\x00\x04', '\x00\x05', '\x00\x06', '\x00\x07',
        '\x00\x08', '\x00\x09', '\x00\x0a', '\x00\x0b',
        '\x00\x0c', '\x00\x0d', '\x00\x0e', '\x00\x0f',
        '\x00\x10', '\x00\x11', '\x00\x12', '\x00\x13',
        '\x00\x14', '\x00\x15', '\x00\x16', '\x00\x17',
        '\x00\x18', '\x00\x19', '\x00\x1a', '\x00\x1b',
        '\x00\x1c', '\x00\x1d', '\x00\x1e',
        '\x00\x1F', '\x00\x20', '\x00\x21', '\x00\x22',
        '\x00\x23', '\x00\x24', '\x00\x25', '\x00\x26',
        '\x00\x27', '\x00\x28', '\x00\x29', '\x00\x2A',
        '\x00\x2B', '\x00\x2C', '\x00\x2D', '\x00\x2E',
        '\x00\x2F', '\x00\x30', '\x00\x31', '\x00\x32',
        '\x00\x33', '\x00\x34', '\x00\x35', '\x00\x36',
        '\x00\x37', '\x00\x38', '\x00\x39', '\x00\x3A',
        '\x00\x3B', '\x00\x3C', '\x00\x3D', '\x00\x3E',
        '\x00\x3F', '\x00\x40', '\x00\x41', '\x00\x42',
        '\x00\x43', '\x00\x44', '\x00\x45', '\x00\x46',
        '\x00\x60', '\x00\x61', '\x00\x62', '\x00\x63',
        '\x00\x64', '\x00\x65', '\x00\x66', '\x00\x67',
        '\x00\x68', '\x00\x69', '\x00\x6A', '\x00\x6B',
        '\x00\x6C', '\x00\x6D', '\x00\x80', '\x00\x81',
        '\x00\x82', '\x00\x83', '\x00\x84', '\x00\x85',
        '\x00\x86', '\x00\x87', '\x00\x88', '\x00\x89',
        '\x00\x8A', '\x00\x8B', '\x00\x8C', '\x00\x8D',
        '\x00\x8E', '\x00\x8F', '\x00\x90', '\x00\x91',
        '\x00\x92', '\x00\x93', '\x00\x94', '\x00\x95',
        '\x00\x96', '\x00\x97', '\x00\x98', '\x00\x99',
        '\x00\x9A', '\x00\x9B', '\x00\x9C', '\x00\x9D',
        '\x00\x9E', '\x00\x9F', '\x00\xA0', '\x00\xA1',
        '\x00\xA2', '\x00\xA3', '\x00\xA4', '\x00\xA5',
        '\x00\xA6', '\x00\xA7', '\x00\xA8', '\x00\xA9',
        '\x00\xAA', '\x00\xAB', '\x00\xAC', '\x00\xAD',
        '\x00\xAE', '\x00\xAF', '\x00\xB0', '\x00\xB1',
        '\x00\xB2', '\x00\xB3', '\x00\xB4', '\x00\xB5',
        '\x00\xB6', '\x00\xB7', '\x00\xB8', '\x00\xB9',
        '\x00\xBA', '\x00\xBB', '\x00\xBC', '\x00\xBD',
        '\x00\xBE', '\x00\xBF', '\x00\xC0', '\x00\xC1',
        '\x00\xC2', '\x00\xC3', '\x00\xC4', '\x00\xC5',
        '\x00\x00', '\xc0\x01', '\xc0\x02', '\xc0\x03',
        '\xc0\x04', '\xc0\x05', '\xc0\x06', '\xc0\x07',
        '\xc0\x08', '\xc0\x09', '\xc0\x0a', '\xc0\x0b',
        '\xc0\x0c', '\xc0\x0d', '\xc0\x0e', '\xc0\x0f',
        '\xc0\x10', '\xc0\x11', '\xc0\x12', '\xc0\x13',
        '\xc0\x14', '\xc0\x15', '\xc0\x16', '\xc0\x17',
        '\xc0\x18', '\xc0\x19', '\xC0\x1A', '\xC0\x1B',
        '\xC0\x1C', '\xC0\x1D', '\xC0\x1E', '\xC0\x1F',
        '\xC0\x20', '\xC0\x21', '\xC0\x22', '\xC0\x23',
        '\xC0\x24', '\xC0\x25', '\xC0\x26', '\xC0\x27',
        '\xC0\x28', '\xC0\x29', '\xC0\x2A', '\xC0\x2B',
        '\xC0\x2C', '\xC0\x2D', '\xC0\x2E', '\xC0\x2F',
        '\xC0\x30', '\xC0\x31', '\xC0\x32', '\xC0\x33',
        '\xC0\x34', '\xC0\x35', '\xC0\x36', '\xC0\x37',
        '\xC0\x38', '\xC0\x39', '\xC0\x3A', '\xC0\x3B',
        '\xfe\xfe', '\xfe\xff', '\xff\xe0', '\xff\xe1'
    ]

    def __init__(self, ip, port, timeout, sslver):
        self._inbuffer = ""
        self._ip = ip
        self._port = port
        self._timeout = timeout
        self._sslVersion = sslver

        self._sock = socket.create_connection((self._ip, self._port), self._timeout)

    def srecv(self):
        r = self._sock.recv(4096)
        self._inbuffer += r

        return r != ''

    def send(self, d):
        self._sock.send(d)

    def close(self):
        self._sock.close()

    # Create a TLS record out of a protocol packet
    def makeRecord(self, t, body):
        l = struct.pack("!H",len(body))
        return chr(t) + PySSL.ssl_tokens[self._sslVersion] + l + body

    def makeHello(self):
        suites = "".join(PySSL.ssl3_cipher)
        rand = "".join([ chr(int(256 * random.random())) for x in range(32) ])
        l  = struct.pack("!L", 39+len(suites))[1:] # 3 bytes
        sl = struct.pack("!H", len(suites))

        # Client hello, lenght and version
        # Random data + session ID + cipher suites + compression suites
        data  = "\x01" + l + PySSL.ssl_tokens[self._sslVersion] + rand + "\x00"
        data += sl + suites + "\x01\x00"

        return self.makeRecord(22, data)

    def makeCCS(self):
        ccsbody = "\x01" # Empty CCS
        return self.makeRecord(20, ccsbody)

    def parseHandshakePkt(self, buf):
        r = []
        while len(buf) >= 4:
            mt = ord(buf[0])
            mlen = struct.unpack("!L", buf[0:4])[0] & 0xFFFFFF

            if mlen+4 > len(buf):
                break

            r.append( {"type":mt, "data": buf[4:4+mlen]} )
            buf = buf[4+mlen:]
        return r

    def parseAlertPkt(self, buf):
        return [ {"level": ord(buf[0]), "desc": ord(buf[1]) } ]

    def parseRecords(self):
        r = []
        # 5 byte header
        while len(self._inbuffer) >= 5:
            mtype = ord(self._inbuffer[0])
            mtlsv = self._inbuffer[1:3]
            mlen  = struct.unpack("!H", self._inbuffer[3:5])[0]

            if len(self._inbuffer) < 5 + mlen:
                break

            if mtype == 22: # Handshake
                protp = self.parseHandshakePkt(self._inbuffer[5:5+mlen])
            elif mtype == 21: # Alert
                protp = self.parseAlertPkt(self._inbuffer[5:5+mlen])
            else:
                protp = []

            r.append( {"type":mtype, "sslv":mtlsv, "proto":protp} )

            self._inbuffer = self._inbuffer[5+mlen:]

        return r


