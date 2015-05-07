#!/usr/bin/env python

import tempfile, subprocess, sys, re

if len(sys.argv) < 2:
	print "Usage %s example.com"%sys.argv[0]
	sys.exit(1)

def domainfilter(ins):
	return re.sub(r"[^A-Za-z0-9\.-]*", '', ins)

domain = domainfilter(sys.argv[1])

# Launch sslyze
xml = tempfile.NamedTemporaryFile()
subprocess.call("./sslyze.py --hsts --tls_fallback_scsv --openssl_ccs --regular %s --xml_out=%s"%(domain,xml.name), shell=True)

# Read XML
from xml.dom import minidom
xml = minidom.parse(xml.name)

def getXMLattr(element, node, attr):
	for n in element.getElementsByTagName(node):
		try:
			return n.attributes[attr].value
		except:
			pass

	return ""

for child in xml.getElementsByTagName("target"):

	# Check for RC4
	rc4 = False
	for c in child.getElementsByTagName("acceptedCipherSuites"):
		for cs in c.getElementsByTagName("cipherSuite"):
			if "RC4" in cs.attributes["name"].value:
				rc4 = True

	# Check for ssl2 and ssl3
	protos = { x: "" for x in ["sslv2", "sslv3", "tlsv1", "tlsv1_1", "tlsv1_2"] }
	for pr in protos:
		proto = child.getElementsByTagName(pr)[0]
		for c in proto.getElementsByTagName("acceptedCipherSuites"):
			protos[pr] = str(len(c.getElementsByTagName("cipherSuite")) > 0)

	# Vuln info
	ssl_report = {
		"vulnerabilities": {
			"heartbleed":    getXMLattr(child, "openSslHeartbleed", "isVulnerable"),
			"ccs-injection": getXMLattr(child, "ccs_injection", "isVulnerable"),
			# CRIMA attack
			"tls-compression": getXMLattr(child, "compressionMethod", "isSupported"),
			
			# Client renegotiation: insecure if enabled! Can cause DoS too!
			"client-renegotiation": getXMLattr(child, "sessionRenegotiation", "canBeClientInitiated"),
			# Secure Renegotiation: Must be enabled, otherwise trivial MITM can be used to get HTTP cookies
			"secure-renegotiation": getXMLattr(child, "sessionRenegotiation", "isSecure"),

			# HSTS support
			"hsts-support": getXMLattr(child, "httpStrictTransportSecurity", "isSupported"),

			# Cipher issues
			"rc4-enabled": str(rc4),
			"tls-fallback-scsv": getXMLattr(child, "tls_fallback_scsv", "support"),
		},
		"protocols": protos,
	}

	import pprint
	pprint.pprint( ssl_report )

