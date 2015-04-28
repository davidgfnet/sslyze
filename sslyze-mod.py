#!/usr/bin/env python

import tempfile, subprocess, sys

if len(sys.argv) < 2:
	print "Usage %s example.com"%sys.argv[0]
	sys.exit(1)

domain = sys.argv[1]

# Launch sslyze
xml = tempfile.NamedTemporaryFile()
subprocess.call("./sslyze.py --tls_fallback_scsv --openssl_ccs --regular %s --xml_out=%s"%(domain,xml.name), shell=True)

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

	# Vuln info
	ssl_report = {
		"vulnerabilities": {
			"heartbleed":      getXMLattr(child, "heartbleed", "isVulnerable"),
			"ccs-injection":   getXMLattr(child, "ccs_injection", "isVulnerable"),
			# CRIMA attack
			"tls-compression": getXMLattr(child, "compressionMethod", "isSupported"),
			
			# Session renegotiation
			"client-renegotiation": getXMLattr(child, "sessionRenegotiation", "canBeClientInitiated"),
			"secure-renegotiation": getXMLattr(child, "sessionRenegotiation", "isSecure"),

			# Cipher issues
			"rc4-enabled": str(rc4),
		},
	}

	import pprint
	pprint.pprint( ssl_report )

