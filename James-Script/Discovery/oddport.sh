#!/bin/bash

# Constants
APPEND='-append-output'
DISCOVERY_DIR=/root/offsec/discovery
FILENAME=$1
GREP=/bin/grep
NIKTO=/usr/bin/nikto
NMAP=/usr/bin/nmap
SED=/bin/sed
TIMING='-T4'
ZAP=/usr/share/zaproxy/zap.sh

# Meta-variables
COMMON="$APPEND $TIMING"

function http {
	# Port 80
	echo -e "\tHTTP:\t\t$HOST $PORT"
#	$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST
#	$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST --proxies http://0.0.0.0:8081
	$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST
	$NIKTO -host $HOST -port $PORT >> $DISCOVERY_DIR/$HOST-nikto.txt
}

function https {
	# Port 443
	http $HOST $PORT
	echo -e "\tHTTPS:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=ssl-cert,ssl-heartbleed,ssl-poodle,sslv2-drown,sslv2 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function odd_port {
	echo "[*] Odd Port: $HOST:$PORT"
	https $HOST $PORT
}

HOST=$1
PORT=$2
odd_port ${HOST} ${PORT}
