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


#counter=0

# Begin function definitions
function ftp {
	# Port 21
	echo -e "\tFTP:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function ssh {
	# Port 22
	echo -e "\tSSH:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=ssh2-enum-algos,ssh-hostkey,sshv1 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function smtp {
	# Port 25
	echo -e "\tSMTP:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=smtp-commands,smtp-ntlm-info,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1764 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function http {
	# Port 80
	echo -e "\tHTTP:\t\t$HOST $PORT"
#	$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST
#	$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST --proxies http://0.0.0.0:8081
	$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST
	$NIKTO -host $HOST -port $PORT >> $DISCOVERY_DIR/$HOST-nikto.txt
}

function pop {
	# Port 110
	echo -e "\tPOP:\t\t$HOST $PORT" 
	$NMAP -p $PORT $HOST --script=pop3-capabilities,pop3-ntlm-info $COMMON -oA $DISCOVERY_DIR/$HOST
}

function rpc-bind {
	# Port 111
	echo -e "\tRPC-BIND:\t$HOST $PORT"
}

function rpc {
	# Port 135
	echo -e "\tRPC:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=msrpc-enum,rpc-grind,rpcinfo $COMMON -oA $DISCOVERY_DIR/$HOST
}

function netbios {
	# Port 139
	echo -e "\tNetBios:\t$HOST $PORT"
	$NMAP -p $PORT,445 $HOST --script=broadcast-netbios-master-browser $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT,445 $HOST --script=smb-vuln-ms08-067 --script-args=unsafe=1 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function imap {
	# Port 143 or 993
	echo -e "\tIMAP:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=imap-capabilities,imap-ntlm-info $COMMON -oA $DISCOVERY_DIR/$HOST
}

function https {
	# Port 443
	http $HOST $PORT
	echo -e "\tHTTPS:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=ssl-cert,ssl-heartbleed,ssl-poodle,sslv2-drown,sslv2 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function ms-ds {
	# Port 445
	echo -e "\tMS-DS:\t\t$HOST $PORT Not searched"
}

function imap-ssl {
	# Port 993
	echo -e "\tIMAP-SSL:\t$HOST $PORT"
}

function pop-ssl {
	# Port 995
	echo -e "\tPOP:\t\t$HOST $PORT"
}

function ms-rpc {
	# Port 1025
	echo -e "\tMS-RPC:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=msrpc-enum,rpc-grind,rpcinfo $COMMON -oA $DISCOVERY_DIR/$HOST
}

function mysql {
	# Port 3306
	echo -e "\tMySQL:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=mysql-audit,mysql-databases,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function rdp {
	# Port 3389
	echo -e "\tRDP:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --script=rdp-enum-encryption,rdp-vuln-ms12-020 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function odd_port {
	echo "[*] Odd Port: $PORT"
	http $HOST $PORT
	https $HOST $PORT
}


# Start ZAP proxy
#$ZAP -port 8081 -config api.key=12345 -newsession $DISCOVERY_DIR >/dev/null &
#sleep 5

while read -r currentline
do
	counter=$((counter + 1))
	echo $currentline |$GREP "Ports:" >/dev/null
	if [ $? -eq 0 ]
	then
		HOST=`echo $currentline |$SED "s/^Host: \(.*\) ().*/\1/"`
		# Cleanup port list
		temp=`echo $currentline |$SED "s/^.*Ports: \(.*\/\).*$/\1/;"`
		temp=`echo ${temp} |$SED "s/[a-zA-Z]//g;s/^/, /;s/$/,/;"`
		temp=`echo ${temp} |$SED "s/, \([0-9]\{1,5\}\)[^,]*/\1 /g;s/,.*$//;"`
		SERVICES=(${temp})
		NETBIOS=0
		echo -e "[*] $HOST\t\t\t\tServices: ${#SERVICES[@]}"

		for PORT in "${SERVICES[@]}"
		do
			case $PORT in
				21 ) ftp ${HOST} ${PORT} ;;
				22 ) ssh ${HOST} ${PORT} ;;
				25 ) smtp ${HOST} ${PORT} ;;
				80 ) http ${HOST} ${PORT} ;;
				110 ) pop ${HOST} ${PORT} ;;
				111 ) rpc-bind ${HOST} ${PORT} ;;
				135 ) rpc ${HOST} ${PORT} ;;
				139 ) NETBIOS=$((NETBIOS + 1)) ;;
				143 ) imap ${HOST} ${PORT} ;;
				443 ) https ${HOST} ${PORT} ;;
				445 ) NETBIOS=$((NETBIOS + 1)) ;;
				993 ) imap ${HOST} ${PORT} ;;
				995 ) pop ${HOST} ${PORT} ;;
				1025 ) ms-rpc ${HOST} ${PORT} ;;
				3306 ) mysql ${HOST} ${PORT} ;;
				3389 ) rdp ${HOST} ${PORT} ;;
				8000 ) http ${HOST} ${PORT} ;;
				* ) odd_port ${HOST} ${PORT} ;;
			esac
		done
		if [ $NETBIOS -ne "0" ]
		then
			netbios ${HOST} 139
		fi
		echo -e "\n****************************************\n"
	fi
done < $FILENAME	
