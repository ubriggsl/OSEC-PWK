#!/usr/bin/python

import argparse
import socket
import sys

a = argparse.ArgumentParser()
a.add_argument('user')
a.add_argument('target')
a.add_argument('-p',dest='port',default='25')
args = a.parse_args()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	connect = s.connect((args.target,int(args.port)))

	banner = s.recv(1024)

	print banner

	s.send('VRFY '+ args.user + '\r\n')

	result = s.recv(1024)
	print result
except:
	pass

s.close()
