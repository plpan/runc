#!/bin/bash

cmd=$1

if [ "$cmd" == "f" ]; then
	if [ -f /bin/docker-runc.bak ]; then
		exit -1
	fi
	mv /bin/docker-runc /bin/docker-runc.bak
	cp /home/odin/panpeilong/go/src/github.com/opencontainers/runc/runc /bin/docker-runc
elif [ "$cmd" == "b" ]; then
	if ! [ -f /bin/docker-runc.bak ]; then
		exit -1
	fi
	mv /bin/docker-runc.bak /bin/docker-runc
	rm -f /var/run/docker/libcontainerd/stupig.log
fi
