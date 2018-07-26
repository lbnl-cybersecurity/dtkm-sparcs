# LBNL Disruption Tolerant Key Management Monitoring for Stream-Processing Architecture for Real-time Cyber-physical Security (DTKM-SPARCS)

This software is a set of signatures that monitor the Disruption-Tolerant Key Management protocol developed by PNNL as part of the DOE CEDS program.  It leverages both the [Bro Network Security Monitor][Bro] and the [LBNL Stream-Processing Architecture for Real-time Cyber-physical Security (SPARCS)][SPARCS].

[Bro]: https://www.bro.org
[SPARCS]: https://github.com/lbnl-cybersecurity/sparcs

Tested on bro 2.5.1. Compatible with 2.5.4 stable, not compatible with beta releases (naming changed in beta 2.5.7)

# Install
Install bro with broker and pybroker. When installing bro, you have to build it yourself with all the public dependencies ./configure --enable-broker

sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev


This requires the C++ Actor Framework (CAF) version 0.14 (http://actor-framework.org) and swig 1&2&3 to be installed on the system
See https://www.bro.org/sphinx/install/install.html


Edit the bro and python files in this repo with your ip adresses and credentials

# Runing this code
Run this code with /usr/local/bro/bin/bro  respectivefile.bro (-r .pcap if replaying) on the respective location. Make sure that traffic is mirrored to the host running this code (e.g via port mirroring, man-in-the-middle etc)

On any device one can run the bro2rabbit.py code that takes messages from Bro and sends it upstream to a RabbitMQ server. 
