# OpenVPN-easy-setup (OUTDATED, PLEASE DO NOT USE)
Bash script for easy and fast OpenVPN server deploy

For CentOS 7.x and Ubuntu Server 17.x only. (Ubuntu Server 16.x is supported, but it have OpenVPN 2.3.x)
Use only on fresh installed machine. It will rewrite your iptables and OpenVPN configuration.

Features:
- Setup new server with one command in a couple of minutes;
- Creates client config in unified format;
- Choose of port and protocol;
- Choose of cipher;
- IPv6 support.

Usage: ./openvpnsetup.sh 

Before enabling IPv6 support ensure that your machine have IPv6 address.
Note: iptables rule allow port 22 tcp (ssh) by default, if you have sshd on another port modify script before execution.

After script is complete you can create client config files in unified format with /etc/openvpn/newclient.sh script.
Usage: ./newclient.sh clientname
Config file will be saved to /etc/openvpn/bundles/clientname.ovpn and it ready to use (even on mobile device).





