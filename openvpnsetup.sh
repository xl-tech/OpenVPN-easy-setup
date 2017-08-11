#! /bin/bash
#
# Express setup of OpenVPN server 
# for CentOS 7.x and Ubuntu Server 16.x / 17.x
# by xl-tech https://github.com/xl-tech
#
# Version 0.1 12 August 2017
#
# Use only on fresh installed machine! It can rewrite your firewall rules
# or your current OpenVPN config (if you have it before).
#
# Script is licensed under the GNU General Public License v3.0
#
# Usage: just run openvpnsetup.sh :)
#

#check for root
IAM=$(whoami)
if [ ${IAM} != "root" ]; then
    echo "You must be root to use this script"
    exit 1
fi

#check for tun/tap
if [ -c /dev/net/tun ]; then
    echo TUN/TAP is enabled
else
    echo TUN/TAP is disabled. Contact your VPS provider to enable it
    exit 1
fi
	
#enable IPv4 forwarding
if sysctl net.ipv4.ip_forward |grep 0; then
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
else
    echo "IPv4 forwarding is already enabled"
fi

#package install
yum_packages="openssl openvpn easy-rsa iptables iptables-services curl"
deb_packages="openssl openvpn easy-rsa iptables netfilter-persistent iptables-persistent curl"

if cat /etc/*release | grep ^NAME | grep CentOS; then
    yum -y install epel-release
    yum -y install $yum_packages
    systemctl disable firewalld & systemctl stop firewalld
elif cat /etc/*release | grep ^NAME | grep Ubuntu; then
    apt-get install -y $deb_packages
    ufw disable
else
    echo "Unsupported distro, sorry"
    exit 1;
fi

#server settings
#internal IP
IIP=`hostname -I`
#external IP
EIP=`curl -s checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//'`
#internal IPv6 with mask
IIPv6=`ip -6 addr|grep inet6|grep fe80|awk -F '[ \t]+|' '{print $3}'`

echo "Select server IP to listen on (only used for IPv4):
1) Internal IP - $IIP (in case you are behind NAT)
2) External IP - $EIP
"
read n
case $n in
    1) IP=$IIP;;
    2) IP=$EIP;;
    *) invalid option;;
esac

echo "Select server PORT to listen on:
1) tcp 443 (recommended)
2) udp 1194 (default)
3) Enter manually (proto (lowercase!) port)
"
read n
case $n in
    1) PORT="tcp 443";;
    2) PORT="udp 1194";;
    3) echo -n "Enter proto and port (like tcp 80 or udp 53): " & read -e PORT;;
    *) invalid option;;
esac

PORTN=`echo $PORT|grep -o '[0-9]*'`
PORTL=`echo $PORT|grep -o '[a-z,A-Z]*'`
PORTL6=$PORTL"6"

echo "Select server cipher:
1) AES-256-GCM (default for OpenVPN 2.4.x, not supported by Ubuntu Server 16.x)
2) AES-256-CBC
3) AES-128-CBC (default for OpenVPN 2.3.x)
4) BF-CBC (insecure)
"
read n
case $n in
    1) CIPHER=AES-256-GCM;;
    2) CIPHER=AES-256-CBC;;
    3) CIPHER=AES-128-CBC;;
    4) CIPHER=BF-CBC;;
    *) invalid option;;
esac

echo "Enable IPv6? (ensure that your machine have IPv6 support):
1) Yes
2) No
"
read n
case $n in
    1) IPV6E=1;;
    2) IPV6E=0;;
    *) invalid option;;
esac

echo "Check your selection"
echo "Server will listen on $IP"
echo "Server will listen on $PORT"
echo "Server will use $CIPHER cipher"
echo "IPv6 - $IPV6E (1 is enabled, 0 is disabled)"
read -rsp $'Press enter to continue...\n'

#create dirs and files
mkdir /etc/openvpn/easy-rsa
mkdir /etc/openvpn/easy-rsa/keys
mkdir /etc/openvpn/logs
mkdir /etc/openvpn/bundles
mkdir /etc/openvpn/ccd
touch /etc/openvpn/easy-rsa/keys/index.txt
touch /etc/openvpn/easy-rsa/keys/serial
echo 00 >> /etc/openvpn/easy-rsa/keys/serial
#copy easy-rsa
if cat /etc/*release | grep ^NAME | grep CentOS; then
    cp /usr/share/easy-rsa/2.0/* /etc/openvpn/easy-rsa
elif cat /etc/*release | grep ^NAME | grep Ubuntu; then
    cp /usr/share/easy-rsa/* /etc/openvpn/easy-rsa
fi
#vars for certs
export EASY_RSA="/etc/openvpn/easy-rsa"
export OPENSSL="openssl"
export PKCS11TOOL="pkcs11-tool"
export GREP="grep"
export KEY_CONFIG=`$EASY_RSA/whichopensslcnf $EASY_RSA`
export KEY_DIR="$EASY_RSA/keys"
export PKCS11_MODULE_PATH="dummy"
export PKCS11_PIN="dummy"
export KEY_SIZE=2048
export CA_EXPIRE=3650
export KEY_EXPIRE=1825
export KEY_COUNTRY="US"
export KEY_PROVINCE="CA"
export KEY_CITY="SanFrancisco"
export KEY_ORG="Fort-Funston"
export KEY_EMAIL="my@vpn.net"
export KEY_OU="MyVPN"
export KEY_NAME="EasyRSA"

#issue certs and keys
#ca
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --batch --initca $*
#server
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --batch --server server-cert
#dh
$OPENSSL dhparam -out ${KEY_DIR}/dh.pem ${KEY_SIZE}
#ta
openvpn --genkey --secret ${KEY_DIR}/ta.key
#issue and revoke client cert to generate list of revoked certs
"$EASY_RSA/pkitool" --batch revoked
"$EASY_RSA/revoke-full" revoked
echo "Error 23 indicates that revoke is successful"

#generate server config

#ipv6 part
if (( "$IPV6E" == 1 )); then

#enable IPv6 forwarding
if sysctl net.ipv6.conf.all.forwarding |grep 0; then
    sysctl -w net.ipv6.conf.all.forwarding=1
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf
else
    echo "IPv6 forwarding is already enabled"
fi

echo -e "#IPv6 config
server-ipv6 fd6c:62d9:eb8c::/112
proto $PORTL6
tun-ipv6
push tun-ipv6
push \042route-ipv6 2000::/3\042
push \042redirect-gateway ipv6\042
" > /etc/openvpn/server.conf
else
echo "local $IP" > /etc/openvpn/server.conf
fi

#main part
echo -e "port $PORTN
proto $PORTL
dev tun

#for cert revoke check
crl-verify /etc/openvpn/easy-rsa/keys/crl.pem

server 10.1.0.0 255.255.255.0
topology subnet
push \042redirect-gateway def1 bypass-dhcp\042

#duplicate-cn

push \042dhcp-option DNS 8.8.8.8\042
push \042dhcp-option DNS 8.8.4.4\042

comp-lzo adaptive
push \042comp-lzo adaptive\042

mssfix 0
push \042mssfix 0\042

#management 0.0.0.0 7000 /etc/openvpn/management-password

#duplicate-cn
keepalive 10 120
tls-timeout 160
hand-window 160

cipher $CIPHER
auth SHA256

#uncomment for 2.4.x feature to disable automatically negotiate in AES-256-GCM
#ncp-disable

#max-clients 300

#user nobody
#group nobody

persist-key
persist-tun

status /etc/openvpn/logs/openvpn-status.log
log-append /etc/openvpn/logs/openvpn.log

verb 2
#reneg-sec 864000
mute 3
tls-server
#script-security 3

#buffers
sndbuf 393216
rcvbuf 393216
push \042sndbuf 393216\042
push \042rcvbuf 393216\042
" >> /etc/openvpn/server.conf

echo "<ca>"  >> /etc/openvpn/server.conf
cat $KEY_DIR/ca.crt >> /etc/openvpn/server.conf
echo "</ca>" >> /etc/openvpn/server.conf

echo "<cert>"  >> /etc/openvpn/server.conf
cat $KEY_DIR/server-cert.crt >> /etc/openvpn/server.conf
echo "</cert>" >> /etc/openvpn/server.conf

echo "<key>"  >> /etc/openvpn/server.conf
cat $KEY_DIR/server-cert.key >> /etc/openvpn/server.conf
echo "</key>" >> /etc/openvpn/server.conf

if openvpn --version | grep 2.3; then
    # ta tls auth OpenVPN 2.3.x
    echo "key-direction 0" >> /etc/openvpn/server.conf
    echo "<tls-auth>"  >> /etc/openvpn/server.conf
    cat $KEY_DIR/ta.key >> /etc/openvpn/server.conf
    echo "</tls-auth>" >> /etc/openvpn/server.conf
else
    # ta tls crypt OpenVPN 2.4.x
    echo "<tls-crypt>"  >> /etc/openvpn/server.conf
    cat $KEY_DIR/ta.key >> /etc/openvpn/server.conf
    echo "</tls-crypt>" >> /etc/openvpn/server.conf
fi

echo "<dh>"  >> /etc/openvpn/server.conf
cat $KEY_DIR/dh.pem >> /etc/openvpn/server.conf
echo "</dh>" >> /etc/openvpn/server.conf

#create iptables file
echo "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:XL-Firewall-1-INPUT - [0:0]
-A INPUT -j XL-Firewall-1-INPUT
-A FORWARD -j XL-Firewall-1-INPUT
-A XL-Firewall-1-INPUT -p icmp --icmp-type any -s localhost -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state NEW -m $PORTL -p $PORTL --dport $PORTN -j ACCEPT
-A XL-Firewall-1-INPUT -i tun+ -j ACCEPT
-A XL-Firewall-1-INPUT -j REJECT --reject-with icmp-host-prohibited
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A POSTROUTING -s 10.1.0.0/24 -j MASQUERADE
COMMIT" > /tmp/iptables

#create ip6tables file
echo "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:XL-Firewall-1-INPUT - [0:0]
-A INPUT -j XL-Firewall-1-INPUT
-A FORWARD -j XL-Firewall-1-INPUT
-A XL-Firewall-1-INPUT -i lo -j ACCEPT
-A XL-Firewall-1-INPUT -p icmpv6 -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A XL-Firewall-1-INPUT -m state --state NEW -m $PORTL -p $PORTL --dport $PORTN -j ACCEPT
-A XL-Firewall-1-INPUT -i tun+ -j ACCEPT
-A XL-Firewall-1-INPUT -j REJECT --reject-with icmp6-adm-prohibited
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A POSTROUTING -s fd6c:62d9:eb8c::/112 -j MASQUERADE
COMMIT" > /tmp/ip6tables

#start services

if cat /etc/*release | grep ^NAME | grep CentOS; then
     cp /tmp/ip6tables /etc/sysconfig/ip6tables
     cp /tmp/iptables /etc/sysconfig/iptables
     systemctl enable iptables & systemctl start iptables
     systemctl enable ip6tables & systemctl start ip6tables
     systemctl enable openvpn@server & systemctl start openvpn@server
     systemctl restart iptables & systemctl restart ip6tables
elif cat /etc/*release | grep ^NAME | grep Ubuntu; then
     cp /tmp/ip6tables /etc/iptables/rules.v6
     cp /tmp/iptables /etc/iptables/rules.v4
     systemctl enable netfilter-persistent & systemctl start netfilter-persistent
     systemctl enable openvpn@server & systemctl start openvpn@server
     systemctl restart netfilter-persistent
fi

#generate client config

echo -e "client
dev tun
dev-type tun

#bind to interface if needed
#dev-node \042Ethernet 4\042

ns-cert-type server
setenv opt tls-version-min 1.0 or-highest
#block local dns
setenv opt block-outside-dns
nobind

remote $EIP $PORTN $PORTL 

cipher $CIPHER
auth SHA256

resolv-retry infinite
persist-key
persist-tun
comp-lzo
mssfix 0
verb 3
ping 10
tls-client
float" >> /etc/openvpn/client.ovpn

#generate bash script to create one-file config for clients

echo -e "#! /bin/bash
# Script to automate creating new OpenVPN clients
#
# H Cooper - 05/02/11
# Y Frolov - 08/06/16 - bundle config added (unified format)
# Usage: newclient.sh <common-name>

echo \042Script to generate unified config for Windows App\042
echo \042sage: newclient.sh <common-name>\042

# Set vars
OPENVPN_DIR=/etc/openvpn
OPENVPN_RSA_DIR=/etc/openvpn/easy-rsa
OPENVPN_KEYS=\044OPENVPN_RSA_DIR/keys
BUNDLE_DIR=/etc/openvpn/bundles

# Either read the CN from \0441 or prompt for it
if [ -z \042\0441\042 ]
    then echo -n \042Enter new client common name (CN): \042
    read -e CN
else
    CN=\u00241
fi

# Ensure CN isn't blank
if [ -z \042\044CN\042 ]
    then echo \042You must provide a CN.\042
    exit
fi

# Check the CN doesn't already exist
if [ -f \044OPENVPN_KEYS/\044CN.crt ]
    then echo \042Error: certificate with the CN \044CN alread exists!\042
    echo \042    \044OPENVPN_KEYS/\044CN.crt\042
    exit
fi

# Establish the default variables
export EASY_RSA=\042/etc/openvpn/easy-rsa\042
export OPENSSL=\042openssl\042
export PKCS11TOOL=\042pkcs11-tool\042
export GREP=\042grep\042
export KEY_CONFIG=\x60\044EASY_RSA/whichopensslcnf \044EASY_RSA\x60
export KEY_DIR=\042\044EASY_RSA/keys\042
export PKCS11_MODULE_PATH=\042dummy\042
export PKCS11_PIN=\042dummy\042
export KEY_SIZE=2048
export CA_EXPIRE=3650
export KEY_EXPIRE=1825
export KEY_COUNTRY=\042US\042
export KEY_PROVINCE=\042CA\042
export KEY_CITY=\042SanFrancisco\042
export KEY_ORG=\042Fort-Funston\042
export KEY_EMAIL=\042my@vpn.net\042
export KEY_OU=\042MyVPN\042
export KEY_NAME=\042EasyRSA\042

# Copied from build-key script (to ensure it works!)
export EASY_RSA=\042\044{EASY_RSA:-.}\042
\042\044EASY_RSA/pkitool\042 --batch \044CN

# Add all certs to unified client config file

# Default config for client
cp \044OPENVPN_DIR/client.ovpn \044BUNDLE_DIR/\044CN.ovpn

# CA
echo \042<ca>\042  >> \044BUNDLE_DIR/\044CN.ovpn
cat \044OPENVPN_KEYS/ca.crt >> \044BUNDLE_DIR/\044CN.ovpn
echo \042</ca>\042 >> \044BUNDLE_DIR/\044CN.ovpn

# Client cert
echo \042<cert>\042 >> \044BUNDLE_DIR/\044CN.ovpn
cat \044OPENVPN_KEYS/\044CN.crt >> \044BUNDLE_DIR/\044CN.ovpn
echo \042</cert>\042 >> \044BUNDLE_DIR/\044CN.ovpn

# Client key
echo \042<key>\042 >> \044BUNDLE_DIR/\044CN.ovpn
cat \044OPENVPN_KEYS/\044CN.key >> \044BUNDLE_DIR/\044CN.ovpn
echo \042</key>\042 >> \044BUNDLE_DIR/\044CN.ovpn

if openvpn --version | grep 2.3; then
    # ta tls auth OpenVPN 2.3.x
    echo \042key-direction 1\042 >> \044BUNDLE_DIR/\044CN.ovpn
    echo \042<tls-auth>\042  >> \044BUNDLE_DIR/\044CN.ovpn
    cat \044OPENVPN_KEYS/ta.key >> \044BUNDLE_DIR/\044CN.ovpn
    echo \042</tls-auth>\042 >> \044BUNDLE_DIR/\044CN.ovpn
else
    # ta tls crypt OpenVPN 2.4.x
    echo \042<tls-crypt>\042  >> \044BUNDLE_DIR/\044CN.ovpn
    cat \044OPENVPN_KEYS/ta.key >> \044BUNDLE_DIR/\044CN.ovpn
    echo \042</tls-crypt>\042 >> \044BUNDLE_DIR/\044CN.ovpn
fi

# DH key
echo \042<dh>\042 >> \044BUNDLE_DIR/\044CN.ovpn
cat \044OPENVPN_KEYS/dh.pem >> \044BUNDLE_DIR/\044CN.ovpn
echo \042</dh>\042 >> \044BUNDLE_DIR/\044CN.ovpn

#echo \042\042
echo \042COMPLETE! Copy the new unified config from here: /etc/openvpn/bundles/\044CN.ovpn\042" > /etc/openvpn/newclient.sh
chmod +x /etc/openvpn/newclient.sh

echo "Setup is complete. Happy VPNing!"
echo "Use /etc/openvpn/newclient.sh to generate client config"

exit 1
