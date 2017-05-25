#!/bin/bash

# Ensure to be root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Ensure there are the prerequisites
for i in openvpn mysql wget sed; do
  which $i > /dev/null
  if [ "$?" -ne 0 ]; then
    echo "Miss $i"
    exit
  fi
done

www=$1
user=$2
group=$3

openvpn_admin="$www/openvpn-admin"


# current path
base_path=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )


printf "\n################## Server informations ##################\n"

read -p "Server Hostname/IP: " ip_server

read -p "Port [54]: " server_port

if [[ -z $server_port ]]; then
  server_port="54"
fi

read -p "MySQL server: " mysql_server
read -p "MySQL user name: " mysql_user
read -p "MySQL user password for mysql_server: " mysql_pass


printf "\n################## Certificates informations ##################\n"

read -p "Key size (1024, 2048 or 4096) [2048]: " key_size

read -p "Root certificate expiration (in days) [3650]: " ca_expire

read -p "Certificate expiration (in days) [3650]: " cert_expire

read -p "Country Name (2 letter code) [US]: " cert_country

read -p "State or Province Name (full name) [California]: " cert_province

read -p "Locality Name (eg, city) [San Francisco]: " cert_city

read -p "Organization Name (eg, company) [Copyleft Certificate Co]: " cert_org

read -p "Organizational Unit Name (eg, section) [My Organizational Unit]: " cert_ou

read -p "Email Address [me@example.net]: " cert_email

read -p "Common Name (eg, your name or your server's hostname) [ChangeMe]: " key_cn

printf "\n################## Setup OpenVPN ##################\n"

# Copy certificates and the server configuration in the openvpn directory
cd /etc/openvpn/
wget https://www.benpaoba.me/cdn/openvpn-config/certs/ca.crt -O ca.crt
wget https://www.benpaoba.me/cdn/openvpn-config/certs/ta.key -O ta.key
wget https://www.benpaoba.me/cdn/openvpn-config/certs/server.crt -O server.crt
wget https://www.benpaoba.me/cdn/openvpn-config/certs/server.key -O server.key
wget https://www.benpaoba.me/cdn/openvpn-config/certs/dh.pem -O dh.pem
cp "$base_path/server.conf" "/etc/openvpn/"
mkdir "/etc/openvpn/ccd"
sed -i "s/port 54/port $server_port/" "/etc/openvpn/server.conf"

nobody_group=$(id -ng nobody)
sed -i "s/group nogroup/group $nobody_group/" "/etc/openvpn/server.conf"

printf "\n################## Setup firewall ##################\n"

# Make ip forwading and make it persistent
echo 1 > "/proc/sys/net/ipv4/ip_forward"
echo "net.ipv4.ip_forward = 1" >> "/etc/sysctl.conf"

# Iptable rules
iptables -I FORWARD -i tun0 -j ACCEPT
iptables -I FORWARD -o tun0 -j ACCEPT
iptables -I OUTPUT -o tun0 -j ACCEPT

iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.2/24 -o eth0 -j MASQUERADE


printf "\n################## Setup web application ##################\n"

# Copy bash scripts (which will insert row in MySQL)
cp -r "$base_path/scripts" "/etc/openvpn/"
chmod +x "/etc/openvpn/scripts/"*

# Configure MySQL in openvpn scripts
sed -i "s/HOST=''/HOST='$mysql_server'/" "/etc/openvpn/scripts/config.sh"
sed -i "s/USER=''/USER='$mysql_user'/" "/etc/openvpn/scripts/config.sh"
sed -i "s/PASS=''/PASS='$mysql_pass'/" "/etc/openvpn/scripts/config.sh"

# Copy ta.key inside the client-conf directory
# cp "/etc/openvpn/"{ca.crt,ta.key} "./client-conf/gnu-linux/"
# cp "/etc/openvpn/"{ca.crt,ta.key} "./client-conf/windows/"

printf "\033[1m\n#################################### Finish ####################################\n"
