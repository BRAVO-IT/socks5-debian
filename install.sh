#!/bin/bash
# Simple Dante Socks5 Script for Debian
# Script by BRAVO_IT
# https://github.com/BRAVO-IT/VPN
#

function YourBanner(){
# Edit nyo to
 echo -e " Welcome to my Script"
 echo -e " SOCKS5 Server Installer for Debian"
 echo -e " Script by BRAVO_IT"
 echo -e " This script is open for Remodification and Redistribution"
 echo -e ""
}

function get_external_address() {
	local addr=$( timeout 3 dig +short myip.opendns.com @resolver1.opendns.com || \
	timeout 3 curl -s http://ipecho.net/plain || \
	timeout 3 curl -s http://ident.me/ || \
	timeout 3 curl -s http://whatismyip.akamai.com/ )
	[ $? -ne 0 ] && addr="<this server IP address>"
	echo "$addr"
}

# args: file user password
function generate_password_file() {
	# -1    generate md5-based password hash
	echo "$2:$( openssl passwd -1 "$3" )" > "$1"
}

# args: file; generates: file.db
function generate_password_dbfile() {
	awk -F: '{print $1; print $2}' < "$1" | db_load -T -t hash "${1}.db"
}

# args: file pwdfile
function generate_pam() {
# nodelay: don't cause a delay on auth failure. Anti-DDOS
cat > "$1" << EOF
auth required pam_pwdfile.so nodelay pwdfile=$2
account required pam_permit.so
EOF
}

# args: file pwdfile
function generate_pam_userdb() {
# Note that the path to the database file should be specified without the .db suffix
cat > "$1" << EOF
auth required pam_userdb.so db=$2 crypt=crypt
account required pam_permit.so
EOF
}

# args: file interface port
function generate_config_v11() {
cat > "$1" << EOF
internal: $2 port=$3
external: $2

method: pam

source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 YourBanner
 echo -e "[\e[1;31mError\e[0m] This script is for Debian Machine only, exting..." 
 exit 1
fi

if [[ $EUID -ne 0 ]];then
 YourBanner
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

function Installation(){
 cd /root
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 apt-get install wget nano dante-server netcat -y &> /dev/null | echo '[*] Installing SOCKS5 Server...'
	generate_password_file /etc/danted.passwd "$USER" "$PASSWORD"

	generate_pam /etc/pam.d/sockd /etc/danted.passwd

	generate_config_v11 /etc/danted.conf "$IFACE" "$PORT"

	open_ufw_port "$PORT"
 cat <<'EOF'> /etc/danted.conf
logoutput: /var/log/socks.log
internal: 0.0.0.0 port = SOCKSPORT
external: SOCKSINET
socksmethod: SOCKSAUTH
user.privileged: root
user.notprivileged: nobody

client pass {
 from: 0.0.0.0/0 to: 0.0.0.0/0
 log: error connect disconnect
 }
 
client block {
 from: 0.0.0.0/0 to: 0.0.0.0/0
 log: connect error
 }
 
socks pass {
 from: 0.0.0.0/0 to: 0.0.0.0/0
 log: error connect disconnect
 }
 
socks block {
 from: 0.0.0.0/0 to: 0.0.0.0/0
 log: connect error
 }
EOF
}

# args: file interface port
function generate_config_v14() {
cat > "$1" <<EOF
# https://www.inet.no/dante/doc/1.4.x/config/ipv6.html
internal.protocol: ipv4 ipv6
internal: $2 port=$3
external.protocol: ipv4 ipv6
external: $2

socksmethod: pam.any

user.privileged: root
user.notprivileged: nobody

client pass {
        from: 0.0.0.0/0 to: 0.0.0.0/0
        log: error
}

client pass {
        from: ::/0 to: ::/0
        log: error
}

# deny proxied to loopback
socks block {
    from: 0.0.0.0/0 to: 127.0.0.0/8
    log: error
}

socks block {
    from: ::/0 to: ::1/128
    log: error
}

socks pass {
        from: 0.0.0.0/0 to: 0.0.0.0/0
        log: error
}
EOF
}

# args: file interface port
function generate_systemd_file() {
cat > "$1" <<EOF
# /etc/systemd/system/sockd.service
[Unit]
Description=Dante Socks5 Daemon
After=network.target

[Service]
Type=forking
PIDFile=/var/run/sockd.pid
ExecStart=/usr/sbin/sockd -D -f /etc/sockd.conf
ExecReload=/bin/kill -HUP \${MAINPID}
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
Alias=danted.service
EOF
}
IFACE=$(ip route get 8.8.8.8 | head -1 | cut -d' ' -f5)

[ -z "$USER" ] && export USER=user
[ -z "$PORT" ] && export PORT=8080
[ -z "$PASSWORD" ] && export PASSWORD=$( cat /dev/urandom | tr --delete --complement 'a-z0-9' | head --bytes=10 )

[ -e /etc/lsb-release ] && source /etc/lsb-release
[ -e /etc/os-release ] && source /etc/os-release
 sed -i "s/SOCKSINET/$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)/g" /etc/danted.conf
 sed -i "s/SOCKSPORT/$SOCKSPORT/g" /etc/danted.conf
 sed -i "s/SOCKSAUTH/$SOCKSAUTH/g" /etc/danted.conf
 sed -i '/\/bin\/false/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 systemctl restart danted.service
 systemctl enable danted.service
}
 
function Uninstallation(){
 echo -e '[*] Uninstalling SOCKS5 Server'
 apt-get remove --purge dante-server &> /dev/null
 rm -rf /etc/danted.conf
 echo -e '[√] SOCKS5 Server successfully uninstalled and removed.'
}

function SuccessMessage(){
 clear
 echo -e ""
 YourBanner
 echo -e ""
 echo -e "== Success installed SOCKS5 Server into your VPS =="

	echo "Your socks proxy configuration:"
	echo "Address: $( get_external_address )"
	echo "Port: $PORT"
	echo "User: $USER"
	echo "Password: $PASSWORD"
	echo "Any question contact telegram @BRAVO_IT"
 fi
 echo -e " Install.txt can be found at /root/socks5.txt"
 cat <<EOF> ~/socks5.txt
==Your SOCKS5 Proxy Information==
IP Address: $(wget -4qO- http://ipinfo.io/ip)
Port: $SOCKSPORT
EOF
 if [ "$SOCKSAUTH" == 'username' ]; then
 cat <<EOF>> ~/socks5.txt
Username: $socksUser
Password: $socksPass
EOF
 fi
 cat ~/socks5.txt | nc termbin.com 9999 > /tmp/walwal.txt
 echo -e " Your SOCKS5 Information Online: $(tr -d '\0' </tmp/walwal.txt)"
 echo -e ""
}

clear
YourBanner
echo -e " To exit the script, kindly Press \e[1;32mCRTL\e[0m key together with \e[1;32mC\e[0m"
echo -e ""
echo -e " Choose SOCKS5 Proxy Type"
echo -e " [1] Public Proxy (Can be Accessible by Anyone in the Internet)"
echo -e " [2] Private Proxy (Can be Accessable using username and password Authentication"
echo -e " [3] Uninstall SOCKS5 Proxy Server"
until [[ "$opts" =~ ^[1-3]$ ]]; do
	read -rp " Choose from [1-3]: " -e opts
	done

	case $opts in
	1)
	until [[ "$SOCKSPORT" =~ ^[0-9]+$ ]] && [ "$SOCKSPORT" -ge 1 ] && [ "$SOCKSPORT" -le 65535 ]; do
	read -rp " Choose your SOCKS5 Port [1-65535]: " -i 2408 -e SOCKSPORT
	done
	SOCKSAUTH='none'
	Installation
	;;
	2)
	until [[ "$SOCKSPORT" =~ ^[0-9]+$ ]] && [ "$SOCKSPORT" -ge 1 ] && [ "$SOCKSPORT" -le 65535 ]; do
	read -rp " Choose your SOCKS5 Port [1-65535]: " -i 2408 -e SOCKSPORT
	done
	SOCKSAUTH='username'
	until [[ "$socksUser" =~ ^[a-zA-Z0-9_]+$ ]]; do
	read -rp " Your SOCKS5 Username: " -e socksUser
	done
	until [[ "$socksPass" =~ ^[a-zA-Z0-9_]+$ ]]; do
	read -rp " Your SOCKS5 Password: " -e socksPass
	done
	userdel -r -f $socksUser &> /dev/null
	useradd -m -s /bin/false $socksUser
	echo -e "$socksPass\n$socksPass\n" | passwd $socksUser &> /dev/null
	Installation
	;;
	3)
	Uninstallation
	exit 1
	;;
esac
SuccessMessage
exit 1
