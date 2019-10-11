#!/bin/bash
#####################################################################
#
# bootstrap.sh
# -------------------
# Configures Debian / Ubuntu to be a set-and-forget Tor relay.
#
#####################################################################

PWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

set -e

INSTALL_PACKAGES=()
STOP_SERVICES=()

# check for root
function check_root () {
    if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root (use su / sudo)" 1>&2
    	exit 1
    fi
}

# suggest user account
function suggest_user () {
    ORIG_USER=$(logname)
    if [ "$ORIG_USER" == "root" ]; then
	echo "It appears that you have logged into this machine as root. If you would like to disable remote root access, create a user account and use su / sudo to run bootstrap.sh."
	echo "Would you like to continue and allow remote root access? [y/n]"
	read useroot
	if [ "$useroot" != "y" ]; then
	    exit 1
	fi
    fi
}

# install mandatory packages for add_tor_sources
function install_requirements() {
    echo "== Updating software"
    apt-get update
    apt-get install -y lsb-release apt-transport-tor gpg dirmngr curl
}

# add official Tor repository and Debian onion service mirrors
function add_tor_sources() {
    APT_SOURCES_FILE="/etc/apt/sources.list.d/torproject.list"
    DISTRO=$(lsb_release -si)
    SID=$(lsb_release -cs)
    if [ "$DISTRO" == "Debian" -o "$DISTRO"=="Ubuntu" ]; then
	echo "== Removing previous sources"
	rm -f $APT_SOURCES_FILE
	echo "== Adding the official Tor repository"
	echo "deb tor+http://sdscoq7snqtznauu.onion/torproject.org `lsb_release -cs` main" >> $APT_SOURCES_FILE
	curl https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
	gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -
	if [ "$DISTRO" == "Debian" ]; then
	    echo "== Switching to Debian's onion service mirrors"
	    echo "deb tor+http://vwakviie2ienjx6t.onion/debian `lsb_release -cs` main" >> $APT_SOURCES_FILE
	    if [ "$SID" != "sid" ]; then
		echo "deb tor+http://vwakviie2ienjx6t.onion/debian `lsb_release -cs`-updates main">> $APT_SOURCES_FILE
		echo "deb tor+http://sgvtcaew4bxjd7ln.onion/debian-security `lsb_release -cs`/updates main" >> $APT_SOURCES_FILE
	    fi
	fi
    else
	echo "You do not appear to be running Debian or Ubuntu"
	exit 1
    fi
}

# install tor
function register_install_tor() {
    echo "== Installing Tor"
    INSTALL_PACKAGES+=("tor")
    INSTALL_PACKAGES+=("deb.torproject.org-keyring")
    STOP_SERVICES+=(tor)
}

function configure_tor() {
    TEMPLATE=$1
    NB_INSTANCES=$2
    echo "== Configuring Tor"

    create_instances $TEMPLATE $NB_INSTANCES

    service tor restart
    echo "== Waiting for Tor Socks5 service to be ready"
    while ! echo -e 'PROTOCOLINFO\r\n' | nc 127.0.0.1 9050  | grep -qa tor; do
	sleep 1
    done
}

# create tor instance
function create_instance() {
    TEMPLATE=$1
    instance=$2
    INSTANCE_NAME="${TEMPLATE}$((instance+1))"
    echo "== Creating Tor Instance ${INSTANCE_NAME}"
    tor-instance-create $INSTANCE_NAME
    cp $PWD/etc/tor/torrc.$TEMPLATE /etc/tor/instances/$INSTANCE_NAME/torrc
    orport=$((instance+9001))
    dirport=$((instance+9030))
    socksport=$((instance+9050))
    sed -i "s/ORPort .*/ORPort ${orport}/" /etc/tor/instances/$INSTANCE_NAME/torrc
    sed -i "s/DirPort .*/DirPort ${dirport}/" /etc/tor/instances/$INSTANCE_NAME/torrc
    sed -i "s/SocksPort .*/SocksPort ${socksport}/" /etc/tor/instances/$INSTANCE_NAME/torrc
}

# create one or more tor instances
function create_instances() {
    TEMPLATE=$1
    NB_INSTANCES=$2
    instance=0
    while [ $instance -lt $NB_INSTANCES ]; do
	create_instance $TEMPLATE $instance
	instance=$((instance+1))
    done
}

# create firewall rule for a single instance
function instance_rules() {
    return
    #TODO: handle ipv6
    instance=$1
    # insert rules after ## allow Tor ORPort, DirPort
    orport=$((instance+9001))
    dirport=$((instance+9030))
    sed -i "/## allow Tor ORPort, DirPort/ \
            -A INPUT -p tcp --dport $orport -j ACCEPT \
	    -A INPUT -p tcp --dport $dirport -j ACCEPT" /etc/iptables/rule.v4
}

function register_install_firewall() {
    echo "== Installing firewall"
    INSTALL_PACKAGES+=("debconf-utils")
    INSTALL_PACKAGES+=("iptables")
    INSTALL_PACKAGES+=("iptables-persistent")
}

# configure firewall rules
function configure_firewall() {
    #TODO: handle NB_INSTANCES
    NB_INSTANCES=$1
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    cp $PWD/etc/iptables/rules.v4 /etc/iptables/rules.v4
    cp $PWD/etc/iptables/rules.v6 /etc/iptables/rules.v6
    #remove the COMMIT command from templates
    sed -i '/COMMIT/d' /etc/iptables/rule.v4 /etc/iptables/rule.v6
    # for each instance call instance_rules
    instance=0
    while [ $instance -lt $NB_INSTANCES ]; do
	orport=$((instance+9001))
	dirport=$((instance+9030))
	echo "-A INPUT -p tcp --dport $orport -j ACCEPT \
	      -A INPUT -p tcp --dport $dirport -j ACCEPT" >> /etc/iptables/rule.v4
	echo "-A INPUT -p tcp --dport $orport -j ACCEPT \
	      -A INPUT -p tcp --dport $dirport -j ACCEPT" >> /etc/iptables/rule.v6
    done
    #re-add the COMMIT command at the end of config files
    echo "COMMIT" >> /etc/iptables/rule.v4
    echo "COMMIT" >> /etc/iptables/rule.v6
    chmod 600 /etc/iptables/rules.v4
    chmod 600 /etc/iptables/rules.v6
    iptables-restore < /etc/iptables/rules.v4
    ip6tables-restore < /etc/iptables/rules.v6
}

function register_install_f2b() {
    echo "== Installing fail2ban"
    INSTALL_PACKAGES+=("fail2ban")
}

function configure_f2b() {
    return
}

function register_install_auto_update() {
    echo "== Installing unattended upgrades"
    INSTALL_PACKAGES+=("unattended-upgrades")
    INSTALL_PACKAGES+=("apt-listchanges")
    STOP_SERVICES+=("unattended-upgrades")
}

# configure automatic updates
function configure_auto_update() {
    echo "== Configuring unattended upgrades"
    cp $PWD/etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades
}

# install apparmor
function register_install_aa() {
    echo "== Installing AppArmor"
    INSTALL_PACKAGES+=("apparmor")
    INSTALL_PACKAGES+=("apparmor-profiles")
    INSTALL_PACKAGES+=("apparmor-utils")
}

# configure apparmor
function configure_aa() {
    echo "== Configuring AppArmor"
    sed -i.bak 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 apparmor=1 security=apparmor"/' /etc/default/grub
    update-grub
}

# install ntp
function register_install_ntp() {
    echo "== Installing ntp"
    INSTALL_PACKAGES+=("ntp")
}

# configure ntp
function configure_ntp() {
    return
}

# install sshd
function register_install_sshd() {
    echo "== Installing openssh-server"
    INSTALL_PACKAGES+=("openssh-server")
}

# configure sshd
function configure_sshd() {
    SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
    if [ -n "$ORIG_USER" ]; then
	echo "== Configuring sshd"
	# only allow the current user to SSH in
	if ! grep -q "AllowUsers $ORIG_USER" $SSHD_CONFIG_FILE; then
	    echo "" >> $SSHD_CONFIG_FILE
	    echo "AllowUsers $ORIG_USER" >> $SSHD_CONFIG_FILE
	    echo "  - SSH login restricted to user: $ORIG_USER"
	fi
	if grep -q "Accepted publickey for $ORIG_USER" /var/log/auth.log; then
	    # user has logged in with SSH keys so we can disable password authentication
	    sed -i '/^#\?PasswordAuthentication/c\PasswordAuthentication no' $SSHD_CONFIG_FILE
	    echo "  - SSH password authentication disabled"
	    if [ $ORIG_USER == "root" ]; then
		# user logged in as root directly (rather than using su/sudo) so make sure root login is enabled
		sed -i '/^#\?PermitRootLogin/c\PermitRootLogin yes' $SSHD_CONFIG_FILE
	    fi
	else
	    # user logged in with a password rather than keys
	    echo "  - You do not appear to be using SSH key authentication.  You should set this up manually now."
	fi
	service ssh reload
    else
	echo "== Could not configure sshd automatically.  You will need to do this manually."
    fi
}

# install unbound
function register_install_unbound() {
    echo "== Installing Unbound"
    INSTALL_PACKAGES+=("unbound")
    STOP_SERVICES+=(unbound)
}

# configure unbound
function configure_unbound() {
    echo "== Configuring Unbound"
    cp $PWD/etc/unbound/unbound.conf /etc/unbound/unbound.conf

    # set system to use only local DNS resolver
    #    chattr -i /etc/resolv.conf
    sed -i 's/^nameserver/#nameserver/g' /etc/resolv.conf
    if grep -q "127.0.0.1" /etc/resolv.conf; then
	echo "nameserver 127.0.0.1" >> /etc/resolv.conf
    fi
    #    chattr +i /etc/resolv.conf
}

# install tor-arm
function register_install_tor_arm() {
    echo "== Installing Tor-Arm"
    INSTALL_PACKAGES+=("tor-arm")
}

function configure_tor_arm() {
    return
}

# install monit
function register_install_monit() {
    if apt-cache search ^monit$ 2>&1 | grep -q monit; then
	echo "== Installing monit"
	INSTALL_PACKAGES+=("monit")
	STOP_SERVICES=("monit")
    fi
}

# configure monit
function configure_monit() {
    if dpkg --get-selections monit | grep -q monit; then
	echo "== Configuring monit"
	cp $PWD/etc/monit/conf.d/tor-relay.conf /etc/monit/conf.d/tor-relay.conf
    fi
}

# install pip for nyx
function register_install_pip() {
    echo "== Installing pip"
    INSTALL_PACKAGES+=("python-pip")
}

# pip install nyx
function pip_install_nyx() {
    echo "== Pip Installing Nyx"
    pip install nyx
}

function install_packages() {
    apt-get install -y "${INSTALL_PACKAGES[@]}"
}

function stop_services() {
    for i in "${STOP_SERVICES[@]}"
    do
	service $i stop
    done
}

function restart_services() {
    for i in "${STOP_SERVICES[@]}"
    do
	service $i restart
    done
}

# final instructions
function print_final() {
    echo ""
    echo "== Try SSHing into this server again in a new window, to confirm the firewall isn't broken"
    echo ""
    echo "== Edit /etc/tor/torrc"
    echo "  - Set Address, Nickname, Contact Info, and MyFamily for your Tor relay"
    echo "  - Optional: include a Bitcoin address in the 'ContactInfo' line"
    echo "    - This will enable you to receive donations from OnionTip.com"
    echo "  - Optional: limit the amount of data transferred by your Tor relay (to avoid additional hosting costs)"
    echo "    - Uncomment the lines beginning with '#AccountingMax' and '#AccountingStart'"
    echo ""
    echo "== If you are running Ubuntu (We do this automatically in Debian), consider having ${APT_SOURCES_FILE} update over HTTPS and/or HTTPS+Tor"
    echo "   see https://guardianproject.info/2014/10/16/reducing-metadata-leakage-from-software-updates/"
    echo "   for more details"
    echo ""
    echo "== REBOOT THIS SERVER"
}

TEMPLATE="proxy"
NB_INSTANCES=1
while getopts "t:m:h" opt; do
    case ${opt} in
	h )
	    echo "Usage:"
	    echo "    -h                      Display this help message."
	    echo "    -t TEMPLATE             Select TEMPLATE [proxy|relay|exit|bridge] to use."
	    echo "    -m %d                   Configure multiple instances."
	    exit 0
	    ;;
	t )
	    TEMPLATE=$OPTARG
	    ;;
	m )
	    NB_INSTANCES=$OPTARG
	    ;;
	\? )
	    echo "Invalid Option: -$OPTARG" 1>&2
	    exit 1
	    ;;
    esac
done
shift $((OPTIND -1))

check_root
suggest_user 
install_requirements
add_tor_sources

register_install_tor
register_install_firewall
register_install_f2b
register_install_auto_update
register_install_aa
register_install_ntp
register_install_sshd
register_install_unbound
register_install_tor_arm
register_install_monit
register_install_pip

install_packages
stop_services

configure_tor $TEMPLATE $NB_INSTANCES
apt-get update #Reupdate packages with Tor network repos

configure_firewall $NB_INSTANCES
configure_f2b
configure_auto_update
configure_aa
configure_ntp
configure_sshd
configure_unbound
configure_tor_arm
configure_monit
pip_install_nyx

restart_services

print_final
