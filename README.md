tor-relay-bootstrap
===================

This is a script to bootstrap a Debian server to be a set-and-forget Tor relay. It should work on any modern Debian or Ubuntu version. Pull requests are welcome.

tor-relay-bootstrap does this:

* Upgrades all software on the system
* Installs apt-transport-tor
* Configures apt sources to use Debian's onion service mirrors (Debian only)
* Adds the deb.torproject.org (onion) repository to apt, so Tor updates will come directly from the Tor Project
* Installs and configures Tor to be a relay (but still requires you to manually edit torrc to set Nickname, ContactInfo, etc. for this relay)
* Allows you to configure multiple Tor instances for high bandwidth connections
* Configures sane default firewall rules
* Configures automatic updates
* Installs ntp to ensure time is synced
* Installs monit and activate config to auto-restart all services
* Installs unbound to reduce the number DNS queries leaving the node
* Helps harden the ssh server
* Gives instructions on what the sysadmin needs to manually do at the end

To use it, set up a Debian or Ubuntu server, SSH into it, and:

```sh
sudo apt install -y git
git clone https://github.com/Sixdsn/tor-relay-bootstrap.git
sudo ./bootstrap.sh
Usage:
    -h                      Display this help message.
    -t TEMPLATE             Select TEMPLATE [proxy|relay|exit|bridge] to use.
    -i INSTALL              Select INSTALL [toronly|minimal|standard|full|cleanup] profile.
    -m %d                   Configure multiple instances.
    -p POSTINST_SCRIPT      Call a post installation script.
```

New featues:
 * cmdline options:
  + Template to specify a type of relay to configure[proxy|relay|exit|bridge]
  + Install to specify which softwares you want to install and configure [toronly|minimal|standard|full]
  + Number of Tor instances to configure at start (max of 2 is recommended)
  + Post Install script
  + Cleanup option to remove almost everything from previous installation
 
 
 * does only apt-get twice, onmce for requirements and the second one with all packages to install
 * configures dynamically iptables ports for multiple instances
 * fixes most of issues reported in the original fork
