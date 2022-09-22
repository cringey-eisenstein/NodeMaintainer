# NodeMaintainer

# This script is intended to run continuously inside a virtual machine, and thereby help maintain a mesh wireguard network comprised of the host VM and many other hosts accessible via the public internet.

The script needs as a command-line argument a JSON file containing seed nodes, each set up using the steps at the top of the file. Example node file is on the way. It uses a mesh of websocket connections to share the state of the each member node with the other members. The state also includes Wireguard public keys, enabling the wireguard mesh to also be maintained. In Ubuntu 20.04, the (earlier version) of the script can be run with all TCP ports closed and a single open UDP port - achieved using fwknop. I am trying to get this to work on Fedora CoreOS 36 but am currently running into issues with fwknop, iptables and/or their interaction with CoreOS.
