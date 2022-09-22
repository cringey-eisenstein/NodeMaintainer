# NodeMaintainer

# This script is intended to run continuously inside a virtual machine, and thereby help maintain a mesh wireguard network comprised of the host VM and many other hosts accessible via the public internet.

The script needs as a command-line argument a JSON file containing seed nodes, each set up using the steps at the top of the file. Example node file is on the way. It uses a mesh of websocket connections to share the state of the each member node with the other members. The state also includes Wireguard public keys, enabling the wireguard mesh to also be maintained. In Ubuntu 20.04, the (earlier version) of the script can be run with all TCP ports closed and a single open UDP port - achieved using fwknop. I am trying to get this to work on Fedora CoreOS 36 but am currently running into issues with fwknop, iptables and/or their interaction with CoreOS.

# Why would you want to make such a network?

To fight fascism; in other words, to prevent, avoid, undermine, subvert, or negate the celebration of violence, domination, authoritarianism, and a "might makes right" ethos manifesting throughout society (but issuing more prominently in some places than others, such as chokepoint capitalism).

More concretely, an "Antifascist Kubernetes Cluster" could be run over the wireguard network described above, and used to support projects for social reproduction, justice, learning, or creativity.

Typically, k8s is run within a single data center, or multiple facilities that are geographically distributed, but linked via private, dedicated, high-bandwidth network connections. This architecture is great for the companies who own such infrastructure, but the benefits to consumers might not have always been explained with complete objectivity.
