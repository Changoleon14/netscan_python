#!/bin/bash

# We are going to set up iptables rules to disable the automatic reset of TCP connections
# there is a common issue when using scapy and it is that for example when we want to manually
# create a 3 way handshake, when the server reply with the synack packet the kernel does not know
# about that connection since scapy creates its own socket, so the kernel thinks it is an unknown
# connection so it sends a RST message back. Similar when we perform an ack scan.
# The scapy official documentation says this is a common issue and that we can use a local firewall
# to work around this issue.
# The only problem of that approach is that, from my point of view, if we set only one port it is
# not very realistic. Because when we use Randshort we get a random port each time. And in theory
# every TCP conection it is unikley identified by the 4 numbers, (source and destination IP and
# ports). So if we only can use one port it is not very realistic.

# Disable the automatic reset of TCP connections
sudo iptables -A OUTPUT -p tcp --sport 54000:55000 --tcp-flags RST RST -j DROP


# ----------------------------- RollBack -----------------------------
# After running the tool we should rollback this setting

# To make sure to delete this rules we can do this:
# sudo iptables -L OUTPUT --line-numbers

# delete each line
# sudo iptables -D OUTPUT <número>