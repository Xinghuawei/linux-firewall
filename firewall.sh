#!/bin/bash
#Firewall host interface
INET_NIC="eno1"
INET_IP="192.168.0.5"
INET_GATEWAY_IP="192.168.0.100"
INET_NET="192.168.0.0/24"

#Local interface
LOC_NIC="enp2s0"
LOC_GATEWAY_IP="10.0.0.1"
LOC_NET="10.0.0.0/24"
LOC_NETMASK="255.255.255.0"

#Client interface
CLIENT_NIC="enp2s0"
CLIENT_IP="10.0.0.2"
CLIENT_NETMASK="255.255.255.0"
CLIENT_GATEWAY_IP=$LOC_GATEWAY_IP


TCP_ALLOW="22 2222 443"
UDP_ALLOW="53 2222"
ICMP_ALLOW="0 8"

HIGH_PORT="1023:65535"

TCP_BLOCK="23 32768:32775 137:139 111 515"
UDP_BLOCK="23 32768:32775 137:139"

function flush(){
    echo 'Flash all rules'
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t mangle -F
    ip route flush table main
    }

    
function default_rule(){
    echo "Set default policy to DROP..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    }

function client(){
    
    echo "Configuring client internet environment..."
    
    echo "nameserver 142.232.76.191" >> /etc/resolv.conf
    ifconfig eno1 down
    ifconfig $CLIENT_NIC down
    ifconfig $CLIENT_NIC $CLIENT_IP up
    route add default gw $CLIENT_GATEWAY_IP
    
    echo "Client Configuration done..."
    }

function firewall(){
    
    echo "Configuring firewall internet environment..."
    
    echo "flushing existing rules and tables..."
    flush
    
    echo "1" > /proc/sys/net/ipv4/ip_forward
    ifconfig $LOC_NIC $LOC_GATEWAY_IP up
    ip route add $INET_NET dev $INET_NIC
    route add default gw $INET_GATEWAY_IP 
    route add -net $LOC_NET gw $LOC_GATEWAY_IP
    
    }

function prerouting(){
    echo "Set prerouting rule..."
    
    iptables -t nat -A PREROUTING -i $INET_NIC -j DNAT -d $INET_IP --to-destination $CLIENT_IP
    
    }
    
function postrouting(){
    echo "Set postrouting rule..."
    
    iptables -t nat -A POSTROUTING -o $INET_NIC -j SNAT --to-source $INET_IP
    }


    
function forward(){
    echo "Create FORWARD chain..."
    
    #drop telnet
    #iptables -A FORWARD -i $INET_NIC -p tcp --dport 23 -j DROP
    #iptables -A FORWARD -i $INET_NIC -p udp --dport 23 -j DROP
    
    #DROP all syn fin
    iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST SYN,FIN -j DROP
    
    #drop all high ports
    iptables -A FORWARD -i $INET_NIC -p tcp --dport $HIGH_PORT --tcp-flags SYN,ACK,FIN,RST SYN,FIN -j DROP
    #iptables -A FORWARD -i $INET_NIC -m state --state NEW -j DROP
    
    #drop tcp_block
    for tcp_block in $TCP_BLOCK
    do
        iptables -A FORWARD -i $INET_NIC -p tcp --dport $tcp_block -j DROP
        iptables -A FORWARD -i $INET_NIC -p tcp --sport $tcp_block -j DROP
    done
    
    #drop udp block
    for udp_block in $UDP_BLOCK
    do
        iptables -A FORWARD -i $INET_NIC -p udp --dport $udp_block -j DROP
        iptables -A FORWARD -i $INET_NIC -p udp --sport $udp_block -j DROP
    done
    


    #iptables -A FORWARD -i $INET_NIC -p tcp --sport 22 -j ACCEPT
    #drop packet to firewall from outside
    iptables -A FORWARD -i $INET_NIC -s $LOC_NET -j DROP
    
    #accept fragments
    iptables -A FORWARD -f -j ACCEPT
   
    #forward tcp ports
    for tcp_allow in $TCP_ALLOW
    do
    iptables -A FORWARD -i $LOC_NIC -o $INET_NIC -p tcp --dport $tcp_allow -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $INET_NIC -o $LOC_NIC -p tcp --sport $tcp_allow -m state --state ESTABLISHED -j ACCEPT
    

    iptables -A FORWARD -i $INET_NIC -o $LOC_NIC -p tcp --dport $tcp_allow -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $LOC_NIC -o $INET_NIC -p tcp --sport $tcp_allow -m state --state ESTABLISHED -j ACCEPT
    done
    
    for udp_allow in $UDP_ALLOW
    do
    iptables -A FORWARD -i $LOC_NIC -o $INET_NIC -p udp --dport $udp_allow -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $INET_NIC -o $LOC_NIC -p udp --sport $udp_allow -m state --state NEW,ESTABLISHED -j ACCEPT
    
    # external UDP traffic to internal 
    iptables -A FORWARD -i $INET_NIC -o $LOC_NIC -p udp --dport $udp_allow -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $LOC_NIC -o $INET_NIC -p udp --sport $udp_allow -m state --state NEW,ESTABLISHED -j ACCEPT
    done
    
    for icmp_allow in $ICMP_ALLOW
    do
        iptables -A FORWARD -i $LOC_NIC -o $INET_NIC -p icmp --icmp-type $icmp_allow -m state --state NEW,ESTABLISHED -j ACCEPT
    
        # external ICMP traffic to internal 
        iptables -A FORWARD -i $INET_NIC -o $LOC_NIC -p icmp --icmp-type $icmp_allow -m state --state NEW,ESTABLISHED -j ACCEPT
    done
    
    for icmp_allow_1 in $ICMP_ALLOW
    do
        # internal ICMP traffic to external 
        iptables -A FORWARD -i $INET_NIC -o $LOC_NIC -p icmp --icmp-type $icmp_allow_1 -m state --state NEW,ESTABLISHED -j ACCEPT
    
        # external ICMP traffic to internal 
        iptables -A FORWARD -i $LOC_NIC -o $INET_NIC -p icmp --icmp-type $icmp_allow_1 -m state --state NEW,ESTABLISHED -j ACCEPT
    done
    
    
        #SSH FTP
    iptables -A PREROUTING -t mangle -p tcp --dport 22 -j TOS --set-tos Minimize-Delay
    
    #FTP
    iptables -A PREROUTING -t mangle -p tcp --sport 21 -j TOS --set-tos Minimize-Delay
    
    #FTP Data
    iptables -A PREROUTING -t mangle -p tcp --sport 20 -j TOS --set-tos Maximize-Throughput
    echo "FORWARD chain done..."
    }



if [ "$1" = "client" ]
then
    echo "Setting client..."
    client
    echo "Client setting finished..."
    exit 0
elif [ "$1" = "firewall" ]
then
    echo "Setting firewall..."
    
    flush
    firewall
    prerouting
    postrouting
    
    echo "Firewall setting finished..."
    exit 0
elif [ "$1" = "flush" ]
then
    echo "Flush all rules and tables without configuring..."
    
    flush
    
    echo "Done flushing..."
    exit 0
elif [ "$1" = "start" ]
then
    echo "Input all rules..."
    flush
    firewall
    prerouting
    postrouting
    default_rule
    forward
    

fi
    
    
    
    
    
    
    
    
