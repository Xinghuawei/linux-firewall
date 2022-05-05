
#!/bin/bash



###############################################################################
# 
# User Configurable Section
#
###############################################################################

# Output File
OUTPUT="./outbound-test"

# Allowed TCP Ports
TCP_ALLOWED="22 80 443"

# Allowed ICMP types
ICMP_ALLOWED="8 0"

# Always Blocked
TCP_BLOCKED="32768 32769 32770 32771 32772 32773 32774 32775 137 138 139 111 515"

# Server
SERVER="192.168.0.12"


###############################################################################
# 
# Implementation Section
#
###############################################################################

rm $OUTPUT

# hping3 the server and port using a SYN
testTCP() {
	hping3 $1 -c 1 --tcpexitcode -S -s 80 -p $2  &>> $OUTPUT
	echo $?
}

printOutput() {
	case $1 in
		18)	
			echo "Port $port is open and service is running on $SERVER."
			echo >> $OUTPUT
			echo "** Port $port is open and service is running on $SERVER." >> $OUTPUT
			echo >> $OUTPUT
			;;
		20)	
			echo "Port $port is open, but no service is responding on $SERVER."
			echo >> $OUTPUT
			echo "** Port $port is open, but no service is responding on $SERVER." >> $OUTPUT
			echo >> $OUTPUT
			;;
		1)	
			echo "Port $port is closed on $SERVER."
			echo >> $OUTPUT
			echo "** Port $port is closed on $SERVER." >> $OUTPUT
			echo >> $OUTPUT
			;;
		*)	
			echo "port $port are DROPPED on $SERVER."
			echo >> $OUTPUT
			echo "**port $port are DROPPED on $SERVER." >> $OUTPUT
			echo >> $OUTPUT
			;;
	esac
}

echo "Testing allowed TCP ports $TCP_ALLOWED on $SERVER"
echo "----------------------------------------------------------------" >> $OUTPUT
echo "# Testing allowed TCP ports $TCP_ALLOWED on $SERVER" >> $OUTPUT
echo "----------------------------------------------------------------" >> $OUTPUT
for port in $TCP_ALLOWED
do
	printOutput `testTCP $SERVER $port`
done


echo "Testing blocked TCP ports $TCP_BLOCKED on $SERVER"
echo "----------------------------------------------------------------" >> $OUTPUT
echo "# Testing blocked TCP ports $TCP_BLOCKED on $SERVER" >> $OUTPUT
echo "----------------------------------------------------------------" >> $OUTPUT
for port in $TCP_BLOCKED
do
	printOutput `testTCP $SERVER $port`
done

echo "Testing inbound SYN to port 1025 on $SERVER"
echo "----------------------------------------------------------------" >> $OUTPUT
echo "# Testing inbound SYN to port 1025 on $SERVER" >> $OUTPUT
echo "----------------------------------------------------------------" >> $OUTPUT
port="1025"
printOutput `hping3 $SERVER -p $port -S -c 1 --tcpexitcode &>> $OUTPUT; echo $?`

echo "Testing if fragments are received from $SERVER"
echo "----------------------------------------------------------------" >> $OUTPUT
echo "# Testing if fragments are received from $SERVER" >> $OUTPUT
echo "----------------------------------------------------------------" >> $OUTPUT
for port in $TCP_ALLOWED
do
	printOutput `hping3 $SERVER -S -s 80 -p $port -f -c 1 --tcpexitcode &>> $OUTPUT; echo $?`
done

echo "Testing $SERVER responds to SYN,FIN packets"
echo "----------------------------------------------------------------" >> $OUTPUT
echo "# Testing $SERVER responds to SYN,FIN packets" >> $OUTPUT
echo "----------------------------------------------------------------" >> $OUTPUT
for port in $TCP_ALLOWED
do
	printOutput `hping3 $SERVER -p $port -S -F -c 1 --tcpexitcode &>> $OUTPUT; echo $?`
done

echo "Testing if $SERVER responds to TELNET packets"
echo "----------------------------------------------------------------" >> $OUTPUT
echo "# Testing if $SERVER responds to TELNET packets" >> $OUTPUT
echo "----------------------------------------------------------------" >> $OUTPUT
port="23"
printOutput `hping3 $SERVER -p $port -S -c 1 --tcpexitcode &>> $OUTPUT; echo $?`


