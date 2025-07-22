#!/bin/bash

# restore settings on host machine to backup of previous config

# backup dir
BACKUPDIR="/var/lib/torctl"

check_root() {
    if [ $(id -u) -ne 0 ]; then
        err "This script must be run as root"
    fi
}

check_backup_dir() {
    if [ ! -d $BACKUPDIR ]; then
        mkdir -p $BACKUPDIR
    fi
}

restore_resolv_conf() {
    if [ -e $BACKUPDIR/resolv.conf.bak ]; then
        warn "restoring nameservers"
        rm -f $BACKUPDIR/resolv.conf
        mv $BACKUPDIR/resolv.conf.bak /etc/resolv.conf
        msg "restored nameservers"
    fi
}

restore_iptables() {
    if [ -e $BACKUPDIR/iptables.rules.bak ]; then
        warn "restoring iptables rules"
        iptables-restore <$BACKUPDIR/iptables.rules.bak
        rm -f $BACKUPDIR/iptables.rules.bak
        msg "restored iptables rules"
    fi
}

restore_sysctl() {
    if [ -e $BACKUPDIR/sysctl.conf.bak ]; then
        warn "restoring sysctl rules"
        sysctl -p $BACKUPDIR/sysctl.conf.bak &>"/dev/null"
        rm -f $BACKUPDIR/sysctl.conf.bak
        msg "restored sysctl rules"
    fi
}

check_root
check_backup_dir
restore_resolv_conf
restore_iptables
restore_sysctl