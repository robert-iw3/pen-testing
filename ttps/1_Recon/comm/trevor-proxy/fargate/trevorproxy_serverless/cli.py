#!/usr/bin/python3
from threadlocal_aws.clients import ecs, ec2
from trevorproxy.cli import main as trevorproxy

import argparse
import threading
import boto3
import os
import signal
import sys
import time
import uuid

queue = None
message_id = None

def terminate(sig, frame):
    message = queue.receive_messages(MaxNumberOfMessages=1)[0]
    queue.delete_messages(Entries=[{'Id':message_id,'ReceiptHandle':message.receipt_handle}])
    exit(0)

def send_proxy_intent():
    global message_id
    print('Sending proxy intent.')
    dedup_id = str(uuid.uuid4())
    message_id = queue.send_message(MessageBody='{}', 
            MessageDeduplicationId=dedup_id,
            MessageGroupId=dedup_id)['MessageId']

def main():
    global queue

    if os.getuid() != 0:
        print("Please run as root")
        exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="Use this SSH key when connecting to proxy hosts", required=True)
    parser.add_argument("-p", "--port", type=int, default=1080,
        help="Port for SOCKS server to listen on (default: 1080)")
    parser.add_argument("-l", "--listen-address", default="127.0.0.1",
        help="Listen address for SOCKS server (default: 127.0.0.1)")
    parser.add_argument("--base-port", default=32482, type=int, 
        help="Base listening port to use for SOCKS proxies (default: 32482)")
    args = parser.parse_args()

    session = boto3.Session()
    sqs = session.resource('sqs')
    queue = sqs.get_queue_by_name(QueueName='proxy-intents.fifo')
    send_proxy_intent()
    
    # setup graceful termination to remove proxy-intent message
    signal.signal(signal.SIGINT, terminate)
    signal.signal(signal.SIGTERM, terminate)
    
    # sliding window, to ensure messages don't expire while the tool is running
    interval = int(queue.attributes['MessageRetentionPeriod']) / 2
    timer = threading.Timer(interval, send_proxy_intent)
    timer.start()

    ecs_client = ecs()
    cluster = ecs_client.describe_clusters(clusters=['proxy-cluster'])['clusters'][0]

    print('Waiting for proxies to spin up..')
    while True:
        taskArns = ecs_client.list_tasks(cluster=cluster['clusterArn'], family='proxy-def')["taskArns"]
        if taskArns:
            tasks = ecs_client.describe_tasks(cluster=cluster['clusterArn'], tasks=taskArns)
            if not [t for t in tasks['tasks'] if t['containers'][0]['lastStatus'] != 'RUNNING']:
                break
        time.sleep(10)

    ec2_client = ec2()
    taskENIIds = [t['attachments'][0]['details'][1]['value'] for t in tasks['tasks']]
    taskENIs = ec2_client.describe_network_interfaces(NetworkInterfaceIds=taskENIIds)['NetworkInterfaces']
    proxyIps=['root@'+e['Association']['PublicIp'] for e in taskENIs]

    # prepare sys.argv for the call into trevorproxy
    trevorArgs = [sys.argv[0], '-p', str(args.port), '-l', args.listen_address,
                'ssh', '-k', args.key,  '--base-port', str(args.base_port)]
    for i in range(len(trevorArgs), len(trevorArgs) + len(proxyIps)):
        trevorArgs.append(proxyIps[i-11])
    sys.argv = trevorArgs

    trevorproxy()

if __name__ == "__main__":
    main()