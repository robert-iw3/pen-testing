import sys
import argparse
from enum import Enum
from impacket import system_errors
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRENUM, NDRUniConformantArray, NDRPOINTER
from impacket.dcerpc.v5.dtypes import ULONG, DWORD, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.uuid import uuidtup_to_bin
import cmd2
import json
import struct
from tabulate import tabulate



class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EFSR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EFSR SessionError: unknown error code: 0x%x' % self.error_code


# CONSTANTS

class CLUSTER_ENUM(NDRENUM):
    class enumItems(Enum):
        CLUSTER_ENUM_NODE                    = 0x00000001
        CLUSTER_ENUM_RESTYPE                 = 0x00000002
        CLUSTER_ENUM_RESOURCE                = 0x00000004
        CLUSTER_ENUM_GROUP                   = 0x00000008
        CLUSTER_ENUM_NETWORK                 = 0x00000010
        CLUSTER_ENUM_NETINTERFACE            = 0x00000020
        CLUSTER_ENUM_INTERNAL_NETWORK        = 0x80000000
        CLUSTER_ENUM_SHARED_VOLUME_RESOURCE  = 0x40000000

CLUSTER_TYPE_MAP = {
        'node': CLUSTER_ENUM.enumItems.CLUSTER_ENUM_NODE,
        'restype': CLUSTER_ENUM.enumItems.CLUSTER_ENUM_RESTYPE,
        'resource': CLUSTER_ENUM.enumItems.CLUSTER_ENUM_RESOURCE,
        'group': CLUSTER_ENUM.enumItems.CLUSTER_ENUM_GROUP,
        'network': CLUSTER_ENUM.enumItems.CLUSTER_ENUM_NETWORK,
        'netinterface': CLUSTER_ENUM.enumItems.CLUSTER_ENUM_NETINTERFACE,
        'internal_network': CLUSTER_ENUM.enumItems.CLUSTER_ENUM_INTERNAL_NETWORK,
        'shared_volume': CLUSTER_ENUM.enumItems.CLUSTER_ENUM_SHARED_VOLUME_RESOURCE,
        }



# STRUCTURES

class ENUM_ENTRY(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('Name', LPWSTR),
    )

class ENUM_ENTRY_ARRAY(NDRUniConformantArray):
    item = ENUM_ENTRY

class ENUM_LIST(NDRSTRUCT):
    structure = (
        ('EntryCount', DWORD),
        ('Entry', ENUM_ENTRY_ARRAY),
    )

class PENUM_LIST(NDRPOINTER):
    referent = (
        ('Data', ENUM_LIST),
    )

# RPC CALLS

class ApiGetClusterName(NDRCALL):
    opnum = 3
    structure = ()

class ApiGetClusterNameResponse(NDRCALL):
    structure = (
        ('ClusterName', LPWSTR),
        ('NodeName', LPWSTR),
        ('ErrorCode', ULONG),
    )

class ApiCreateEnum(NDRCALL):
    opnum = 7
    structure = (
        ('EnumType', DWORD),
    )

class ApiCreateEnumResponse(NDRCALL):
    structure = (
        ('ReturnEnum', PENUM_LIST),
        ('rpc_status', ULONG),
        ('ErrorCode', ULONG),
    )


# HELPER FUNCTIONS
#claude is OP

def encode_ndr(string):
    """Encode string for NDR transmission"""
    unicode_bytes = string.encode('utf-16-le')
    str_len = len(unicode_bytes) // 2
    data = struct.pack('<III', str_len + 1, 0, str_len + 1)
    data += unicode_bytes + b'\x00\x00'
    padding = (4 - len(data) % 4) % 4
    return data + b'\x00' * padding

def parse_ndr(response, offset=0):
    """Parse NDR string from response"""
    referent_id = struct.unpack('<I', response[offset:offset+4])[0]
    if referent_id == 0:
        return "", offset + 4

    max_count = struct.unpack('<I', response[offset+4:offset+8])[0]
    str_offset = struct.unpack('<I', response[offset+8:offset+12])[0]
    actual_count = struct.unpack('<I', response[offset+12:offset+16])[0]

    str_data = response[offset+16:offset+16+(actual_count*2)]
    string = str_data.decode('utf-16-le').rstrip('\x00')

    end_offset = offset + 16 + (actual_count * 2)
    end_offset += (4 - end_offset % 4) % 4
    return string, end_offset

def rpc_call(dce, opnum, request_data, operation_name):
    """Standard RPC call with error handling"""
    try:
        dce.call(opnum, request_data)
        response = dce.recv()
        return response
    except DCERPCException as e:
        raise DCERPCSessionError(str(e), e.error_code)
    except Exception as e:
        print(f"[-] Error in {operation_name}: {e}")
        return None

def check_response(error_code, operation_name):
    """Check error code and raise DCERPCSessionError if needed"""
    if error_code != 0:
        raise DCERPCSessionError(f"{operation_name} failed", error_code)

def table_print(jsonstr):
    data = json.loads(jsonstr)
    if 'entries' in data and isinstance(data['entries'], list):
        if not data['entries']:
            return
        table_data = [[i, entry['name']] for i, entry in enumerate(data['entries'])]
        print(tabulate(table_data, headers=['Index', 'Name'], tablefmt='grid'))
    else:
        table_data = [[field, value] for field, value in data.items()]
        print(tabulate(table_data, headers=['Field', 'Value'], tablefmt='grid'))

def print_status(operation, details):
    """Print operation status in table format"""
    table_data = [[k, v] for k, v in details.items()]
    print(f"\n[*] {operation}")
    print(tabulate(table_data, headers=['Property', 'Value'], tablefmt='grid'))

def print_result(operation, success, details=None, error_msg=None):
    """Print operation result in table format"""
    status = "SUCCESS" if success else "FAILED"
    table_data = [["Operation", operation], ["Status", status]]

    if details:
        table_data.extend([[k, v] for k, v in details.items()])

    if error_msg:
        table_data.append(["Error", error_msg])

    print(tabulate(table_data, headers=['Property', 'Value'], tablefmt='grid'))

def print_error(operation, error_code, error_msg):
    """Print errors in table format"""
    table_data = [
        ["Operation", operation],
        ["Status", "FAILED"],
        ["Error Code", f"0x{error_code:08x}" if isinstance(error_code, int) else str(error_code)],
        ["Error Message", error_msg]
    ]
    print(tabulate(table_data, headers=['Property', 'Value'], tablefmt='grid'))

def jprint(resp):
    result = {name: resp[name] for name, _ in resp.structure}
    jsonstr = json.dumps(result)
    return jsonstr

# CONNECTION

def cmrp_connect(username, password, domain, lmhash, nthash, doKerberos, dcHost, targetIp):
    MSRPC_UUID_CMRP = uuidtup_to_bin(('b97db8b2-4c63-11cf-bff6-08002be23f2f', '3.0'))
    sb = epm.hept_map(targetIp, MSRPC_UUID_CMRP, protocol = 'ncacn_ip_tcp', dce=None)

    bp = {
        'stringBinding': f"{sb}",
        'MSRPC_UUID_CMRP' : ('b97db8b2-4c63-11cf-bff6-08002be23f2f', '3.0')
    }
    rpctransport = transport.DCERPCTransportFactory(bp['stringBinding'])
    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
    if doKerberos:
        rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)


    rpctransport.setRemoteHost(targetIp)

    dce = rpctransport.get_dce_rpc()
    if doKerberos:
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    else:
        dce.set_auth_type(RPC_C_AUTHN_WINNT)

    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    print(f"[-] Connecting to {sb}")
    try:
        dce.connect()
    except Exception as e:
        print("Something went wrong, check error status => %s" % str(e))
        return
    print("[+] Connected!")
    print(f"[+] Binding to {sb}")
    try:
        dce.bind(MSRPC_UUID_CMRP)
    except Exception as e:
        print("Something went wrong, check error status => %s" % str(e))
        return
    print("[+] Successfully bound!")
    return dce

# RPC FUNCTIONS

def OpenGroupEx_RawBytes(dce, group_name, desired_access=0x10000000):
    try:
        request_data = encode_ndr(group_name) + struct.pack('<I', desired_access)

        response = rpc_call(dce, 119, request_data, "OpenGroupEx")
        if not response or len(response) < 32:
            print_error("Open Group", "N/A", "Invalid response or insufficient data")
            return None

        granted_access, status, rpc_status = struct.unpack('<III', response[:12])
        context_handle = response[12:32]

        if status == 0:
            details = {
                "Group Name": group_name,
                "Requested Access": f"0x{desired_access:08x}",
                "Granted Access": f"0x{granted_access:08x}",
                "Handle": context_handle.hex()
            }
            print_result("Open Group", True, details)
            return context_handle
        else:
            check_response(status, "OpenGroupEx")

    except DCERPCSessionError as e:
        print_error("Open Group", e.error_code if hasattr(e, 'error_code') else "N/A", str(e))
        return None

def GetGroupState_RawBytes(dce, group_handle):
    """Get the current state of a cluster group"""
    response = rpc_call(dce, 45, group_handle, "GetGroupState")
    if not response:
        print_error("Get Group State", "N/A", "No response received")
        return None, None, -1

    # Parse response: int32 state, string NodeName, uint32 rpc_status, uint32 return value
    state = struct.unpack('<i', response[0:4])[0]

    node_name, str_end = parse_ndr(response, 4)

    rpc_status = struct.unpack('<I', response[str_end:str_end+4])[0]
    error_code = struct.unpack('<I', response[str_end+4:str_end+8])[0]

    # Group states
    state_names = {0: "Online", 1: "Offline", 2: "Failed", 3: "PartialOnline", 4: "Pending", 5: "Unknown"}
    state_name = state_names.get(state, f"Unknown({state})")

    if error_code == 0:
        details = {
            "Handle": group_handle.hex(),
            "State Code": state,
            "State Name": state_name,
            "Current Node": node_name or "N/A"
        }
        print_result("Get Group State", True, details)
    else:
        print_error("Get Group State", error_code, f"State: {state_name}, Node: {node_name}")

    return state, node_name, error_code

def OpenNode_RawBytes(dce, node_name):
    """Open a handle to a cluster node"""
    request_data = encode_ndr(node_name)

    response = rpc_call(dce, 66, request_data, "OpenNode")
    if not response or len(response) < 28:
        print_error("Open Node", "N/A", "Invalid response or insufficient data")
        return None

    status, rpc_status = struct.unpack('<II', response[:8])
    node_handle = response[8:28]

    if status == 0:
        details = {
            "Node Name": node_name,
            "Handle": node_handle.hex()
        }
        print_result("Open Node", True, details)
        return node_handle
    else:
        print_error("Open Node", status, f"Failed to open node: {node_name}")
        return None


def MoveGroupToNode_RawBytes(dce, group_handle, node_handle):
    """Move a cluster group to a specific node"""
    request_data = group_handle + node_handle  # 20 + 20 = 40 bytes

    response = rpc_call(dce, 52, request_data, "MoveGroupToNode")
    if not response or len(response) < 8:
        print_error("Move Group", "N/A", "Invalid response or insufficient data")
        return -1

    rpc_status, error_code = struct.unpack('<II', response[:8])

    details = {
        "Group Handle": group_handle.hex(),
        "Node Handle": node_handle.hex(),
        "Error Code": f"0x{error_code:08x}"
    }

    # Common error codes:
    if error_code == 0:
        details["Result"] = "Move operation completed successfully"
        print_result("Move Group", True, details)
    elif error_code == 0x000003e5 or error_code == 0x8007139F:  # ERROR_IO_PENDING (997 or full code)
        details["Result"] = "Move operation pending (this is normal)"
        details["Status Note"] = "Operation is in progress"
        print_result("Move Group", True, details)
    else:
        print_error("Move Group", error_code, "Move operation failed")

    return error_code

def CreateClusterEnum(dce, enum_type):
    try:
        request = ApiCreateEnum()
        request['EnumType'] = enum_type

        resp = dce.request(request)

        if resp['ErrorCode'] != 0:
            check_response(resp['ErrorCode'], "CreateClusterEnum")

        results = []
        return_enum = resp['ReturnEnum']

        if return_enum and return_enum['EntryCount'] > 0:
            for entry in return_enum['Entry']:
                name = entry['Name']
                if isinstance(name, bytes):
                    name = name.decode('utf-16-le').rstrip('\x00')
                elif isinstance(name, str):
                    name = name.rstrip('\x00')
                results.append({'name': name})

        return json.dumps({'entries': results, 'count': len(results)})

    except DCERPCSessionError as e:
        print(f"[-] {e}")
        return json.dumps({'entries': [], 'count': 0})
    except Exception as e:
        print(f"[-] Error: {e}")
        return json.dumps({'entries': [], 'count': 0})

def GetClusterName(dce):
    try:
        request = ApiGetClusterName()
        resp = dce.request(request)
        if resp['ErrorCode'] == 0:
            return jprint(resp)
    except Exception as e:
        print(e)

# SHELL

class SHELL(cmd2.Cmd):
    hidden = ["alias", "help", "macro", "run_pyscript", "set", "shortcuts", "edit", "history", "quit", "run_script", "shell", "_relative_run_script", "eof"]

    #these are cool, didn't know you could do this
    enum_parser = argparse.ArgumentParser()
    enum_parser.add_argument(
        'type',
        choices=list(CLUSTER_TYPE_MAP.keys()),
        help='Type of cluster resource to enumerate'
    )

    movegroup_parser = argparse.ArgumentParser()
    movegroup_parser.add_argument('-group', action='store', help="Target group to move")
    movegroup_parser.add_argument('-node', action='store', help='Target node to move the group to')

    def __init__(self, dce):
        self.dce = dce
        self.prompt = '# '
        super().__init__(allow_cli_args=False)
        self.hidden_commands = self.hidden

    def do_exit(self, arg):
        """Exit the console."""
        return True

    def do_help(self, arg):
        print("""
exit                            - terminate the shell
get_clustername                 - get the cluster name of current target
enum_cluster [type]             - enum cluster for specified resource
get_groupstate <group_name>      - get current state of a group
movegroup -group <name> -node <name> - move group to node
    """)

    def do_get_clustername(self, arg):
        result = GetClusterName(self.dce)
        table_print(result)

    def do_get_groupstate(self, arg):
        if not arg:
            print("Usage: getgroupstate <group_name>")
            return

        print(f"[*] Opening group: {arg}")
        group_handle = OpenGroupEx_RawBytes(self.dce, arg)

        if group_handle:
            print(f"\n[*] Got group handle, now getting state...")
            GetGroupState_RawBytes(self.dce, group_handle)

    @cmd2.with_argparser(enum_parser)
    def do_enum_cluster(self, args):
        enum_value = CLUSTER_TYPE_MAP[args.type]
        result = CreateClusterEnum(self.dce, enum_value.value)
        table_print(result)

    @cmd2.with_argparser(movegroup_parser)
    def do_movegroup(self, args):
        """Move a group to a node"""
        group_name, node_name = args.group, args.node

        group_handle = OpenGroupEx_RawBytes(self.dce, group_name)
        if not group_handle:
            return

        node_handle = OpenNode_RawBytes(self.dce, node_name)
        if not node_handle:
            return

        MoveGroupToNode_RawBytes(self.dce, group_handle, node_handle)

# MAIN

def main():
    print("v0.0.1 by @d4rk4rmy")
    parser = argparse.ArgumentParser(add_help = True, description = "POC to interact with the ClusterMgmt API")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass)')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')

    parser.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-target-ip', action='store', metavar="ip address",
                        help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                        'This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it')

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    dce = cmrp_connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, doKerberos=options.k, dcHost=options.dc_ip, targetIp=options.target_ip)
    if dce is not None:
        cli = SHELL(dce)
        cli.cmdloop()
    dce.disconnect()
    sys.exit()

if __name__ == '__main__':
    main()