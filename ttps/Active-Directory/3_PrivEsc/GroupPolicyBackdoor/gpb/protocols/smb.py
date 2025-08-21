import uuid
import logging
import smbclient

from smbprotocol.session import Session
from smbprotocol.connection import Connection


logger = logging.getLogger(__name__)

def initialize_smb_connection(dc, username, password, kerberos, low_level=False):
    if low_level is False:
        if kerberos is False:
            smbclient.ClientConfig(username=username, password=password, auth_protocol="ntlm")
        else:
            smbclient.ClientConfig(auth_protocol="kerberos")
        return
    else:
        connection = Connection(uuid.uuid4(), dc, 445)
        connection.connect()
        if kerberos is False:
            session = Session(connection, username, password)
        else:
            session = Session(connection, auth_protocol="kerberos")
        session.connect()
        return (connection,session)

def write_file(target_path, contents):
    with smbclient.open_file(target_path, mode="w") as fd:
        fd.write(contents)

def write_file_binary(target_path, bytes):
    with smbclient.open_file(target_path, mode="wb") as fd:
        fd.write(bytes)

def delete_file(target_file):
    smbclient.remove(target_file)

def delete_directory(target_directory):
    smbclient.rmdir(target_directory)

def create_directory(target_directory):
    smbclient.mkdir(target_directory)

def read_file_binary(target_file):
    with smbclient.open_file(target_file, mode="rb") as fd:
       file_contents = fd.read()
    return file_contents 