import os
import shutil
import logging

from    functools import partial
from    conf import OUTPUT_DIR
from    impacket.smbconnection import SMBConnection

def get_smb_connection(dc_ip, username, password, hash, domain):
    smb_session = SMBConnection(dc_ip, dc_ip)
    if hash is not None:
        smb_session.login(user=username, lmhash=hash.split(':')[0], nthash=hash.split(':')[1], password=None, domain=domain)
    else:
        smb_session.login(user=username, password=password, domain=domain)
    return smb_session


def write_data_to_file(local_file_name, data):
    # Sometimes, the gpt.ini file will be stored in the SMB share as "GPT.INI",
    # which causes issues when the DC is then looking for it in our spoofed share.
    directory, filename = os.path.split(local_file_name)
    if filename == "GPT.INI":
        filename = filename.lower()
        local_file_name = os.path.join(directory, filename)

    with open(local_file_name, "wb") as local_file:
        local_file.write(data)

def recursive_smb_download(smb_session, share, remote_path, local_path):
    items = smb_session.listPath(share, os.path.join(remote_path, '*'))

    for item in items:
        if item.is_directory():
            if item.get_longname() == '.' or item.get_longname() == '..':
                continue
            subdirectory = os.path.join(local_path, item.get_longname())
            os.makedirs(subdirectory, exist_ok=True)
            recursive_smb_download(smb_session, share, os.path.join(remote_path, item.get_longname()), subdirectory)

        else:
            callback = partial(write_data_to_file, os.path.join(local_path, item.get_longname()))
            smb_session.getFile(share, os.path.join(remote_path, item.get_longname()), callback)



def download_initial_gpo(smb_session, domain, gpo_id):
    try:
        tid = smb_session.connectTree("SYSVOL")
        logging.info(f"Connected to SYSVOL share")
    except:
        logging.error(f"Unable to connect to SYSVOL share", exc_info=True)
        return False
    
    path = domain + "/Policies/{" + gpo_id + "}"
    
    try:
        shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        recursive_smb_download(smb_session, "SYSVOL", path, OUTPUT_DIR)
        logging.debug("Successfully cloned GPO {} from SYSVOL".format(gpo_id))
    except:
        logging.error("Couldn't clone GPO {} (maybe it does not exist?)".format(gpo_id), exc_info=True)
        return False


def upload_directory_to_share(smb_session, remote_share):
    try:
        for root, dirs, files in os.walk(OUTPUT_DIR):
            remote_subdir = os.path.relpath(root, OUTPUT_DIR)
            if remote_subdir != '.':
                smb_session.createDirectory(remote_share, remote_subdir)
            for file in files:
                local_file_path = os.path.join(root, file)
                remote_file_path = os.path.join(remote_subdir, file)
                with open(local_file_path, 'rb') as local_file:
                    smb_session.putFile(remote_share, remote_file_path, local_file.read)
    except:
        import traceback
        traceback.print_exc()


def recursive_smb_delete(smb_session, remote_share, root):
    items = smb_session.listPath(remote_share, root)
    for item in items:
        if item.is_directory():
            if item.get_longname() not in ['.', '..']:
                new_root = root[:-1] + item.get_longname() + '/*'
                recursive_smb_delete(smb_session, remote_share, new_root)
                smb_session.deleteDirectory(remote_share, root[:-1] + item.get_longname())
        else:
            smb_session.deleteFile(remote_share, root[:-1] + item.get_longname())