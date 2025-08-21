import os
import json

from datetime import datetime

def clean_create_folder(command, gpo_guid):
    state_folder = datetime.now().strftime("%Y_%m_%d_%H%M%S")
    os.makedirs("state_folders", exist_ok=True)
    os.makedirs(os.path.join("state_folders", state_folder))
    os.makedirs(os.path.join("state_folders", state_folder, "revert"))



    with open(os.path.join("state_folders", state_folder, "gpo_guid.json"), "w") as f:
        json.dump({"GPO_GUID": gpo_guid}, f, indent=2) 
    with open(os.path.join("state_folders", state_folder, "clean.json"), "a") as f:
        f.write("[]")
    with open(os.path.join("state_folders", state_folder, "actions.json"), "w") as f:
        json.dump({"command": command, "actions": []}, f)
    return os.path.join("state_folders", state_folder)

def clean_save_module(state_folder, configuration_type, configuration_name, configuration_identifier):
    with open(os.path.join(state_folder, "clean.json"), 'r+') as f:
        data = json.load(f)
        data.append({
            "configuration_name": configuration_name,
            "configuration_type": configuration_type,
            "configuration_identifier": configuration_identifier
        })
        f.seek(0)
        json.dump(data, f, indent=2)

def clean_save_action(state_folder, action, item, attribute=None, old_value=None, new_value=None):
    with open(os.path.join(state_folder, "actions.json"), 'r+') as f:
        data = json.load(f)
        data["actions"].append({
            "action": action,
            "item": item,
            "attribute": attribute,
            "old_value": old_value,
            "new_value": new_value
        })
        f.seek(0)
        json.dump(data, f, indent=2, default=str)

def get_gpo_guid_from_state(state_folder):
    with open(os.path.join(state_folder, "gpo_guid.json"), "r") as f:
        gpo_guid = json.load(f)["GPO_GUID"]
    return gpo_guid