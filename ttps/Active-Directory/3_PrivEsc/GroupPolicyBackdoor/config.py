import logging

from enum import Enum

from gpb.modules.ScheduledTasks         import ScheduledTasks
from gpb.modules.Files                  import Files
from gpb.modules.Groups                 import Groups
from gpb.modules.Registry               import Registry
from gpb.modules.Folders                import Folders

logger = logging.getLogger("gpb")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

MODULES_CONFIG = {
    "Scheduled Tasks": {
        "class": ScheduledTasks,
        "setting_type": "Preferences",
        "cse_guid": "AADCED64-746C-4633-A97C-D61349046527",
        "admin_guid": "CAB54552-DEEA-4691-817E-ED4A4D1AFC72",
        "gpt_path": "Preferences\ScheduledTasks\ScheduledTasks.xml",
    },
    "Files": {
        "class": Files,
        "setting_type": "Preferences",
        "cse_guid": "7150F9BF-48AD-4DA4-A49C-29EF4A8369BA",
        "admin_guid": "3BAE7E51-E3F4-41D0-853D-9BB9FD47605F",
        "gpt_path": "Preferences\Files\Files.xml",
    },
    "Groups": {
        "class": Groups,
        "setting_type": "Preferences",
        "cse_guid": "17D89FEC-5C44-4972-B12D-241CAEF74509",
        "admin_guid": "79F92669-4224-476C-9C5C-6EFB4D87DF4A",
        "gpt_path": "Preferences\Groups\Groups.xml",
    },
    "Registry": {
        "class": Registry,
        "setting_type": "Preferences",
        "cse_guid": "B087BE9D-ED37-454F-AF9C-04291E351182",
        "admin_guid": "BEE07A6A-EC9F-4659-B8C9-0B1937907C83",
        "gpt_path": "Preferences\Registry\Registry.xml",
    },
    "Folders": {
        "class": Folders,
        "setting_type": "Preferences",
        "cse_guid": "6232C319-91AC-4931-9385-E70C2B099F0E",
        "admin_guid": "3EC4E9D3-714D-471F-88DC-4DD4471AAB47",
        "gpt_path": "Preferences\Folders\Folders.xml",
    }
}

AD_OPERATIONAL_ATTRIBUTES = [
    "objectGUID",
    "objectSid",
    "whenCreated",
    "whenChanged",
    "uSNCreated",
    "uSNChanged",
    "dSASignature",
    "isDeleted",
    "isCriticalSystemObject",
    "instanceType"
]

class LinkOptions(Enum):
    NORMAL = 0
    DISABLED = 1
    ENFORCED = 2
    DISABLED_ENFORCED = 3

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class GPBLDAPNoResultsError(Exception):
    pass

CSE_LIST = {
    'B587E2B1-4D59-4E7E-AED9-22B9DF11D053': '802.3 Group Policy',
    'C6DC5466-785A-11D2-84D0-00C04FB169F7': 'Software Installation',
    'F3CCC681-B74C-4060-9F26-CD84525DCA2A': 'Audit Policy Configuration',
    '53D6AB1D-2488-11D1-A28C-00C04FB94F17': 'Certificates Run Restriction',
    '803E14A0-B4FB-11D0-A0D0-00A0C90F574B': 'Restricted Groups',
    '00000000-0000-0000-0000-000000000000': 'Core GPO Engine',
    '8A28E2C5-8D06-49A4-A08C-632DAA493E17': 'Deployed Printer Connections',
    'B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A': 'EFS Recovery',
    'FB2CA36D-0B40-4307-821B-A13B252DE56C': 'Enterprise QoS',
    '88E729D6-BDC1-11D1-BD2A-00C04FB9603F': 'Folder Redirection',
    '25537BA6-77A8-11D2-9B6C-0000F8080861': 'Folder Redirection',
    'F9C77450-3A41-477E-9310-9ACD617BD9E3': 'Group Policy Applications',
    '6232C319-91AC-4931-9385-E70C2B099F0E': 'Group Policy Folders',
    'CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D': 'Internet Explorer Machine Accelerators',
    'FC715823-C5FB-11D1-9EEF-00A0C90347FF': 'Internet Explorer Maintenance Extension protocol',
    'A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B': 'Internet Explorer Maintenance policy processing',
    '7B849A69-220F-451E-B3FE-2CB811AF94AE': 'Internet Explorer User Accelerators',
    '4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3': 'Internet Explorer Zonemapping',
    'E437BC1C-AA7D-11D2-A382-00C04F991E27': 'IP Security',
    '9650FDBC-053A-4715-AD14-FC2DC65E8330': 'ProcessHVSIPolicy',
    '3610EDA5-77EF-11D2-8DC5-00C04FA31A66': 'Microsoft Disk Quota',
    'C631DF4C-088F-4156-B058-4375F0853CD8': 'Microsoft Offline Files',
    'F6E72D5A-6ED3-43D9-9710-4440455F6934': 'Policy Maker',
    'F27A6DA8-D22B-4179-A042-3D715F9E75B5': 'Policy Maker',
    'F17E8B5B-78F2-49A6-8933-7B767EDA5B41': 'Policy Maker',
    'F0DB2806-FD46-45B7-81BD-AA3744B32765': 'Policy Maker',
    'F581DAE7-8064-444A-AEB3-1875662A61CE': 'Policy Maker',
    'F648C781-42C9-4ED4-BB24-AEB8853701D0': 'Policy Maker',
    'FD2D917B-6519-4BF7-8403-456C0C64312F': 'Policy Maker',
    'FFC64763-70D2-45BC-8DEE-7ACAF1BA7F89': 'Policy Maker',
    '47BA4403-1AA0-47F6-BDC5-298F96D1C2E3': 'Policy Maker Print Policy',
    '728EE579-943C-4519-9EF7-AB56765798ED': 'Group Policy Data Sources',
    '1A6364EB-776B-4120-ADE1-B63A406A76B5': 'Group Policy Device Settings',
    '5794DAFD-BE60-433F-88A2-1A31939AC01F': 'Group Policy Drive Maps',
    '0E28E245-9368-4853-AD84-6DA3BA35BB75': 'Group Policy Environment',
    '7150F9BF-48AD-4DA4-A49C-29EF4A8369BA': 'Group Policy Files',
    'A3F3E39B-5D83-4940-B954-28315B82F0A8': 'Group Policy Folder Options',
    '74EE6C03-5363-4554-B161-627540339CAB': 'Group Policy Ini Files',
    'E47248BA-94CC-49C4-BBB5-9EB7F05183D0': 'Group Policy Internet Settings',
    '17D89FEC-5C44-4972-B12D-241CAEF74509': 'Group Policy Local Users and Groups',
    '3A0DBA37-F8B2-4356-83DE-3E90BD5C261F': 'Group Policy Network Options',
    '6A4C88C6-C502-4F74-8F60-2CB23EDC24E2': 'Group Policy Network Shares',
    'E62688F0-25FD-4C90-BFF5-F508B9D2E31F': 'Group Policy Power Options',
    'BC75B1ED-5833-4858-9BB8-CBF0B166DF9D': 'Group Policy Printers',
    'E5094040-C46C-4115-B030-04FB2E545B00': 'Group Policy Regional Options',
    'B087BE9D-ED37-454F-AF9C-04291E351182': 'Group Policy Registry',
    'AADCED64-746C-4633-A97C-D61349046527': 'Group Policy Scheduled Tasks',
    '91FBB303-0CD5-4055-BF42-E512A681B325': 'Group Policy Services',
    'C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7': 'Group Policy Shortcuts',
    'E4F48E54-F38D-4884-BFB9-D4D2E5729C18': 'Group Policy Start Menu Settings',
    '1612B55C-243C-48DD-A449-FFC097B19776': 'Group Policy Data Sources',
    '1B767E9A-7BE4-4D35-85C1-2E174A7BA951': 'Group Policy Devices',
    '2EA1A81B-48E5-45E9-8BB7-A6E3AC170006': 'Group Policy Drives',
    '35141B6B-498A-4CC7-AD59-CEF93D89B2CE': 'Group Policy Environment Variables',
    '3BAE7E51-E3F4-41D0-853D-9BB9FD47605F': 'Group Policy Files',
    '3BFAE46A-7F3A-467B-8CEA-6AA34DC71F53': 'Group Policy Folder Options',
    '3EC4E9D3-714D-471F-88DC-4DD4471AAB47': 'Group Policy Folders',
    '516FC620-5D34-4B08-8165-6A06B623EDEB': 'Group Policy Ini Files',
    '5C935941-A954-4F7C-B507-885941ECE5C4': 'Group Policy Internet Settings',
    '79F92669-4224-476C-9C5C-6EFB4D87DF4A': 'Group Policy Local Users and Groups',
    '949FB894-E883-42C6-88C1-29169720E8CA': 'Group Policy Network Options',
    'BFCBBEB0-9DF4-4C0C-A728-434EA66A0373': 'Group Policy Network Shares',
    '9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD': 'Group Policy Power Options',
    'A8C42CEA-CDB8-4388-97F4-5831F933DA84': 'Group Policy Printers',
    'B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7': 'Group Policy Regional Options',
    'BEE07A6A-EC9F-4659-B8C9-0B1937907C83': 'Group Policy Registry',
    'CAB54552-DEEA-4691-817E-ED4A4D1AFC72': 'Group Policy Scheduled Tasks',
    'CC5746A9-9B74-4BE5-AE2E-64379C86E0E4': 'Group Policy Services',
    'CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1': 'Group Policy Shortcuts',
    'CF848D48-888D-4F45-B530-6A201E62A605': 'Group Policy Start Menu',
    '35378EAC-683F-11D2-A89A-00C04FBBCFA2': 'Registry',
    '3060E8CE-7020-11D2-842D-00C04FA372D4': 'Remote Installation Services',
    '40B66650-4972-11D1-A7CA-0000F87571E3': 'Scripts (Logon/Logoff) Run Restriction',
    '827D319E-6EAC-11D2-A4EA-00C04F79F83A': 'Security',
    '942A8E4F-A261-11D1-A760-00C04FB9603F': 'Software Installation ()',
    'BACF5C8A-A3C7-11D1-A760-00C04FB9603F': 'Software Installation Run Restriction',
    'CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA': 'TCPIP',
    'D02B1F72-3407-48AE-BA88-E8213C6761F1': 'Policy Settings',
    '0F6B957D-509E-11D1-A7CC-0000F87571E3': 'Policy Settings Run Restriction',
    'D02B1F73-3407-48AE-BA88-E8213C6761F1': 'Policy Settings',
    '0F6B957E-509E-11D1-A7CC-0000F87571E3': 'Policy Settings Run Restriction',
    '2BFCC077-22D2-48DE-BDE1-2F618D9B476D': 'AppV Policy',
    '0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63': 'Wireless Group Policy',
    '169EBF44-942F-4C43-87CE-13C93996EBBE': 'UEV Policy',
    '16BE69FA-4209-4250-88CB-716CF41954E0': 'Central Access Policy Configuration',
    '2A8FDC61-2347-4C87-92F6-B05EB91A201A': 'MitigationOptions',
    '346193F5-F2FD-4DBD-860C-B88843475FD3': 'ConfigMgr User State Management Extension',
    '426031C0-0B47-4852-B0CA-AC3D37BFCB39': 'QoS Packet Scheduler',
    '42B5FAAE-6536-11D2-AE5A-0000F87571E3': 'Scripts',
    '4B7C3B0F-E993-4E06-A241-3FBE06943684': 'Per-process Mitigation Options',
    '4BCD6CDE-777B-48B6-9804-43568E23545D': 'Remote Desktop USB Redirection',
    '4D2F9B6F-1E52-4711-A382-6A8B1A003DE6': '?',
    '4D968B55-CAC2-4FF5-983F-0A54603781A3': 'Work Folders',
    '7909AD9E-09EE-4247-BAB9-7029D5F0A278': 'MDM Policy',
    '7933F41E-56F8-41D6-A31C-4148A711EE93': 'Windows Search Group Policy Extension',
    'BA649533-0AAC-4E04-B9BC-4DBAE0325B12': 'Windows To Go Startup Options',
    'C34B2751-1CF4-44F5-9262-C3FC39666591': 'Windows To Go Hibernate Options',
    'C50F9585-D8AD-46D4-8A81-940406C4D8A6': 'Application Manager',
    'CFF649BD-601D-4361-AD3D-0FC365DB4DB7': 'Delivery Optimization GP extension',
    'D76B9641-3288-4F75-942D-087DE603E3EA': 'AdmPwd',
    'F312195E-3D9D-447A-A3F5-08DFFA24735E': 'ProcessVirtualizationBasedSecurityGroupPolicy',
    'FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F': 'CP',
    'FC491EF1-C4AA-4CE1-B329-414B101DB823': 'ProcessConfigCIPolicyGroupPolicy',
    '53D6AB1B-2488-11D1-A28C-00C04FB94F17': 'EFS Policy',
    '40B6664F-4972-11D1-A7CA-0000F87571E3': 'Tool extension GUID'
}