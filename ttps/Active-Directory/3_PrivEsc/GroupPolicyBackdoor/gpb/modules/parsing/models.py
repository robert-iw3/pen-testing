import json

from datetime                               import datetime, timedelta
from typing_extensions                      import Annotated
from typing                                 import Annotated, Literal, Union, List
from pydantic                               import BaseModel, Field
from pydantic.functional_validators         import BeforeValidator

from config                                 import MODULES_CONFIG, logger, bcolors


def validate_options_based_on_type(value, info):
    try:
        module_name = info.data.get("MODULECONFIG").name
    except Exception as e:
        return None
    
    if module_name == 'Scheduled Tasks':
        options = ScheduledTasksOptions(**value)

        if options.task_type == "immediate" and options.action != "create":
            raise ValueError("The only possible 'action' value for Immediate Tasks is 'create', as there is no need to delete immediate tasks")
        if options.action == "create" and options.program is None:
            raise ValueError("When creating a new Scheduled Task, please provide a program to launch")
        return options
    elif module_name == 'Files':
        options = FilesOptions(**value)
        if options.action == "create" and options.source_file is None:
            raise ValueError("When creating a new File, please provide a source file")
        return options
    elif module_name == 'Groups':
        options = GroupsOptions(**value)
        return options
    elif module_name == 'Registry':
        options = RegistryOptions(**value)
        return options
    elif module_name == 'Folders':
        options = FoldersOptions(**value)
        return options
    return None

def validate_filters(value, info):
    if not value or "filters" not in value.keys() or len(value["filters"]) == 0:
        return ModuleFilters(**{'filters': []})
    try:
        filters = []
        try:
            parsed = json.loads(value["filters"])
        except Exception as e:
            logger.error(f"{bcolors.FAIL}Filters are not a valid JSON string. Remember that to produce valid JSON, backslashes should be escaped")
            raise e

        if parsed[0]["operator"] != "AND":
            raise ValueError(f"The operator of the first filter should always be 'AND' (current {parsed[0]['operator']})")

        for item in parsed:
            if item["type"] == "Computer Name":
                filters.append(ComputerFilter(**item))
            elif item["type"] == "Security Group":
                if info.data.get("MODULECONFIG").type == "computer" and item["user_context"] != False:
                    raise ValueError(f"When defining a 'computer' configuration, Security Group filters cannot be configured with 'user_context'=True")
                filters.append(SecurityGroupFilter(**item))
            elif item["type"] == "WMI Query":
                filters.append(WMIQueryFilter(**item))
            else:
                raise ValueError(f"Unsupported item filter '{item['type']}'")
        return ModuleFilters(**{'filters': filters})
    except Exception as e:
        raise ValueError(f"[!] Error encountered while parsing GPO filters: {e}")

class ModuleConfigSection(BaseModel):
    name: Literal[*MODULES_CONFIG.keys()]
    type: Literal["user", "computer"]

class ScheduledTasksOptions(BaseModel):
    action: Literal["create", "delete"] = Field(default="create")
    task_type: Literal["scheduled", "immediate"] = Field(default="scheduled")
    program: str = Field(default=None)
    arguments: str = Field(default=None)
    impersonate: str = Field(default=None)
    repeat_every: int = Field(default=60, ge=1, le=43200)
    start_from: datetime = Field(default_factory=lambda: datetime.now() - timedelta(days=30))
    expiration_date: datetime = Field(default=None)
    task_name: str = Field(default="OneDrive Telemetry")
    author: str = Field(default="Microsoft Corporation")
    description: str = Field(default="")

class FilesOptions(BaseModel):
    action: Literal["create", "delete"]
    source_file: str = Field(default=None)
    destination_file: str
    hidden: bool = Field(default=False)
    name: str = Field(default="Deploy_logs")

class GroupsOptions(BaseModel):
    action: Literal["add", "remove"]
    group_sid: str
    user_sid: str
    group_name: str = Field(default="")
    user_name: str = Field(default="")

class RegistryOptions(BaseModel):
    hive: Literal["HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_CURRENT_CONFIG"]
    path: str
    key: str
    key_type: Literal["REG_SZ", "REG_DWORD", "REG_BINARY", "REG_MULTI_SZ", "REG_EXPAND_SZ", "REG_QWORD"]
    value: str

class FoldersOptions(BaseModel):
    action: Literal["create", "delete"]
    path: str
    hidden: bool = Field(default=False)
    recursive_delete: bool = Field(default=False)

class ComputerFilter(BaseModel):
    operator: Literal["AND", "OR"]
    type: Literal["Computer Name"]
    value: str

class SecurityGroupFilter(BaseModel):
    operator: Literal["AND", "OR"]
    type: Literal["Security Group"]
    group_name: str = Field(default="")
    group_sid: str
    primary_group: bool = Field(default=False)
    user_context: bool

class WMIQueryFilter(BaseModel):
    operator: Literal["AND", "OR"]
    type: Literal["WMI Query"]
    query: str
    namespace: str = Field(default=r"Root\\cimv2")

class ModuleFilters(BaseModel):
    filters: List[Union[ComputerFilter, SecurityGroupFilter, WMIQueryFilter]]

class GPBModule(BaseModel):
    MODULECONFIG: ModuleConfigSection
    MODULEOPTIONS: Annotated[Union[ScheduledTasksOptions, FilesOptions, GroupsOptions, RegistryOptions, FoldersOptions, None], BeforeValidator(validate_options_based_on_type)]
    MODULEFILTERS: Annotated[Union[ModuleFilters, None], BeforeValidator(validate_filters)]
