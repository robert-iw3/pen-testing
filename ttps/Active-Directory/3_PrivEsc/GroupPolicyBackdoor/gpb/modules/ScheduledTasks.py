import json
import uuid
import string
import random
import configparser

from datetime                   import datetime, timedelta
from gpb.utils.encodings        import get_xml_declared_encoding
from lxml                       import etree
from gpb.modules.utils.filters  import generate_filters, serialize_filters

class ScheduledTasks():
    def __init__(self, module_config, module_options, module_filters, existing_xml, state_folder):
        self.config = module_config
        self.options = module_options
        self.filters = module_filters.filters
        self.xml = existing_xml
        
        if len(self.xml) > 0:
            self.encoding = get_xml_declared_encoding(self.xml)
        else:
            self.encoding = "UTF-8"
        self.state_folder = state_folder
        self.identifier = str(uuid.uuid4()).upper()

        if self.options.task_type == "immediate":
            self.run_immediatetask()
        elif self.options.task_type == "scheduled":
            self.run_scheduledtasks()


    @staticmethod
    def format_duration(minutes):
        result = "P"
        days, rem = divmod(minutes, 1440)
        hours, mins = divmod(rem, 60)
        if days > 0: result += f"{days}D"
        if hours > 0 or mins > 0: result += "T"
        if hours > 0: result += f"{hours}H"
        if mins > 0: result += f"{mins}M"
        return result

    def run_scheduledtasks(self) -> None:
        if len(self.xml) == 0:
            scheduled_task = etree.Element("ScheduledTasks", attrib={
                "clsid": "{CC63F200-7309-4ba0-B154-A71CD118DBCC}"
            })
        else:
            scheduled_task = etree.XML(self.xml)

        if self.options.action == "create":
            taskv2 = self.create_scheduledtasks_generate_xml()
            self.create_scheduledtasks_generate_reverse_file()
        elif self.options.action == "delete":
            taskv2 = self.delete_scheduledtasks_generate_xml()
        else:
            return

        scheduled_task.append(taskv2)
        tree = etree.ElementTree(scheduled_task)
        self.xml = etree.tostring(tree, xml_declaration=True, encoding=self.encoding)
    
    
    def run_immediatetask(self) -> None:
        if len(self.xml) == 0:
            scheduled_task = etree.Element("ScheduledTasks", attrib={
                "clsid": "{CC63F200-7309-4ba0-B154-A71CD118DBCC}"
            })
        else:
            scheduled_task = etree.XML(self.xml)

        taskv2 = self.create_immediatetasks_generate_xml()
        scheduled_task.append(taskv2)
        tree = etree.ElementTree(scheduled_task)
        self.xml = etree.tostring(tree, xml_declaration=True, encoding=self.encoding)


    def create_scheduledtasks_generate_xml(self):
        if self.options.impersonate is None:
            runAs = "NT AUTHORITY\SYSTEM"
            logon_type = "S4U"
        else:
            runAs = self.options.impersonate
            logon_type = "InteractiveToken"

        taskv2 = etree.Element("TaskV2", attrib={
            "clsid": "{D8896631-B747-47a7-84A6-C155337F3BC8}",
            "name": self.options.task_name,
            "image": "0", # The image attribute is actually the small icon that we see in the Group Policy Management Console. 0 here is create
            "userContext": "0",
            "removePolicy": "0",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}"
        })

        properties = etree.SubElement(taskv2, "Properties", attrib={
            "action": "C",
            "name": self.options.task_name,
            "runAs": runAs,
            "logonType": logon_type
        })

        task = etree.SubElement(properties, "Task", attrib={
            "version": "1.2"
        })

        registration_info = etree.SubElement(task, "RegistrationInfo")
        registration_info_author = etree.SubElement(registration_info, "Author")
        registration_info_author.text = self.options.author
        registration_info_descr = etree.SubElement(registration_info, "Description")
        registration_info_descr.text = self.options.description
        

        principals = etree.SubElement(task, "Principals")
        principal = etree.SubElement(principals, "Principal", attrib={
            "id": "Author"
        })
        user_id = etree.SubElement(principal, "UserId")
        user_id.text = runAs
        logon_type_elem = etree.SubElement(principal, "LogonType")
        logon_type_elem.text = logon_type
        run_level = etree.SubElement(principal, "RunLevel")
        run_level.text = "HighestAvailable"

        settings = etree.SubElement(task, "Settings")
        idle_settings = etree.SubElement(settings, "IdleSettings")
        duration = etree.SubElement(idle_settings, "Duration")
        duration.text = "PT5M"
        wait_timeout = etree.SubElement(idle_settings, "WaitTimeout")
        wait_timeout.text = "PT1H"
        stop_on_idle_end = etree.SubElement(idle_settings, "StopOnIdleEnd")
        stop_on_idle_end.text = "false"
        restart_on_idle = etree.SubElement(idle_settings, "RestartOnIdle")
        restart_on_idle.text = "false"

        multiple_instances_policy = etree.SubElement(settings, "MultipleInstancesPolicy")
        multiple_instances_policy.text = "IgnoreNew"
        disallow_start_battery = etree.SubElement(settings, "DisallowStartIfOnBatteries")
        disallow_start_battery.text = "false"
        stop_going_battery = etree.SubElement(settings, "StopIfGoingOnBatteries")
        stop_going_battery.text = "false"
        hard_terminate = etree.SubElement(settings, "AllowHardTerminate")
        hard_terminate.text = "false"
        start_when_available = etree.SubElement(settings, "StartWhenAvailable")
        start_when_available.text = "true"
        start_on_demand = etree.SubElement(settings, "AllowStartOnDemand")
        start_on_demand.text = "true"
        enabled = etree.SubElement(settings, "Enabled")
        enabled.text = "true"
        hidden = etree.SubElement(settings, "Hidden")
        hidden.text = "true"
        execution_time_limit = etree.SubElement(settings, "ExecutionTimeLimit")
        execution_time_limit.text = "PT0S"
        priority = etree.SubElement(settings, "Priority")
        priority.text = "7"
        if self.options.expiration_date != None:
            delete_expired = etree.SubElement(settings, "DeleteExpiredTaskAfter")
            delete_expired.text = "PT0S"


        actions = etree.SubElement(task, "Actions", attrib={
            "Context": "Author"
        })
        exec = etree.SubElement(actions, "Exec")
        command = etree.SubElement(exec, "Command")
        command.text = self.options.program
        arguments = etree.SubElement(exec, "Arguments")
        arguments.text = self.options.arguments

        triggers = etree.SubElement(task, "Triggers")
        time_trigger = etree.SubElement(triggers, "TimeTrigger")
        start_boundary = etree.SubElement(time_trigger, "StartBoundary")
        start_boundary.text = self.options.start_from.isoformat()
        trigger_enabled = etree.SubElement(time_trigger, "Enabled")
        trigger_enabled.text = "true"
        repetition = etree.SubElement(time_trigger, "Repetition")
        repetition_interval = etree.SubElement(repetition, "Interval")
        repetition_interval.text = self.format_duration(self.options.repeat_every)
        stop_at_duration_end = etree.SubElement(repetition, "StopAtDurationEnd")
        stop_at_duration_end.text = "false"
        if self.options.expiration_date != None:
            end_boundary = etree.SubElement(time_trigger, "EndBoundary")
            end_boundary.text = self.options.expiration_date.isoformat()

        generate_filters(taskv2, self.filters)

        return taskv2

    def delete_scheduledtasks_generate_xml(self) -> None:
        taskv2 = etree.Element("TaskV2", attrib={
            "clsid": "{D8896631-B747-47a7-84A6-C155337F3BC8}",
            "name": self.options.task_name,
            "image": "3",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}"
        })

        properties = etree.SubElement(taskv2, "Properties", attrib={
            "action": "D",
            "name": self.options.task_name,
            "runAs": "SYSTEM",
            "logonType": "S4U"
        })

        task = etree.SubElement(properties, "Task", attrib={
            "version": "1.2"
        })

        registration_info = etree.SubElement(task, "RegistrationInfo")
        registration_info_author = etree.SubElement(registration_info, "Author")
        registration_info_author.text = self.options.author
        registration_info_descr = etree.SubElement(registration_info, "Description")
        registration_info_descr.text = self.options.description
        

        principals = etree.SubElement(task, "Principals")
        principal = etree.SubElement(principals, "Principal", attrib={
            "id": "Author"
        })
        user_id = etree.SubElement(principal, "UserId")
        user_id.text = "SYSTEM"
        logon_type_elem = etree.SubElement(principal, "LogonType")
        logon_type_elem.text = "S4U"
        run_level = etree.SubElement(principal, "RunLevel")
        run_level.text = "HighestAvailable"

        triggers = etree.SubElement(task, "Triggers")

        settings = etree.SubElement(task, "Settings")

        idle_settings = etree.SubElement(settings, "IdleSettings")
        duration = etree.SubElement(idle_settings, "Duration")
        duration.text = "PT5M"
        wait_timeout = etree.SubElement(idle_settings, "WaitTimeout")
        wait_timeout.text = "PT1H"
        stop_on_idle_end = etree.SubElement(idle_settings, "StopOnIdleEnd")
        stop_on_idle_end.text = "false"
        restart_on_idle = etree.SubElement(idle_settings, "RestartOnIdle")
        restart_on_idle.text = "false"

        multiple_instances_policy = etree.SubElement(settings, "MultipleInstancesPolicy")
        multiple_instances_policy.text = "IgnoreNew"
        disallow_start_battery = etree.SubElement(settings, "DisallowStartIfOnBatteries")
        disallow_start_battery.text = "false"
        stop_going_battery = etree.SubElement(settings, "StopIfGoingOnBatteries")
        stop_going_battery.text = "false"
        hard_terminate = etree.SubElement(settings, "AllowHardTerminate")
        hard_terminate.text = "false"
        start_when_available = etree.SubElement(settings, "StartWhenAvailable")
        start_when_available.text = "true"
        start_on_demand = etree.SubElement(settings, "AllowStartOnDemand")
        start_on_demand.text = "true"
        enabled = etree.SubElement(settings, "Enabled")
        enabled.text = "true"
        hidden = etree.SubElement(settings, "Hidden")
        hidden.text = "true"
        execution_time_limit = etree.SubElement(settings, "ExecutionTimeLimit")
        execution_time_limit.text = "PT0S"
        priority = etree.SubElement(settings, "Priority")
        priority.text = "7"

        actions = etree.SubElement(task, "Actions", attrib={
            "Context": "Author"
        })
        exec = etree.SubElement(actions, "Exec")
        command = etree.SubElement(exec, "Command")
        command.text = " "

        generate_filters(taskv2, self.filters)

        return taskv2

    def create_immediatetasks_generate_xml(self):

        if self.options.impersonate is None:
            runAs = "NT AUTHORITY\SYSTEM"
            logon_type = "S4U"
        else:
            runAs = self.options.impersonate
            logon_type = "InteractiveToken"

        taskv2 = etree.Element("ImmediateTaskV2", attrib={
            "clsid": "{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}",
            "name": self.options.task_name,
            "image": "0",
            "changed": (datetime.now() - timedelta(days=random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S"),
            "uid": f"{{{self.identifier}}}",
            "userContext": "0",
            "removePolicy": "0",
        })

        properties = etree.SubElement(taskv2, "Properties", attrib={
            "action": "C",
            "name": self.options.task_name,
            "runAs": runAs,
            "logonType": logon_type
        })

        task = etree.SubElement(properties, "Task", attrib={
            "version": "1.2"
        })

        registration_info = etree.SubElement(task, "RegistrationInfo")
        registration_info_author = etree.SubElement(registration_info, "Author")
        registration_info_author.text = self.options.author
        registration_info_descr = etree.SubElement(registration_info, "Description")
        registration_info_descr.text = self.options.description
        

        principals = etree.SubElement(task, "Principals")
        principal = etree.SubElement(principals, "Principal", attrib={
            "id": "Author"
        })
        user_id = etree.SubElement(principal, "UserId")
        user_id.text = runAs
        logon_type_elem = etree.SubElement(principal, "LogonType")
        logon_type_elem.text = logon_type
        run_level = etree.SubElement(principal, "RunLevel")
        run_level.text = "HighestAvailable"

        settings = etree.SubElement(task, "Settings")
        idle_settings = etree.SubElement(settings, "IdleSettings")
        duration = etree.SubElement(idle_settings, "Duration")
        duration.text = "PT5M"
        wait_timeout = etree.SubElement(idle_settings, "WaitTimeout")
        wait_timeout.text = "PT1H"
        stop_on_idle_end = etree.SubElement(idle_settings, "StopOnIdleEnd")
        stop_on_idle_end.text = "false"
        restart_on_idle = etree.SubElement(idle_settings, "RestartOnIdle")
        restart_on_idle.text = "false"

        multiple_instances_policy = etree.SubElement(settings, "MultipleInstancesPolicy")
        multiple_instances_policy.text = "IgnoreNew"
        disallow_start_battery = etree.SubElement(settings, "DisallowStartIfOnBatteries")
        disallow_start_battery.text = "false"
        stop_going_battery = etree.SubElement(settings, "StopIfGoingOnBatteries")
        stop_going_battery.text = "false"
        hard_terminate = etree.SubElement(settings, "AllowHardTerminate")
        hard_terminate.text = "false"
        start_when_available = etree.SubElement(settings, "StartWhenAvailable")
        start_when_available.text = "true"
        start_on_demand = etree.SubElement(settings, "AllowStartOnDemand")
        start_on_demand.text = "false"
        enabled = etree.SubElement(settings, "Enabled")
        enabled.text = "true"
        hidden = etree.SubElement(settings, "Hidden")
        hidden.text = "true"
        execution_time_limit = etree.SubElement(settings, "ExecutionTimeLimit")
        execution_time_limit.text = "PT0S"
        priority = etree.SubElement(settings, "Priority")
        priority.text = "7"
        delete_expired = etree.SubElement(settings, "DeleteExpiredTaskAfter")
        delete_expired.text = "PT0S"

        triggers = etree.SubElement(task, "Triggers")
        time_trigger = etree.SubElement(triggers, "TimeTrigger")
        start_boundary = etree.SubElement(time_trigger, "StartBoundary")
        start_boundary.text = "%LocalTimeXmlEx%"
        end_boundary = etree.SubElement(time_trigger, "EndBoundary")
        end_boundary.text = "%LocalTimeXmlEx%"
        trigger_enabled = etree.SubElement(time_trigger, "Enabled")
        trigger_enabled.text = "true"

        actions = etree.SubElement(task, "Actions", attrib={
            "Context": "Author"
        })
        exec = etree.SubElement(actions, "Exec")
        command = etree.SubElement(exec, "Command")
        command.text = self.options.program
        arguments = etree.SubElement(exec, "Arguments")
        arguments.text = self.options.arguments

        generate_filters(taskv2, self.filters)

        return taskv2


    def create_scheduledtasks_generate_reverse_file(self):
        reverse_module = configparser.ConfigParser(interpolation=None)

        reverse_module["MODULECONFIG"] = {
            "name": "Scheduled Tasks",
            "type": self.config.type
        }

        reverse_module["MODULEOPTIONS"] = {
            "action": "delete",
            "task_name": self.options.task_name,
        }
        reverse_module["MODULEFILTERS"] = {}
        if len(self.filters) > 0:
            reverse_module["MODULEFILTERS"]["filters"] = json.dumps(serialize_filters(self.filters))

        filename = f"reverse_Scheduled_Task_create_{''.join(random.choices(string.ascii_letters, k=6))}.ini"
        with open(f"{self.state_folder}/revert/{filename}", "a+") as f:
            reverse_module.write(f)
 
 
    def get_xml(self):
        return self.xml