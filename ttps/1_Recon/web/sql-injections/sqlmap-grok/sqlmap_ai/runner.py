import os
import sys
import time
import json
import requests
from typing import List, Dict, Any, Optional, Union
from sqlmap_ai.ui import print_info, print_warning, print_error, print_success

class SQLMapAPIRunner:
    def __init__(self):
        self.script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.sqlmap_path = os.path.join(self.script_dir, "sqlmap")
        self.sqlmap_api_script = os.path.join(self.sqlmap_path, "sqlmapapi.py")
        self.api_server = "http://127.0.0.1:8775"
        self.current_task_id = None
        
        if not os.path.exists(self.sqlmap_api_script):
            print_error(f"sqlmapapi.py not found in {self.sqlmap_path}. Make sure sqlmap is in the correct directory.")
            sys.exit(1)
        
        # Start API server if not already running
        self._start_api_server()

    def _start_api_server(self):
        """Start the sqlmapapi server if not already running."""
        import subprocess
        try:
            # Check if the server is already running
            response = requests.get(f"{self.api_server}/admin/0/version")
            if response.status_code == 200:
                print_info("SQLMap API server is already running.")
                return
        except:
            print_info("Starting SQLMap API server...")
            subprocess.Popen(
                [sys.executable, self.sqlmap_api_script, "-s"], 
                cwd=self.script_dir
            )
            time.sleep(2)  # Wait for the server to start

    def _create_new_task(self) -> Optional[str]:
        """Create a new scan task and return its ID."""
        try:
            response = requests.get(f"{self.api_server}/task/new")
            data = response.json()
            
            if data["success"]:
                task_id = data["taskid"]
                print_info(f"Created new task with ID: {task_id}")
                self.current_task_id = task_id
                return task_id
            else:
                print_error("Failed to create new task")
                return None
        except Exception as e:
            print_error(f"Error creating new task: {str(e)}")
            return None

    def _start_scan(self, task_id: str, target_url: str, options: Union[List[str], str]) -> bool:
        """Start a scan for the specified target with given options."""
        scan_options = {
            "url": target_url,
            "flushSession": True,
            "getBanner": True,
        }
        
        # Process options list into a dictionary
        if isinstance(options, list):
            for opt in options:
                if opt.startswith("--batch"):
                    scan_options["batch"] = True
                elif opt.startswith("--threads="):
                    scan_options["threads"] = int(opt.split("=")[1])
                elif opt.startswith("--dbms="):
                    scan_options["dbms"] = opt.split("=")[1]
                elif opt.startswith("--level="):
                    scan_options["level"] = int(opt.split("=")[1])
                elif opt.startswith("--risk="):
                    scan_options["risk"] = int(opt.split("=")[1])
                elif opt.startswith("--technique="):
                    scan_options["technique"] = opt.split("=")[1]
                elif opt.startswith("--time-sec="):
                    scan_options["timeSec"] = int(opt.split("=")[1])
                elif opt.startswith("--tamper="):
                    scan_options["tamper"] = opt.split("=")[1]
                elif opt == "--fingerprint":
                    scan_options["getBanner"] = True
                    scan_options["getDbms"] = True
                elif opt == "--dbs":
                    scan_options["getDbs"] = True
                elif opt == "--tables":
                    scan_options["getTables"] = True
                elif opt == "--dump":
                    scan_options["dump"] = True
                elif opt == "--identify-waf":
                    scan_options["identifyWaf"] = True
                elif opt == "--forms":
                    scan_options["forms"] = True
                elif opt == "--common-tables":
                    scan_options["getCommonTables"] = True
                elif opt == "--common-columns":
                    scan_options["getCommonColumns"] = True
                elif opt.startswith("-D "):
                    scan_options["db"] = opt[3:]
                elif opt.startswith("-T "):
                    scan_options["tbl"] = opt[3:]
                elif opt.startswith("-C "):
                    scan_options["col"] = opt[3:]
                elif opt.startswith("--data=") or opt.startswith("--data "):
                    data_value = opt.split("=")[1] if "=" in opt else opt[7:]
                    scan_options["data"] = data_value
                elif opt.startswith("--cookie=") or opt.startswith("--cookie "):
                    cookie_value = opt.split("=")[1] if "=" in opt else opt[9:]
                    scan_options["cookie"] = cookie_value
                elif opt.startswith("--headers=") or opt.startswith("--headers "):
                    headers_value = opt.split("=")[1] if "=" in opt else opt[10:]
                    scan_options["headers"] = headers_value
                elif opt == "--is-dba":
                    scan_options["isDba"] = True
                elif opt == "--current-user":
                    scan_options["getCurrentUser"] = True
                elif opt == "--privileges":
                    scan_options["getPrivileges"] = True
                elif opt == "--schema":
                    scan_options["getSchema"] = True
                elif opt == "--json":
                    # Handle JSON request format - already using JSON so just note it
                    pass
        elif isinstance(options, str):
            # If options is a string, split and process the same way
            self._start_scan(task_id, target_url, options.split())
            return True

        # Set some defaults if not specified
        if "threads" not in scan_options:
            scan_options["threads"] = 5
        if "level" not in scan_options:
            scan_options["level"] = 1
        if "risk" not in scan_options:
            scan_options["risk"] = 1
        if "batch" not in scan_options:
            scan_options["batch"] = True
            
        try:
            headers = {"Content-Type": "application/json"}
            response = requests.post(
                f"{self.api_server}/scan/{task_id}/start",
                data=json.dumps(scan_options),
                headers=headers
            )
            data = response.json()
            
            if data["success"]:
                print_info(f"Scan started for task ID: {task_id}")
                return True
            else:
                print_error(f"Failed to start scan for task ID: {task_id}")
                print_error(f"Error: {data.get('message', 'Unknown error')}")
                return False
        except Exception as e:
            print_error(f"Error starting scan: {str(e)}")
            return False

    def _get_scan_status(self, task_id: str) -> Optional[str]:
        """Get the status of a scan."""
        try:
            response = requests.get(f"{self.api_server}/scan/{task_id}/status")
            data = response.json()
            
            if data["success"]:
                return data["status"]
            else:
                print_error(f"Failed to get status for task ID: {task_id}")
                return None
        except Exception as e:
            print_error(f"Error getting scan status: {str(e)}")
            return None

    def _get_scan_data(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get the scan results."""
        try:
            response = requests.get(f"{self.api_server}/scan/{task_id}/data")
            data = response.json()
            
            if data["success"]:
                return data["data"]
            else:
                print_error(f"Failed to get data for task ID: {task_id}")
                return None
        except Exception as e:
            print_error(f"Error getting scan data: {str(e)}")
            return None

    def _delete_task(self, task_id: str) -> bool:
        """Delete a task."""
        try:
            response = requests.get(f"{self.api_server}/task/{task_id}/delete")
            data = response.json()
            
            if data["success"]:
                print_info(f"Task {task_id} deleted successfully")
                return True
            else:
                print_error(f"Failed to delete task {task_id}")
                return False
        except Exception as e:
            print_error(f"Error deleting task: {str(e)}")
            return False

    def _monitor_scan(self, task_id: str, timeout: int = 120, interactive_mode: bool = False) -> Optional[str]:
        """Monitor the scan until it completes or times out."""
        start_time = time.time()
        last_output_time = start_time
        spinner_chars = ['|', '/', '-', '\\']
        spinner_idx = 0
        last_spinner_update = time.time()
        spinner_interval = 0.2
        last_progress_message = ""
        
        print_info("Starting SQLMap scan...")
        print_info("Running", end='', flush=True)
        
        try:
            while True:
                current_time = time.time()
                if current_time - last_spinner_update >= spinner_interval:
                    print(f"\b{spinner_chars[spinner_idx]}", end='', flush=True)
                    spinner_idx = (spinner_idx + 1) % len(spinner_chars)
                    last_spinner_update = current_time
                
                elapsed_time = current_time - start_time
                
                if elapsed_time > timeout:
                    print("\b \nSQLMap command timeout after {:.1f} seconds".format(elapsed_time))
                    print_warning(f"SQLMap command timeout after {elapsed_time:.1f} seconds")
                    return "TIMEOUT: Command execution exceeded time limit"
                
                status = self._get_scan_status(task_id)
                
                if status == "running":
                    # Optionally get log data to show progress
                    if interactive_mode and current_time - last_output_time > 5:
                        log_data = self._get_scan_logs(task_id)
                        if log_data:
                            last_lines = log_data.splitlines()[-5:]
                            for line in last_lines:
                                if line and line != last_progress_message:
                                    print("\b \b", end='', flush=True)
                                    print(f"\r\033[K{line}")
                                    print("Running", end='', flush=True)
                                    last_progress_message = line
                        last_output_time = current_time
                    time.sleep(1)
                    continue
                elif status == "terminated":
                    print("\b \nScan completed")
                    break
                else:
                    print(f"\b \nUnexpected status: {status}")
                    break
                
                time.sleep(0.5)
            
            print("\b \b", end='', flush=True)
            print()  # New line after spinner
            
            # Get the results
            result_data = self._get_scan_data(task_id)
            if not result_data:
                return None
            
            # Convert API response to a format similar to CLI output
            formatted_output = self._format_api_data(result_data)
            return formatted_output
            
        except KeyboardInterrupt:
            print("\b \b", end='', flush=True)
            print("\nProcess interrupted by user")
            print_warning("\nProcess interrupted by user")
            return "INTERRUPTED: Process was stopped by user"
        except Exception as e:
            print("\b \b", end='', flush=True)
            print_error(f"Error monitoring scan: {str(e)}")
            return None

    def _get_scan_logs(self, task_id: str) -> Optional[str]:
        """Get the scan logs."""
        try:
            response = requests.get(f"{self.api_server}/scan/{task_id}/log")
            data = response.json()
            
            if data["success"]:
                return "\n".join(entry["message"] for entry in data["log"])
            else:
                return None
        except:
            return None

    def _format_api_data(self, data: List[Dict[str, Any]]) -> str:
        """Format the API response data to a string similar to CLI output."""
        output_lines = []
        
        # Map of API data types to formatted sections
        type_map = {
            1: "vulnerable parameters",
            2: "back-end DBMS",
            3: "banner",
            4: "current user",
            5: "current database",
            6: "hostname",
            7: "is DBA",
            8: "users",
            9: "passwords",
            10: "privileges",
            11: "roles",
            12: "databases",
            13: "tables",
            14: "columns",
            15: "schema",
            16: "count",
            17: "dump table",
            18: "dump",
            19: "search",
            20: "SQL query",
            21: "common tables",
            22: "common columns",
            23: "file read",
            24: "file write",
            25: "os cmd",
            26: "reg key",
            27: "reg value",
            28: "reg data",
            29: "reg enum"
        }
        
        # Process each data entry by type
        for entry in data:
            entry_type = entry.get("type")
            value = entry.get("value")
            
            if entry_type == 1:  # Vulnerable parameters
                output_lines.append("[+] the following parameters are vulnerable to SQL injection:")
                for vuln in value:
                    output_lines.append(f"    Parameter: {vuln.get('parameter')} ({vuln.get('place')})")
                    if vuln.get("payload"):
                        output_lines.append(f"    Payload: {vuln.get('payload')}")
                
            elif entry_type == 2:  # DBMS
                output_lines.append(f"[+] back-end DBMS: {value}")
                
            elif entry_type == 3:  # Banner
                output_lines.append(f"[+] banner: {value}")
                
            elif entry_type == 4:  # Current user
                output_lines.append(f"[+] current user: {value}")
                
            elif entry_type == 7:  # Is DBA
                output_lines.append(f"[+] is DBA: {'yes' if value else 'no'}")
                
            elif entry_type == 12:  # Databases
                output_lines.append(f"[+] available databases [{len(value)}]:")
                for db in value:
                    output_lines.append(f"[*] {db}")
                    
            elif entry_type == 13:  # Tables
                output_lines.append(f"[+] Database: {list(value.keys())[0]}")
                tables = list(value.values())[0]
                output_lines.append(f"[+] tables [{len(tables)}]:")
                for i, table in enumerate(tables):
                    output_lines.append(f"[{i+1}] {table}")
                    
            elif entry_type == 14:  # Columns
                for db, tables in value.items():
                    output_lines.append(f"[+] Database: {db}")
                    for table, columns in tables.items():
                        output_lines.append(f"[+] Table: {table}")
                        output_lines.append(f"[+] columns [{len(columns)}]:")
                        for i, column in enumerate(columns):
                            output_lines.append(f"[{i+1}] {column}")
                            
            elif entry_type == 18:  # Dump
                for db, tables in value.items():
                    output_lines.append(f"[+] Database: {db}")
                    for table, data in tables.items():
                        output_lines.append(f"[+] Table: {table}")
                        output_lines.append(f"[+] [{len(data.get('entries', []))} entries]")
                        columns = data.get("columns", [])
                        entries = data.get("entries", [])
                        
                        # Create table header
                        header = "| " + " | ".join(columns) + " |"
                        separator = "+" + "+".join(["-" * (len(col) + 2) for col in columns]) + "+"
                        output_lines.append(separator)
                        output_lines.append(header)
                        output_lines.append(separator)
                        
                        # Add data rows
                        for entry in entries:
                            row = "| " + " | ".join(str(entry.get(col, "NULL")) for col in columns) + " |"
                            output_lines.append(row)
                        output_lines.append(separator)
            
            elif entry_type == 24:  # Common tables
                output_lines.append(f"[+] found common tables: {', '.join(value)}")
                
            elif entry_type == 25:  # Common columns
                output_lines.append(f"[+] found common columns: {', '.join(value)}")
            
            # Add more type handlers as needed
        
        return "\n".join(output_lines)

    def run_sqlmap(self, target_url: str, options: Union[List[str], str], timeout: int = 180, interactive_mode: bool = False) -> Optional[str]:
        """Run sqlmap with API against the target URL and return the results."""
        task_id = self._create_new_task()
        if not task_id:
            return None
            
        command_str = f"sqlmap -u {target_url}"
        if isinstance(options, list):
            command_str += " " + " ".join(options)
        else:
            command_str += " " + options
            
        print_info(f"Executing SQLMap command: {command_str}")
        print_info(f"Timeout set to {timeout} seconds. Press Ctrl+C to cancel.")
        
        if not self._start_scan(task_id, target_url, options):
            self._delete_task(task_id)
            return None
            
        result = self._monitor_scan(task_id, timeout, interactive_mode)
        
        # Clean up task
        self._delete_task(task_id)
        
        if result:
            if not interactive_mode:
                result_lines = result.split('\n')
                if len(result_lines) > 20:
                    print("\n".join(result_lines[-20:]))
                    print_info("Showing last 20 lines of output. Full results will be analyzed.")
                else:
                    print(result)
            print_success("SQLMap execution completed")
            return result
        else:
            print_error("SQLMap execution failed")
            return None

    def gather_info(self, target_url: str, timeout: int = 120, interactive: bool = False) -> Optional[str]:
        """Run basic fingerprinting and database enumeration."""
        print_info("Running basic fingerprinting and database enumeration...")
        print_info("This will identify the database type and list available databases.")
        print_info("If scan takes too long, you can press Ctrl+C to interrupt it")
        
        try:
            result = self.run_sqlmap(
                target_url=target_url, 
                options=["--fingerprint", "--dbs", "--threads=5"], 
                timeout=timeout,
                interactive_mode=interactive
            )
            return result
        except Exception as e:
            print_error(f"Error running basic scan: {str(e)}")
            return None

    def fallback_options_for_timeout(self, target_url: str) -> Optional[str]:
        """Run with more focused options after a timeout."""
        print_info("Original scan timed out. Running with more focused options...")
        print_info("This will attempt a faster scan with fewer test vectors.")
        
        fallback_options = [
            "--technique=BT",   
            "--level=1",        
            "--risk=1",         
            "--time-sec=1",     
            "--timeout=10",     
            "--retries=1",      
            "--threads=8",      
            "--dbs"             
        ]
        
        try:
            result = self.run_sqlmap(
                target_url=target_url, 
                options=fallback_options,
                timeout=90
            )
            return result
        except Exception as e:
            print_error(f"Error running fallback scan: {str(e)}")
            return None

# Alias for backward compatibility
SQLMapRunner = SQLMapAPIRunner 