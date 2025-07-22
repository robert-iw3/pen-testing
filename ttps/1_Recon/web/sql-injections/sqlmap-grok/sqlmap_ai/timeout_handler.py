from sqlmap_ai.ui import (
    print_warning, 
    print_info, 
    handle_timeout_ui, 
    handle_no_data_timeout_ui
)
def handle_timeout_response(report, target_url, runner):
    print_warning("The scan timed out. This could be due to several reasons:")
    print("1. The target application might be slow to respond")
    print("2. Network latency issues")
    print("3. Intrusion prevention systems or WAFs might be blocking the scan")
    print("4. The target might be performing complex operations that take longer")
    print_info("\nRecommended actions:")
    if report and report.startswith("TIMEOUT_WITH_PARTIAL_DATA:"):
        fallback_opts = runner.fallback_options_for_timeout(target_url)
        choice, new_timeout = handle_timeout_ui(fallback_opts, target_url)
        if choice == '1':
            return True, report
        elif choice == '2':
            new_report = runner.run_sqlmap(target_url, fallback_opts, timeout=new_timeout)
            return True, new_report
        elif choice == '3':
            new_report = runner.run_sqlmap(target_url, ["--fingerprint", "--dbs"], timeout=new_timeout)
            return True, new_report
        else:
            print_warning("Invalid choice. Stopping here.")
            return False, None
    else:
        choice, new_timeout, fallback_opts = handle_no_data_timeout_ui(target_url)
        if choice == '1':
            new_report = runner.run_sqlmap(target_url, fallback_opts, timeout=new_timeout)
            return True, new_report
        elif choice == '2':
            new_report = runner.run_sqlmap(target_url, ["--fingerprint", "--dbs"], timeout=new_timeout)
            return True, new_report
        elif choice == '3':
            print_info("Please restart the script with a different URL or parameter.")
            return False, None
        else:
            print_warning("Invalid choice. Stopping here.")
            return False, None 