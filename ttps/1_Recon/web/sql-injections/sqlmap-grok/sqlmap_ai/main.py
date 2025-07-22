import time
import argparse
from sqlmap_ai.ui import (
    print_banner, 
    print_info, 
    print_success, 
    print_error, 
    print_warning,
    get_target_url,
    get_timeout,
    get_interactive_mode,
    get_user_choice,
    confirm_save_report
)
from sqlmap_ai.runner import SQLMapRunner
from sqlmap_ai.parser import display_report, save_report_to_file, extract_sqlmap_info, create_json_report
from sqlmap_ai.ai_analyzer import ai_suggest_next_steps
from sqlmap_ai.timeout_handler import handle_timeout_response
from sqlmap_ai.adaptive_testing import run_adaptive_test_sequence
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="SQLMap AI Assistant")
    parser.add_argument("--adaptive", action="store_true", help="Run with adaptive step-by-step testing")
    parser.add_argument("--timeout", type=int, help="Set custom timeout in seconds (default: 120)")
    args = parser.parse_args()
    target_url = get_target_url()
    if args.timeout:
        user_timeout = args.timeout
        print_info(f"Using timeout of {user_timeout} seconds from command line argument")
    else:
        user_timeout = get_timeout()
    interactive_mode = get_interactive_mode()
    runner = SQLMapRunner()
    if args.adaptive:
        run_adaptive_mode(runner, target_url, user_timeout, interactive_mode)
    else:
        run_standard_mode(runner, target_url, user_timeout, interactive_mode)
def run_adaptive_mode(runner, target_url, user_timeout, interactive_mode):
    print_info("Starting adaptive step-by-step testing sequence...")
    print_info("This mode will automatically sequence through multiple testing phases")
    result = run_adaptive_test_sequence(
        runner=runner,
        target_url=target_url,
        interactive_mode=interactive_mode,
        timeout=user_timeout
    )
    if result and result.get("success", False):
        if result.get("partial", False):
            print_warning("Adaptive testing completed with partial success.")
            print_info("Summary of findings:")
            if "databases_found" in result:
                print_success(f"Databases found: {', '.join(result['databases_found'])}")
                print_warning("However, tables could not be enumerated. This can happen when:")
                print_warning("1. The database is empty")
                print_warning("2. There are WAF/IPS protections against table enumeration")
                print_warning("3. The SQL injection vulnerability is limited in scope")
                print_info("The scan output is still saved for your reference.")
            if confirm_save_report():
                print_info("Creating detailed report with structured data...")
                base_filename = f"sqlmap_adaptive_partial_report_{int(time.time())}"
                text_filename = f"{base_filename}.txt"
                json_filename = f"{base_filename}.json"
                try:
                    report_content = "\n".join([f"{k}: {v}" for k, v in result.items() if k != "scan_history"])
                    report_content += "\n\nScan History:\n"
                    for step in result.get("scan_history", []):
                        report_content += f"\nStep: {step.get('step', 'unknown')}\n"
                        report_content += f"Command: {step.get('command', 'N/A')}\n"
                    with open(text_filename, "w") as f:
                        f.write(report_content)
                    print_success(f"Report saved to {text_filename}")
                    last_step = result.get("scan_history", [])[-1] if result.get("scan_history") else {}
                    last_result = last_step.get("result", {})
                    json_report = create_json_report(last_result, result.get("scan_history", []))
                    save_report_to_file(json_report, json_filename)
                    print_success(f"Structured JSON report saved to {json_filename}")
                    print_info("The JSON report format is optimized for AI analysis with Groq.")
                except Exception as e:
                    print_error(f"Failed to save report: {str(e)}")
        else:
            print_success("Adaptive testing completed successfully!")
            print_info("Summary of findings:")
            for step in result.get("scan_history", []):
                if "result" in step and "databases" in step["result"]:
                    if step["result"]["databases"]:
                        print_success(f"Databases found: {', '.join(step['result']['databases'])}")
            if "extracted_data" in result:
                for table, data in result["extracted_data"].items():
                    print_success(f"Data extracted from table: {table}")
                    if "columns" in data:
                        print_info(f"Columns: {', '.join(data['columns'])}")
            if confirm_save_report():
                print_info("Creating detailed report with structured data...")
                base_filename = f"sqlmap_adaptive_report_{int(time.time())}"
                text_filename = f"{base_filename}.txt"
                json_filename = f"{base_filename}.json"
                try:
                    report_content = "\n".join([f"{k}: {v}" for k, v in result.items() if k != "scan_history"])
                    report_content += "\n\nScan History:\n"
                    for step in result.get("scan_history", []):
                        report_content += f"\nStep: {step.get('step', 'unknown')}\n"
                        report_content += f"Command: {step.get('command', 'N/A')}\n"
                    with open(text_filename, "w") as f:
                        f.write(report_content)
                    print_success(f"Report saved to {text_filename}")
                    last_step = result.get("scan_history", [])[-1] if result.get("scan_history") else {}
                    last_result = last_step.get("result", {})
                    json_report = create_json_report(last_result, result.get("scan_history", []))
                    save_report_to_file(json_report, json_filename)
                    print_success(f"Structured JSON report saved to {json_filename}")
                    print_info("The JSON report format is optimized for AI analysis with Groq.")
                except Exception as e:
                    print_error(f"Failed to save report: {str(e)}")
    else:
        print_error("Adaptive testing failed. Check target URL and try again.")
        if result and "message" in result:
            print_info(f"Error: {result['message']}")
def run_standard_mode(runner, target_url, user_timeout, interactive_mode):
    print_info("Starting initial reconnaissance...")
    scan_history = []
    extracted_data = {}
    report = runner.gather_info(target_url, timeout=user_timeout, interactive=interactive_mode)
    if report:
        print_success("Initial reconnaissance completed!")
        initial_info = extract_sqlmap_info(report)
        scan_history.append({
            "step": "initial_reconnaissance",
            "command": f"sqlmap -u {target_url} --fingerprint --dbs",
            "result": initial_info
        })
        if "TIMEOUT:" in report:
            continue_scan, updated_report = handle_timeout_response(report, target_url, runner)
            if not continue_scan:
                return
            if updated_report:
                report = updated_report
                timeout_info = extract_sqlmap_info(updated_report)
                scan_history.append({
                    "step": "timeout_fallback",
                    "command": "Fallback scan after timeout",
                    "result": timeout_info
                })
        if "INTERRUPTED:" in report:
            print_warning("Scan was interrupted by user. Stopping here.")
            return
        display_report(report)
        print_info("Analyzing results with Groq AI and determining next steps...")
        next_options = ai_suggest_next_steps(
            report=report, 
            scan_history=scan_history,
            extracted_data=extracted_data
        )
        if next_options:
            user_options = get_user_choice(next_options)
            if user_options:
                print_info("Running follow-up scan...")
                second_timeout = int(user_timeout * 1.5)
                result = runner.run_sqlmap(target_url, user_options, timeout=second_timeout, interactive_mode=interactive_mode)
                if result and "TIMEOUT:" in result:
                    print_warning("Follow-up scan timed out.")
                    print_info("You may still get useful results from the partial scan data.")
                if result:
                    print_success("Test completed successfully!")
                    followup_info = extract_sqlmap_info(result)
                    scan_history.append({
                        "step": "follow_up_scan",
                        "command": f"sqlmap -u {target_url} {user_options}",
                        "result": followup_info
                    })
                    display_report(result)
                    if (
                        followup_info.get("tables") 
                        and followup_info.get("columns")
                        and confirm_additional_step()
                    ):
                        print_info("Starting data extraction...")
                        extraction_options = f"--dump -T {','.join(followup_info['tables'][:3])}"
                        extraction_result = runner.run_sqlmap(
                            target_url, 
                            extraction_options, 
                            timeout=second_timeout,
                            interactive_mode=interactive_mode
                        )
                        if extraction_result:
                            print_success("Data extraction completed!")
                            extraction_info = extract_sqlmap_info(extraction_result)
                            scan_history.append({
                                "step": "data_extraction",
                                "command": f"sqlmap -u {target_url} {extraction_options}",
                                "result": extraction_info
                            })
                            if extraction_info.get("extracted"):
                                extracted_data.update(extraction_info["extracted"])
                            display_report(extraction_result)
                    if confirm_save_report():
                        print_info("Creating report file...")
                        filename = f"sqlmap_report_{int(time.time())}.json"
                        try:
                            json_report = create_json_report(followup_info, scan_history)
                            save_report_to_file(json_report, filename)
                            print_success(f"Report saved to {filename}")
                        except Exception as e:
                            print_error(f"Failed to save report: {str(e)}")
                else:
                    print_error("Follow-up test failed. Check SQLMap output for details.")
        else:
            print_warning("No clear vulnerabilities found. Try different parameters or advanced options.")
    else:
        print_error("Initial test failed. Check target URL and try again.")
def confirm_additional_step():
    while True:
        choice = input("\nWould you like to extract data from discovered tables? (y/n): ").lower()
        if choice in ["y", "yes"]:
            return True
        elif choice in ["n", "no"]:
            return False
        else:
            print("Please answer with 'y' or 'n'.")
if __name__ == "__main__":
    main() 