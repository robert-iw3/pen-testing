import threading
import io
from contextlib import redirect_stdout, redirect_stderr
from colorama import Fore, Style

brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"

# Dictionary to track background jobs: job_id -> {'thread': Thread, 'name': module_name, 'buffer': StringIO}
BACKGROUND_JOBS = {}
_job_counter = 1


def _bg_wrapper(job_id, mod):
    """Internal helper to run a module in a background thread and capture its output."""
    buf = BACKGROUND_JOBS[job_id]['buffer']
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            mod.run()
    except Exception as e:
        print(brightred + f"[-] Background error in {mod.name}: {e}", file=buf)


def run_in_background(mod):
    """
    Start the given module in a daemon thread, capture its stdout/stderr, and track it.
    Returns the job ID.
    """
    global _job_counter
    job_id = _job_counter
    _job_counter += 1

    # Prepare an in-memory buffer for output
    buf = io.StringIO()
    thread = threading.Thread(target=_bg_wrapper, args=(job_id, mod), daemon=True)

    # Store job details
    BACKGROUND_JOBS[job_id] = {'thread': thread, 'name': mod.name, 'buffer': buf}

    thread.start()
    print(brightgreen + f"[*] {mod.name} started as job [{job_id}]")
    return job_id


def list_jobs():
    """
    Print all background jobs in a table: ID, Module, Status.
    """
    # Header
    print(f"{'ID':<3}  {'Module':<23}  Status")
    print(f"{'--':<3}  {'-'*23}  {'-'*6}")

    for job_id, info in BACKGROUND_JOBS.items():
        thread = info['thread']
        name = info['name']
        status = 'running' if thread.is_alive() else 'done'
        print(f"{job_id:<3}  {name:<23}  {status}")


def get_job_output(job_id):
    """
    Return the captured stdout/stderr of the specified background job, or None if not found.
    """
    info = BACKGROUND_JOBS.get(job_id)
    if not info:
        return None
    return info['buffer'].getvalue()


def wait_for_job(job_id, timeout=None):
    """
    Block until the specified job finishes or timeout expires, then print completion status.
    """
    info = BACKGROUND_JOBS.get(job_id)
    if not info:
        print(brightred + f"[!] No such job: {job_id}")
        return

    thread = info['thread']
    name = info['name']
    thread.join(timeout)

    if thread.is_alive():
        print(brightyellow + f"[!] Job [{job_id}] ({name}) still running")
    else:
        print(brightgreen + f"[+] Job [{job_id}] ({name}) completed")
