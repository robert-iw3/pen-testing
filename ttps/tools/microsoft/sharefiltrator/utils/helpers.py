import requests
import argparse
import json
import logging
from typing import List, Tuple, Optional
from utils.url_class import URL
from utils.options_class import Options
from utils.query_class import Query
from utils.constants import DEFAULT_HEADERS, DEFAULT_QUERY, DEFAULT_MAX_SIZE_MB, DEFAULT_MAX_THREADS


def save_lines_to_file(
    lines: List[URL],
    output_file: str,
    first_write_to_file: bool = False,
    query_name: str = None,
) -> bool:
    if first_write_to_file and query_name:
        try:
            with open(output_file, "a", encoding="utf-8") as f:
                if query_name:
                    f.write(f"\n\n######### Query: {query_name} #########\n")
        except Exception as e:
            logging.error(f"[-] Error writing to file: {e}")
            return False

    try:
        with open(output_file, "a", encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line.path}\n")
        logging.info(f"[+] Successfully wrote {len(lines)} results to {output_file}")
        return True
    except Exception as e:
        logging.error(f"[-] Error writing to file: {e}")
        return False


def load_json_presets(preset) -> List[dict]:
    try:
        with open(preset, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as e:
        logging.error(f"[-] Error loading preset file: {e}")
        raise e


def get_args():
    banner = r"""
   _____ _                    ______ _ _ _             _
  / ____| |                  |  ____(_) | |           | |
 | (___ | |__   __ _ _ __ ___| |__   _| | |_ _ __ __ _| |_ ___  _ __
  \___ \| '_ \ / _` | '__/ _ \  __| | | | __| '__/ _` | __/ _ \| '__|
  ____) | | | | (_| | | |  __/ |    | | | |_| | | (_| | || (_) | |
 |_____/|_| |_|\__,_|_|  \___|_|    |_|_|\__|_|  \__,_|\__\___/|_|
"""
    print(banner)
    print("Author: Yehuda Smirnov (@Yudasm_)")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        type=str,
        help="SharePoint domain (e.g., yourcompany.sharepoint.com)",
    )
    parser.add_argument(
        "-r", "--rtfa", required=True, type=str, help="rtFa cookie value"
    )
    parser.add_argument(
        "-f", "--fedauth", required=True, type=str, help="FedAuth cookie value"
    )
    parser.add_argument(
        "-o", "--output_file", required=True, type=str, help="Output file name for URLs"
    )
    parser.add_argument(
        "-q",
        "--query",
        default=DEFAULT_QUERY,
        type=str,
        help="Search query to use (default - finds sites & personal OneDrive folders which are shared)",
    )
    parser.add_argument(
        "-rq", "--refinement_filters", type=str, help="Refinement filters to use"
    )
    parser.add_argument(
        "-s",
        "--save",
        default=False,
        type=str,
        help="Folder name to download files found (example: 'files')",
    )
    parser.add_argument(
        "-t",
        "--max_threads",
        required=False,
        default=DEFAULT_MAX_THREADS,
        type=int,
        help="Max threads to use for file downloads (default: 10)",
    )
    parser.add_argument(
        "-m",
        "--max_size",
        required=False,
        default=DEFAULT_MAX_SIZE_MB,
        type=int,
        help="Max file size to download in MB (default: 20 MB, example: 100)",
    )
    parser.add_argument(
        "-p",
        "--preset",
        required=False,
        type=str,
        help="Preset file with a line seprated list of queries to run",
    )

    args = parser.parse_args()
    return args


def get_options_from_args(args):
    headers, cookies = setup_request_params(args)

    return Options(
        domain=args.domain,
        rtfa=args.rtfa,
        fedauth=args.fedauth,
        query=args.query,
        refinement_filters=args.refinement_filters,
        output_file=args.output_file,
        save_files=args.save,
        max_threads=args.max_threads,
        max_size=args.max_size * 1024 * 1024,
        preset=args.preset,
        headers=headers,
        cookies=cookies,
    )


def setup_request_params(options: Options) -> Tuple[dict, dict]:
    """Setup headers and cookies for requests"""
    headers = DEFAULT_HEADERS
    cookies = {
        "rtFa": options.rtfa.strip('"').strip("'"),
        "FedAuth": options.fedauth.strip('"').strip("'"),
    }
    return headers, cookies


def build_search_url(domain: str, query: Query, row_limit: int, start_row: int) -> str:
    """Build the SharePoint search URL"""
    base_url = f"https://{domain}/_api/search/query"
    params = f"?querytext='{query.querytext}'&rowlimit={row_limit}&startrow={start_row}"
    params += "&sortlist='LastModifiedTime:descending'"

    if query.refinementfilters:
        params += f"&refinementfilters='{query.refinementfilters}'"
    if query.enablefql:
        params += "&enablefql=true"

    return base_url + params


def perform_search_request(
    options: Options, query: Query, row_limit: int, start_row: int
) -> Optional[dict]:
    """Perform search request with error handling"""
    url = build_search_url(options.domain, query, row_limit, start_row)

    try:
        response = requests.get(url, headers=options.headers, cookies=options.cookies)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error("[!] Search request failed: %s", e)
        if response.status_code == 403:
            logging.error("[!] Authentication failed. Check rtFa and FedAuth cookies.")
            raise SystemExit(1)
        return None


def parse_search_results(search_results, total_rows):
    primary_query_result = (
        search_results.get("d", {}).get("query", {}).get("PrimaryQueryResult", {})
    )
    relevant_results = (
        primary_query_result.get("RelevantResults", {})
        .get("Table", {})
        .get("Rows", {})
        .get("results", [])
    )

    if total_rows is None:
        total_rows = primary_query_result.get("RelevantResults", {}).get("TotalRows", 0)
        if total_rows == 0:
            return [], 0

    return relevant_results, total_rows


def extract_site_urls(relevant_results, max_size) -> List[URL]:
    site_urls = []
    for result in relevant_results:
        cells = result.get("Cells", {}).get("results", [])
        temp_url = URL(None, None, None)
        parent_link = None
        temp_path = None
        file_name = None
        for cell in cells:
            if (
                temp_url.path is not None
                and temp_url.file_extension is not None
                and temp_url.url_class is not None
                and temp_url.size is not None
                and temp_url.last_modified_time is not None
            ):
                break
            if cell.get("Key") == "Path":
                temp_path = cell.get("Value")
            if cell.get("Key") == "ParentLink":
                parent_link = cell.get("Value")
            if cell.get("Key") == "Title":
                file_name = cell.get("Value")
            elif cell.get("Key") == "FileType":
                temp_url.file_extension = cell.get("Value")
            elif cell.get("Key") == "contentclass":
                temp_url.url_class = cell.get("Value")
            elif cell.get("Key") == "Size":
                try:
                    temp_url.size = int(cell.get("Value"))
                except (ValueError, TypeError):
                    temp_url.size = 0  # or handle the error as needed
            elif cell.get("Key") == "LastModifiedTime":
                temp_url.last_modified_time = cell.get("Value")
        if temp_url.size is None or temp_url.size > max_size:
            # print(f"[!] Skipping a file due to size: {temp_url.size}")
            continue

        if parent_link is None and temp_path is not None:
            parent_link = temp_path

        if (
            file_name is not None
            and parent_link is not None
            and temp_url.url_class is not None
        ):
            temp_url.path = parent_link

            if temp_url.size > 0:
                if file_name != "DispForm.aspx":
                    temp_url.path += f"/{file_name}"
                else:
                    temp_url.path += "/"

                if (
                    temp_url.file_extension is not None
                    and _check_if_extension_required(
                        temp_url.path, temp_url.file_extension
                    )
                ):
                    temp_url.path += f".{temp_url.file_extension}"

            site_urls.append(temp_url)
        else:
            logging.info(f"[*] Skipping a file due to extension or file name, path")
    return site_urls


def _check_if_extension_required(path, file_extension):
    if path.endswith(file_extension):
        return False
    return True


def _fix_download_path(download_path):
    parts = download_path.split(".")
    if len(parts) > 2 and parts[-1] == parts[-2]:
        download_path = ".".join(parts[:-1])

    return download_path
