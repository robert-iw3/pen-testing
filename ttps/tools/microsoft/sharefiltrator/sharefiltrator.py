import asyncio
import logging
from typing import Optional, List

from utils.helpers import (
    perform_search_request,
    parse_search_results,
    extract_site_urls,
    get_args,
    save_lines_to_file,
    load_json_presets,
    get_options_from_args,
)
from utils.url_class import URL, download_files
from utils.query_class import Query
from utils.options_class import Options
from utils.constants import DEFAULT_ROW_LIMIT

logging.basicConfig(level=logging.INFO)


async def try_download_files(site_urls, options):
    try:
        await download_files(
            urls=site_urls,
            headers=options.headers,
            cookies=options.cookies,
            save_folder=options.save_files,
            max_threads=options.max_threads,
        )
    except Exception as e:
        logging.error("[-] Error during file download: %s", e)


async def process_search_results(
    options: Options, query: Query, start_row: int
) -> tuple[List[URL], int, Optional[int]]:
    """Process a single page of search results"""
    search_results = perform_search_request(
        options=options, query=query, row_limit=DEFAULT_ROW_LIMIT, start_row=start_row
    )
    if not search_results:
        return [], start_row, None

    relevant_results, total_rows = parse_search_results(search_results, None)
    site_urls = extract_site_urls(relevant_results, options.max_size)

    return site_urls, len(relevant_results), total_rows


async def run_query(options: Options, query: Query = None) -> None:
    """Execute a single search query"""
    query = query or Query(options.query, options.refinement_filters, False)
    start_row = 0
    total_rows = None
    processed_count = 0
    first_write = True

    while True:
        site_urls, results_count, total_rows = await process_search_results(
            options, query, start_row
        )
        if not site_urls:
            break

        save_lines_to_file(
            site_urls,
            options.output_file,
            first_write_to_file=first_write,
            query_name=query.queryname,
        )
        first_write = False

        if options.save_files:
            await try_download_files(site_urls, options)

        processed_count += len(site_urls)
        start_row += results_count

        logging.info("[+] Processed %d results so far...", processed_count)

        if start_row >= total_rows:
            logging.info("[+] Finished processing all search results")
            break


async def main():
    args = get_args()
    options = get_options_from_args(args)
    preset = args.preset

    if preset:
        preset_queries = load_json_presets(preset)
        queries = [Query.from_json(q.get("Request")) for q in preset_queries]

        for q in queries:
            logging.info("[+] Running query: %s", q)
            await run_query(options=options, query=q)
    else:
        logging.info("[+] Running query: %s", options.query)
        await run_query(options=options)


if __name__ == "__main__":
    asyncio.run(main())
