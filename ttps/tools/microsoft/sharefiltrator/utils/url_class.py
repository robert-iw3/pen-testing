import asyncio
import os
from typing import List
from requests import Session
from aiofiles import open as aio_open
from datetime import datetime
import logging
from dataclasses import dataclass
from typing import Optional


@dataclass
class URL:
    path: str
    file_extension: Optional[str]
    url_class: str
    size: int = 0
    last_modified_time: Optional[str] = None

    async def download_file(
        self,
        headers: dict,
        cookies: dict,
        save_folder: str,
        semaphore: asyncio.Semaphore,
    ) -> None:
        if not self._should_download():
            return

        download_path = self._prepare_download_path(save_folder)
        if not download_path:
            return

        if await self._file_exists(download_path):
            logging.info("[*] Skipping '%s' - file already exists", download_path)
            return

        await self._perform_download(download_path, headers, cookies, semaphore)

    def _should_download(self) -> bool:
        return self.url_class is not None and "STS_ListItem" in self.url_class

    def _prepare_download_path(self, save_folder: str) -> Optional[str]:
        path_parts = self.path.split("/")
        if len(path_parts) <= 4:
            logging.warning("[*] Skipping '%s' - invalid path structure", self.path)
            return None

        return self._build_download_path(save_folder, path_parts)

    def _build_download_path(self, save_folder: str, path_parts: List[str]) -> str:
        if "personal" in path_parts[3]:
            folder_name = path_parts[4].replace(":", "_")
            relative_path = "/".join(path_parts[5:])
            sanitized_path = relative_path.replace("/", "_")
        else:
            relative_path = "/".join(path_parts[5:])
            folder_name = path_parts[4]
            sanitized_path = relative_path.replace("/", "_")

        return f"./{save_folder}/{folder_name}/{sanitized_path}"

    async def _file_exists(self, download_path: str) -> bool:
        return os.path.exists(download_path)

    async def _perform_download(
        self,
        download_path: str,
        headers: dict,
        cookies: dict,
        semaphore: asyncio.Semaphore,
    ) -> None:
        file_url = self.path

        async with semaphore:
            try:

                def fetch_file():
                    with Session() as session:
                        session.cookies.update(cookies)
                        response = session.get(url=file_url, headers=headers)
                        response.raise_for_status()
                        if response.status_code >= 400 and response.status_code < 500:
                            return None
                        return response.content

                response_content = await asyncio.to_thread(fetch_file)
            except Exception as e:
                logging.error("[!] Error fetching file: %s", e)
                return

            if response_content is None:
                logging.error("[!] Error fetching file: %s", self.path)
                return

        os.makedirs(os.path.dirname(download_path), exist_ok=True)

        try:
            async with aio_open(download_path, "wb") as f:
                await f.write(response_content)
        except Exception as e:
            logging.error("[!] Error writing file: %s", e)
            return

        logging.info("[+] Downloaded '%s'", download_path)

        if self.last_modified_time is not None:
            trimmed_time = self.last_modified_time[:-2] + "Z"
            last_modified_time = datetime.strptime(
                trimmed_time, "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            timestamp = last_modified_time.timestamp()
            os.utime(download_path, (timestamp, timestamp))


@staticmethod
async def download_files(urls: List[URL], headers, cookies, save_folder, max_threads):
    semaphore = asyncio.Semaphore(max_threads)
    tasks = [
        url.download_file(
            headers=headers,
            cookies=cookies,
            save_folder=save_folder,
            semaphore=semaphore,
        )
        for url in urls
        if url.size > 0 and url.file_extension is not None
    ]
    await asyncio.gather(*tasks)


@staticmethod
def create_directories(urls: List[URL], save_folder: str):
    unique_folders = set()
    for url in urls:
        if "STS_ListItem" in url.url_class:
            destination = url.path.split("/")[4].replace(":", "_")
            unique_folders.add(f"./{save_folder}/{destination}")

    if not os.path.exists(f"./{save_folder}/"):
        os.makedirs(f"./{save_folder}")

    for folder in unique_folders:
        if not os.path.exists(folder):
            os.makedirs(folder)


def _generate_timestamp():
    return datetime.now().strftime("%y%m%d%H%M%S%f")


def _sanitize_filename(filename: str, max_length: int = 80) -> str:
    name, extension = os.path.splitext(filename)
    special_chars = set('!@#$%^&*()={}[];:"|/,')
    name = "".join(c if c not in special_chars else "_" for c in name)
    if len(name) > max_length - len(extension):
        name = name[: max_length - len(extension)]
    return name + extension
