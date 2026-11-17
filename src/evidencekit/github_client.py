from types import TracebackType
from typing import Any, Self

import httpx

API_URL = "https://api.github.com"
API_VERSION = "2022-11-28"
PAGE_SIZE = 100
TIMEOUT_SECONDS = 30


class GitHubClient:
    def __init__(self, token: str, transport: httpx.BaseTransport | None = None) -> None:
        self._http = httpx.Client(
            base_url=API_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
            },
            timeout=TIMEOUT_SECONDS,
            transport=transport,
        )

    def get(self, path: str) -> httpx.Response:
        return self._http.get(path)

    def get_json(self, path: str) -> Any:
        response = self._http.get(path)
        response.raise_for_status()
        return response.json()

    def paginate(self, path: str) -> list[Any]:
        response = self._page(path, {"per_page": PAGE_SIZE})
        items = list(response.json())
        while next_url := response.links.get("next", {}).get("url"):
            response = self._page(next_url)
            items.extend(response.json())
        return items

    def _page(self, url: str, params: dict[str, int] | None = None) -> httpx.Response:
        response = self._http.get(url, params=params)
        response.raise_for_status()
        return response

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
