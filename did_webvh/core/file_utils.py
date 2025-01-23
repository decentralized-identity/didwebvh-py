"""File access helpers."""

import os
import re
from asyncio import get_running_loop
from codecs import getincrementaldecoder
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from io import FileIO, StringIO
from pathlib import Path
from typing import TypeAlias

import aiohttp
import aiohttp.helpers

CHUNK_SIZE = 16384
NL = re.compile(r"^([^\r\n]*)(\r\n?|\n)(.*)$", flags=re.DOTALL | re.MULTILINE)


AsyncTextGenerator: TypeAlias = AsyncGenerator["AsyncTextReader", None]


class AsyncTextReadError(Exception):
    """An exception raised by an async text reader."""

    def __init__(self, *args, **extra):
        """Constructor."""
        super().__init__(*args)
        self.extra = extra


@asynccontextmanager
async def read_str(value: str | StringIO) -> AsyncTextGenerator:
    """Provide the async text reading interface over a string."""
    yield AsyncTextReader(init=value)


@asynccontextmanager
async def read_text_file(
    path: str | Path, *, chunk_size: int = CHUNK_SIZE, encoding: str = "utf-8"
) -> AsyncTextGenerator:
    """Open a local file for async text reading."""
    handle = None
    try:
        handle = await get_running_loop().run_in_executor(None, _open_sync, path)
        yield AsyncTextReader(
            input=_AsyncFileIterator(handle, chunk_size=chunk_size), encoding=encoding
        )
    finally:
        if handle:
            await get_running_loop().run_in_executor(None, handle.__exit__)


@asynccontextmanager
async def read_url(
    url: str, *, session=None, chunk_size: int = CHUNK_SIZE
) -> AsyncTextGenerator:
    """Open a URL for async text reading."""
    async with session or aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as resp:
                if not resp.ok:
                    raise AsyncTextReadError(
                        resp.reason, status=resp.status, history=resp.history
                    )
                ctype = resp.headers.get("Content-Type", "").lower()
                mime = aiohttp.helpers.parse_mimetype(ctype)
                encoding = mime.parameters.get("charset") or "utf-8"
                yield AsyncTextReader(
                    input=_AsyncUrlIterator(resp, chunk_size), encoding=encoding
                )
        except aiohttp.ClientError as err:
            raise AsyncTextReadError(str(err)) from err


def _open_sync(path: str | Path):
    file = open(path, "rb")  # noqa: SIM115
    return file.__enter__()


class AsyncTextReader:
    """An async text reader supporting line splitting."""

    def __init__(
        self,
        *,
        init: str | None = None,
        input: AsyncIterator[bytes] | None = None,
        encoding: str = "utf-8",
    ):
        """Constructor."""
        self._decoder = _LineDecoder(init, encoding) if init else None
        self._encoding = encoding
        self._input = input

    def __aiter__(self):
        """Access as an async iterator."""
        return self

    async def __anext__(self):
        """Read the next entry from an async iterator."""
        line = await self.nextline()
        if line is None:
            raise StopAsyncIteration
        return line

    async def nextline(self) -> str | None:
        """Fetch the next line."""
        while True:
            if self._decoder:
                line = self._decoder.readline()
                if line is not None:
                    return line
            if self._input:
                try:
                    chunk = await anext(self._input)
                    if not self._decoder:
                        self._decoder = _LineDecoder(encoding=self._encoding)
                    self._decoder.append_bytes(chunk)
                except StopAsyncIteration:
                    self._input = None
                    if self._decoder:
                        self._decoder.finalize()
            else:
                return None

    async def text(self) -> str:
        """Read the remainder of the input."""
        while self._input:
            try:
                chunk = await anext(self._input)
                if not self._decoder:
                    self._decoder = _LineDecoder(encoding=self._encoding)
                self._decoder.append_bytes(chunk)
            except StopAsyncIteration:
                self._input = None
        if self._decoder:
            self._decoder.finalize()
            res = self._decoder.read()
            self._decoder = None
            return res
        return ""


class _AsyncFileIterator:
    """An async iterator over sequential chunks of a file."""

    def __init__(self, handle: FileIO, chunk_size: int = CHUNK_SIZE):
        """Constructor."""
        self._chunk_size = chunk_size
        self._handle = handle

    async def __anext__(self) -> bytes:
        """Read the next chunk from the file."""
        if self._handle:
            chunk = await get_running_loop().run_in_executor(
                None, self._handle.read, self._chunk_size
            )
            if chunk:
                return chunk
            self._handle = None
        raise StopAsyncIteration


class _AsyncUrlIterator:
    """An async iterator over sequential chunks of a resolved URL."""

    def __init__(self, response: aiohttp.ClientResponse, chunk_size: int = CHUNK_SIZE):
        """Constructor."""
        self._chunk_size = chunk_size
        self._handle = response

    async def __anext__(self) -> bytes:
        """Read the next chunk from the response."""
        if self._handle:
            chunk = await self._handle.content.read(self._chunk_size)
            if chunk:
                return chunk
            self._handle = None
        raise StopAsyncIteration


class _LineDecoder:
    def __init__(self, buffer: str = "", encoding="utf-8"):
        self._buffer = buffer or ""
        self._decoder = None
        self._encoding = encoding

    def append_bytes(self, value: bytes):
        if not self._decoder:
            try:
                decoder = getincrementaldecoder(self._encoding)
            except LookupError:
                raise AsyncTextReadError(
                    f"Unsupported encoding: {self._encoding}"
                ) from None
            self._decoder = decoder()
        self._buffer += self._decoder.decode(value, final=False)

    def finalize(self):
        if self._decoder:
            self._buffer += self._decoder.decode(b"", final=True)
            self._decoder = None

    def readline(self) -> str | None:
        if self._buffer:
            split = re.match(NL, self._buffer)
            if split:
                self._buffer = split.group(3)
                return split.group(1) + os.linesep
            if not self._decoder:
                (line, self._buffer) = (self._buffer, "")
                return line
        return None

    def read(self) -> str:
        (b, self._buffer) = (self._buffer, "")
        return b
