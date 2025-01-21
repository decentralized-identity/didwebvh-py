from tempfile import NamedTemporaryFile

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from did_webvh.core.file_utils import _LineDecoder, read_str, read_text_file, read_url

TEST_INPUT = "abc\ndef\r\ng"
TEST_OUTPUT = ["abc\n", "def\n", "g"]


async def test_read_file():
    with NamedTemporaryFile("w") as f:
        f.write(TEST_INPUT)
        f.flush()
        async with read_text_file(f.name) as wrap:
            lines = [line async for line in wrap]
            assert await wrap.text() == ""
    assert lines == TEST_OUTPUT


async def test_read_str():
    async with read_str(TEST_INPUT) as wrap:
        lines = [line async for line in wrap]
        assert await wrap.text() == ""
    assert lines == TEST_OUTPUT


async def test_read_url():
    async def data(_request):
        return web.Response(text=TEST_INPUT)

    app = web.Application()
    app.router.add_get("/data", data)
    async with (
        TestServer(app) as server,
        read_url("/data", session=TestClient(server)) as wrap,
    ):
        lines = [line async for line in wrap]
    assert lines == TEST_OUTPUT


async def test_line_decoder():
    ld = _LineDecoder("")
    ld.append_bytes(TEST_INPUT.encode("utf-8"))
    ld.finalize()
    lines = []
    while line := ld.readline():
        lines.append(line)
    assert lines == TEST_OUTPUT
