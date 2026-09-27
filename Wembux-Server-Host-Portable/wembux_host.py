from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys
from pathlib import Path

from aiohttp import web

from wembux_server import WembuxService, default_data_dir, open_db, setup_owner


def find_cloudflared() -> str | None:
    configured = os.environ.get("CLOUDFLARED_PATH")
    if configured and Path(configured).is_file():
        return configured
    found = shutil.which("cloudflared") or shutil.which("cloudflared.exe")
    if found:
        return found
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidate = Path(local_app_data) / "Microsoft" / "WinGet" / "Links" / "cloudflared.exe"
        if candidate.is_file():
            return str(candidate)
    return None


async def stream_tunnel_output(process: asyncio.subprocess.Process) -> None:
    if process.stdout is None:
        return
    async for raw_line in process.stdout:
        line = raw_line.decode("utf-8", errors="replace").rstrip()
        if line:
            print(line, flush=True)
            if "trycloudflare.com" in line and "https://" in line:
                url = next((part for part in line.split() if part.startswith("https://") and "trycloudflare.com" in part), None)
                if url:
                    print("\nShare this HTTPS link with Wembux users:", url, "\n", flush=True)


async def run_host(data_dir: Path, host: str, port: int) -> int:
    db_path = data_dir / "wembux.sqlite3"
    with open_db(db_path) as db:
        owner_exists = db.execute("SELECT 1 FROM accounts WHERE role='owner' LIMIT 1").fetchone()
    if not owner_exists:
        setup_owner(db_path)

    service = WembuxService(db_path)
    runner = web.AppRunner(service.create_app(), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    local_url = f"http://127.0.0.1:{port}"
    print(f"Wembux server is ready at {local_url}", flush=True)
    print("Keep this laptop awake and connected while people use Wembux.", flush=True)

    cloudflared_path = find_cloudflared()
    tunnel: asyncio.subprocess.Process | None = None
    output_task: asyncio.Task[None] | None = None
    try:
        if not cloudflared_path:
            print("Cloudflare Tunnel is not installed, so this server is local-only.", flush=True)
            print("Install cloudflared, then run this BAT again to get a public HTTPS link.", flush=True)
            await asyncio.Event().wait()
            return 0
        print("Starting temporary HTTPS tunnel...", flush=True)
        tunnel = await asyncio.create_subprocess_exec(
            cloudflared_path,
            "tunnel",
            "--url",
            local_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output_task = asyncio.create_task(stream_tunnel_output(tunnel))
        return await tunnel.wait()
    finally:
        if tunnel is not None and tunnel.returncode is None:
            tunnel.terminate()
            try:
                await asyncio.wait_for(tunnel.wait(), timeout=5)
            except asyncio.TimeoutError:
                tunnel.kill()
                await tunnel.wait()
        if output_task is not None:
            output_task.cancel()
            await asyncio.gather(output_task, return_exceptions=True)
        await runner.cleanup()
        print("Wembux server stopped.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Wembux server and temporary HTTPS tunnel.")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEMBUX_PORT", "8765")))
    args = parser.parse_args()
    try:
        return asyncio.run(run_host(args.data_dir.resolve(), args.host, args.port))
    except KeyboardInterrupt:
        print("\nStopping Wembux...", flush=True)
        return 0
    except OSError as error:
        print(f"Could not start Wembux: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
