from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class ServeError(RuntimeError):
    pass


def find_llama_server(explicit_path: str | None = None) -> str:
    candidates = [
        explicit_path,
        shutil.which("llama-server"),
        shutil.which("llama-server.exe"),
        shutil.which("server"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
        if candidate and shutil.which(candidate):
            return candidate
    raise ServeError(
        "Could not find llama-server. Install llama.cpp and pass --llama-server /path/to/llama-server."
    )


def run_llama_server(
    *,
    model_path: Path,
    llama_server: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8011,
    ctx_size: int = 4096,
    gpu_layers: int | None = None,
    parallel: int = 1,
    threads: int | None = None,
    temperature: float = 0.0,
    reasoning: bool = False,
    extra_args: list[str] | None = None,
) -> int:
    if not model_path.exists():
        raise ServeError(f"model file does not exist: {model_path}")
    server = find_llama_server(llama_server)
    command = [
        server,
        "-m",
        str(model_path),
        "--host",
        host,
        "--port",
        str(port),
        "-c",
        str(ctx_size),
        "--parallel",
        str(parallel),
        "--temp",
        str(temperature),
        "--cache-ram",
        "0",
    ]
    if gpu_layers is not None:
        command.extend(["-ngl", str(gpu_layers)])
    if not reasoning:
        command.extend(["--reasoning", "off"])
    if threads is not None:
        command.extend(["-t", str(threads)])
    if extra_args:
        command.extend(extra_args)
    try:
        return subprocess.run(command, check=False).returncode
    except KeyboardInterrupt:
        return 130
