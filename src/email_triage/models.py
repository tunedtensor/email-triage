from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_PRESET = "small"
DEFAULT_CACHE_ENV = "EMAIL_TRIAGE_CACHE_DIR"


class ModelDownloadError(RuntimeError):
    pass


@dataclass(frozen=True)
class ModelPreset:
    name: str
    repo_id: str
    filename: str
    api_model_id: str
    quantization: str
    description: str
    revision: str = "main"

    @property
    def url(self) -> str:
        return f"https://huggingface.co/{self.repo_id}/resolve/{self.revision}/{self.filename}"


MODEL_PRESETS: dict[str, ModelPreset] = {
    "small": ModelPreset(
        name="small",
        repo_id="tunedtensor/email-triage-gguf",
        filename="email-triage-Q5_K_M.gguf",
        api_model_id="email-triage",
        quantization="Q5_K_M",
        description="Qwen 3.5 2B email safety triage GGUF for llama.cpp.",
    ),
}


def resolve_model_id(model: str | None) -> str:
    if not model:
        return MODEL_PRESETS[DEFAULT_PRESET].api_model_id
    preset = MODEL_PRESETS.get(model)
    return preset.api_model_id if preset else model


def resolve_model_preset(model: str | None) -> ModelPreset:
    if not model:
        return MODEL_PRESETS[DEFAULT_PRESET]
    preset = MODEL_PRESETS.get(model)
    if preset:
        return preset
    raise ModelDownloadError(
        f"unknown GGUF model preset: {model}. Available presets: {', '.join(sorted(MODEL_PRESETS))}"
    )


def default_cache_dir() -> Path:
    override = os.environ.get(DEFAULT_CACHE_ENV)
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        return Path(root or Path.home() / "AppData" / "Local") / "email-triage"
    if os.uname().sysname == "Darwin":
        return Path.home() / "Library" / "Caches" / "email-triage"
    root = os.environ.get("XDG_CACHE_HOME")
    return Path(root).expanduser() / "email-triage" if root else Path.home() / ".cache" / "email-triage"


def local_model_path(preset: ModelPreset, cache_dir: Path | None = None) -> Path:
    root = cache_dir.expanduser() if cache_dir else default_cache_dir()
    repo_dir = preset.repo_id.replace("/", "--")
    return root / repo_dir / preset.revision / preset.filename


def resolve_gguf_model_path(
    model: str | None = None,
    *,
    cache_dir: Path | None = None,
    force_download: bool = False,
) -> Path:
    if model:
        path = Path(model).expanduser()
        if path.exists():
            return path
        if path.suffix.lower() == ".gguf":
            raise ModelDownloadError(f"GGUF model file does not exist: {path}")

    preset = resolve_model_preset(model)
    path = local_model_path(preset, cache_dir)
    if path.exists() and not force_download:
        return path
    return download_gguf_model(preset, path, force_download=force_download)


def download_gguf_model(
    preset: ModelPreset,
    destination: Path | None = None,
    *,
    force_download: bool = False,
) -> Path:
    destination = destination or local_model_path(preset)
    if destination.exists() and not force_download:
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        from huggingface_hub import hf_hub_download

        path = hf_hub_download(
            repo_id=preset.repo_id,
            filename=preset.filename,
            revision=preset.revision,
            local_dir=str(destination.parent),
            force_download=force_download,
        )
    except Exception as exc:
        raise ModelDownloadError(f"failed to download {preset.repo_id}/{preset.filename}: {exc}") from exc
    path = Path(path)
    if path.resolve() == destination.resolve():
        return destination
    if path != destination and path.exists():
        if destination.exists():
            destination.unlink()
        path.replace(destination)
    return destination
