"""Lightweight provider/runtime presets for the OpenAI-compatible external path.

A preset only substitutes a default ``base_url`` and a suggested credential env-var
**name** and prints notes. It does **not** add a provider SDK, change the transport,
or hide a network call - the external path is still explicit, opt-in,
OpenAI-compatible only. Vendor URLs are starting points; confirm the current value in
the provider's docs.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

_TEMPLATE_HOST = "YOUR-ENDPOINT"  # placeholder base URLs that require an explicit --base-url


class Preset(BaseModel):
    """A named connection preset (base URL + notes; no secrets)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    base_url: str
    needs_key: bool = False
    default_key_env: str = ""
    notes: str = ""


_PRESETS: dict[str, Preset] = {
    "fake-local": Preset(
        name="fake-local",
        base_url="http://127.0.0.1:8766/v1",
        needs_key=False,
        notes="bundled deterministic fake server (examples/fake_openai_server.py)",
    ),
    "vllm": Preset(
        name="vllm",
        base_url="http://localhost:8000/v1",
        needs_key=False,
        default_key_env="ASH_EXTERNAL_API_KEY",
        notes="local vLLM OpenAI-compatible server; --model = the served model id",
    ),
    "ollama": Preset(
        name="ollama",
        base_url="http://localhost:11434/v1",
        needs_key=False,
        notes="Ollama native OpenAI-compatible endpoint; pull the model first",
    ),
    "lm-studio": Preset(
        name="lm-studio",
        base_url="http://localhost:1234/v1",
        needs_key=False,
        notes="LM Studio local server; start its server and load a model",
    ),
    "deepseek": Preset(
        name="deepseek",
        base_url="https://api.deepseek.com/v1",
        needs_key=True,
        default_key_env="ASH_EXTERNAL_API_KEY",
        notes="confirm the current base URL and model ids in the DeepSeek API docs",
    ),
    "alibaba-qwen-compatible": Preset(
        name="alibaba-qwen-compatible",
        base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        needs_key=True,
        default_key_env="ASH_EXTERNAL_API_KEY",
        notes="Model Studio compatible-mode; host is region-dependent, confirm in docs",
    ),
    "generic-openai-compatible": Preset(
        name="generic-openai-compatible",
        base_url=f"https://{_TEMPLATE_HOST}/v1",
        needs_key=True,
        default_key_env="ASH_EXTERNAL_API_KEY",
        notes="any OpenAI-compatible gateway; pass --base-url with your endpoint",
    ),
}


def list_presets() -> list[Preset]:
    """All presets, sorted by name."""
    return [_PRESETS[name] for name in sorted(_PRESETS)]


def preset_names() -> list[str]:
    return sorted(_PRESETS)


def resolve_preset(name: str) -> Preset:
    """Return a preset by name, or raise KeyError with a helpful message."""
    if name not in _PRESETS:
        known = ", ".join(sorted(_PRESETS))
        raise KeyError(f"unknown preset '{name}'. Known presets: {known}")
    return _PRESETS[name]


def is_template_url(base_url: str) -> bool:
    """True if the URL is a placeholder that the user must replace with --base-url."""
    return _TEMPLATE_HOST in base_url


def apply_preset(
    preset_name: str | None,
    base_url: str | None,
    credential_env_var: str,
) -> tuple[str, str, str | None]:
    """Resolve effective (base_url, credential_env_var, error).

    Explicit ``base_url`` always wins. The preset fills the base URL and, when the
    provider needs a credential and none was given, suggests its default credential env
    var **name** (never a value). Returns an error string when a template URL was
    selected without an explicit ``--base-url``.
    """
    if preset_name is None:
        if not base_url:
            return "", credential_env_var, "provide --base-url or --preset"
        return base_url, credential_env_var, None

    preset = resolve_preset(preset_name)  # may raise KeyError, handled by caller
    effective_url = base_url or preset.base_url
    if is_template_url(effective_url):
        return (
            effective_url,
            credential_env_var,
            f"preset '{preset_name}' has a placeholder base URL; pass --base-url "
            "with your endpoint",
        )
    effective_credential_env_var = (
        credential_env_var or (preset.default_key_env if preset.needs_key else "")
    )
    return effective_url, effective_credential_env_var, None
