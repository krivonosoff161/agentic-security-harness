"""Lightweight provider/runtime presets for the OpenAI-compatible external path.

A preset only substitutes a default ``base_url`` and a suggested credential env-var
**name** and prints notes. It does **not** add a provider SDK, change the transport,
or hide a network call - the external path is still explicit, opt-in,
OpenAI-compatible only. Vendor URLs are starting points; confirm the current value in
the provider's docs.
"""

from __future__ import annotations

from urllib.parse import urlparse

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
    runtime_name: str = "generic-openai-compatible"
    runtime_family: str = "openai-compatible"
    network_mode: str = "authorized-external"
    authorization_mode: str = "authorized_external"
    local_only: bool = False
    model_license_note: str = (
        "Verify the model license, acceptable-use policy, and authorization scope "
        "before running or publishing results."
    )


class RuntimeProfile(BaseModel):
    """Secret-free runtime profile stored in run artifacts."""

    model_config = ConfigDict(extra="forbid")

    runtime_name: str
    runtime_family: str
    network_mode: str
    authorization_mode: str
    local_only: bool
    model_license_note: str
    recovery_guidance: list[str]


_LOCAL_RECOVERY_GUIDANCE = [
    "If the server is not running, start the runtime server and retry with external-check --live.",
    "If the model is not found, pull or load the model and verify the --model id.",
    "If the output is inconclusive, inspect raw_responses/ and rerun with "
    "--temperature 0.0 and more repeats.",
]

_REMOTE_RECOVERY_GUIDANCE = [
    "If connectivity fails, verify the base URL, credential env var, and authorization scope.",
    "If the model is not found, verify the provider model id and current endpoint documentation.",
    "If output is inconclusive, inspect raw_responses/ and rerun with lower temperature "
    "or more repeats.",
]


_PRESETS: dict[str, Preset] = {
    "fake-local": Preset(
        name="fake-local",
        base_url="http://127.0.0.1:8766/v1",
        needs_key=False,
        notes="bundled deterministic fake server (examples/fake_openai_server.py)",
        runtime_name="fake-local",
        runtime_family="local-fake",
        network_mode="local-only",
        authorization_mode="demo_synthetic",
        local_only=True,
        model_license_note="Bundled fake server; no model license applies.",
    ),
    "vllm": Preset(
        name="vllm",
        base_url="http://localhost:8000/v1",
        needs_key=False,
        default_key_env="ASH_EXTERNAL_API_KEY",
        notes="local vLLM OpenAI-compatible server; --model = the served model id",
        runtime_name="vllm",
        runtime_family="local-runtime",
        network_mode="local-only",
        authorization_mode="local_runtime",
        local_only=True,
        model_license_note="Verify the served model license and vLLM deployment policy.",
    ),
    "ollama": Preset(
        name="ollama",
        base_url="http://localhost:11434/v1",
        needs_key=False,
        notes="Ollama native OpenAI-compatible endpoint; pull the model first",
        runtime_name="ollama",
        runtime_family="local-runtime",
        network_mode="local-only",
        authorization_mode="local_runtime",
        local_only=True,
        model_license_note="Verify the pulled model license and acceptable-use policy.",
    ),
    "lm-studio": Preset(
        name="lm-studio",
        base_url="http://localhost:1234/v1",
        needs_key=False,
        notes="LM Studio local server; start its server and load a model",
        runtime_name="lm-studio",
        runtime_family="local-runtime",
        network_mode="local-only",
        authorization_mode="local_runtime",
        local_only=True,
        model_license_note="Verify the loaded model license and LM Studio usage policy.",
    ),
    "deepseek": Preset(
        name="deepseek",
        base_url="https://api.deepseek.com/v1",
        needs_key=True,
        default_key_env="ASH_EXTERNAL_API_KEY",
        notes="confirm the current base URL and model ids in the DeepSeek API docs",
        runtime_name="deepseek",
        runtime_family="cloud-provider",
    ),
    "alibaba-qwen-compatible": Preset(
        name="alibaba-qwen-compatible",
        base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        needs_key=True,
        default_key_env="ASH_EXTERNAL_API_KEY",
        notes="Model Studio compatible-mode; host is region-dependent, confirm in docs",
        runtime_name="alibaba-qwen-compatible",
        runtime_family="cloud-provider",
    ),
    "generic-openai-compatible": Preset(
        name="generic-openai-compatible",
        base_url=f"https://{_TEMPLATE_HOST}/v1",
        needs_key=True,
        default_key_env="ASH_EXTERNAL_API_KEY",
        notes="any OpenAI-compatible gateway; pass --base-url with your endpoint",
        runtime_name="generic-openai-compatible",
        runtime_family="openai-compatible",
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


def base_url_error(base_url: str) -> str | None:
    """Return a fail-closed error for an invalid OpenAI-compatible HTTP base URL."""

    if not base_url or base_url != base_url.strip():
        return "base URL must be non-empty and have no surrounding whitespace"
    if any(ord(char) < 32 or ord(char) == 127 for char in base_url):
        return "base URL must not contain control characters"
    try:
        parsed = urlparse(base_url)
        _ = parsed.port
    except ValueError as exc:
        return f"invalid base URL: {exc}"
    if parsed.scheme.lower() not in {"http", "https"}:
        return "base URL scheme must be http or https"
    if not parsed.hostname:
        return "base URL must include a hostname"
    if parsed.username is not None or parsed.password is not None:
        return "base URL must not contain embedded credentials"
    if parsed.query or parsed.fragment:
        return "base URL must not contain a query string or fragment"
    return None


def is_loopback_base_url(base_url: str) -> bool:
    """Return true only for valid HTTP(S) URLs with a literal loopback hostname."""

    if base_url_error(base_url) is not None:
        return False
    host = (urlparse(base_url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def infer_runtime_profile(preset_name: str | None, base_url: str) -> RuntimeProfile:
    """Infer artifact-safe runtime metadata from the preset and effective URL."""
    preset = _PRESETS.get(preset_name or "")
    url_is_local = is_loopback_base_url(base_url)
    if preset is not None and preset.local_only == url_is_local:
        guidance = (
            _LOCAL_RECOVERY_GUIDANCE if preset.local_only else _REMOTE_RECOVERY_GUIDANCE
        )
        return RuntimeProfile(
            runtime_name=preset.runtime_name,
            runtime_family=preset.runtime_family,
            network_mode=preset.network_mode,
            authorization_mode=preset.authorization_mode,
            local_only=preset.local_only,
            model_license_note=preset.model_license_note,
            recovery_guidance=list(guidance),
        )

    if url_is_local:
        return RuntimeProfile(
            runtime_name="local-openai-compatible",
            runtime_family="local-runtime",
            network_mode="local-only",
            authorization_mode="local_runtime",
            local_only=True,
            model_license_note=(
                "Local OpenAI-compatible endpoint; verify the served model license "
                "and acceptable-use policy."
            ),
            recovery_guidance=list(_LOCAL_RECOVERY_GUIDANCE),
        )

    return RuntimeProfile(
        runtime_name="generic-openai-compatible",
        runtime_family="openai-compatible",
        network_mode="authorized-external",
        authorization_mode="authorized_external",
        local_only=False,
        model_license_note=(
            "Authorized external OpenAI-compatible endpoint; verify provider terms, "
            "scope, and model policy before running or publishing results."
        ),
        recovery_guidance=list(_REMOTE_RECOVERY_GUIDANCE),
    )


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
        return base_url, credential_env_var, base_url_error(base_url)

    preset = resolve_preset(preset_name)  # may raise KeyError, handled by caller
    effective_url = base_url or preset.base_url
    if is_template_url(effective_url):
        return (
            effective_url,
            credential_env_var,
            f"preset '{preset_name}' has a placeholder base URL; pass --base-url "
            "with your endpoint",
        )
    error = base_url_error(effective_url)
    if error is not None:
        return effective_url, credential_env_var, error
    effective_credential_env_var = (
        credential_env_var or (preset.default_key_env if preset.needs_key else "")
    )
    return effective_url, effective_credential_env_var, None
