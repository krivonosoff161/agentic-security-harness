"""Bounded read-only closure over literal batch edges and local Python imports."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Final

from agentic_security_harness.safe_io import is_link_or_reparse
from agentic_security_harness.source_identity import component_fingerprint
from agentic_security_harness.version import __version__

_MAX_FILES: Final = 768
_BATCH_CALL = re.compile(r"(?im)^\s*call\s+\"?([^\"\r\n]+?\.bat)\"?\s*$")
_PYTHON_MODULE = re.compile(
    r"(?i)\bpython(?:\.exe)?\b[^\r\n]*?\s-m\s+"
    r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
)
_POWERSHELL_MODULE = re.compile(
    r"[\"']-m[\"']\s*,\s*[\"']([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)[\"']"
)
_DYNAMIC_CALLS: Final = {"__import__", "import_module", "run_module", "run_path"}
_DELIVERY_CALLS: Final = {"send_message", "send_telegram", "send_telegram_message"}
_PROVIDER_CALLS: Final = {
    "chat_completion",
    "completion",
    "generate",
    "urlopen",
    "urlopen_no_redirect",
}
_STORAGE_CALLS: Final = {"to_csv", "to_excel", "write_bytes", "write_text"}
_PROCESS_EXECUTION_CALLS: Final = {
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "os.popen",
    "os.startfile",
    "os.system",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "subprocess.popen",
    "subprocess.run",
}
_DYNAMIC_CODE_CALLS: Final = {"eval", "exec"}
_ANALYZER_COMPONENTS: Final = (
    "safe_io.py",
    "source_identity.py",
    "static_import_closure.py",
    "version.py",
)


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_candidate(root: Path, relative: str) -> Path | None:
    root = root.resolve(strict=False)
    if not root.is_dir() or is_link_or_reparse(root):
        return None
    normalized = relative.replace("\\", "/").strip().strip('"')
    parts = Path(normalized).parts
    if (
        not normalized
        or "%" in normalized
        or Path(normalized).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        return None
    candidate = (root / normalized).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    for path in (candidate, *candidate.parents):
        if path.exists() and is_link_or_reparse(path):
            return None
        if path == root:
            break
    return candidate


def _module_path(root: Path, module: str) -> Path | None:
    if not module or any(not part.isidentifier() for part in module.split(".")):
        return None
    base = root.joinpath(*module.split("."))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        if resolved.is_file() and _safe_candidate(
            root, resolved.relative_to(root).as_posix()
        ) is not None:
            return resolved
    return None


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _import_bindings(tree: ast.AST) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                bindings[local] = alias.name if alias.asname else local
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return bindings


def _resolved_qualified_name(node: ast.AST, bindings: dict[str, str]) -> str:
    qualified = _qualified_name(node)
    if not qualified:
        return ""
    head, separator, tail = qualified.partition(".")
    resolved_head = bindings.get(head, head)
    return f"{resolved_head}.{tail}" if separator else resolved_head


def _node_phase(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    parent = parents.get(node)
    while parent is not None:
        if isinstance(parent, (ast.AsyncFunctionDef, ast.FunctionDef, ast.Lambda)):
            return "call-time"
        parent = parents.get(parent)
    return "import-time"


def _call_sink_categories(
    node: ast.Call,
    bindings: dict[str, str],
) -> set[str]:
    qualified = _resolved_qualified_name(node.func, bindings).lower()
    tail = qualified.rsplit(".", 1)[-1]
    categories: set[str] = set()
    if tail == "load_dotenv":
        categories.add("environment_load")
    if tail in _DELIVERY_CALLS or (
        tail.startswith("send_") and "telegram" in tail
    ):
        categories.add("external_delivery")
    if tail in _PROVIDER_CALLS or (
        tail in {"get", "post", "request"}
        and qualified.startswith(("aiohttp.", "httpx.", "requests."))
    ):
        categories.add("provider_or_network")
    if tail in _STORAGE_CALLS:
        categories.add("storage_write")
    if (
        qualified in _PROCESS_EXECUTION_CALLS
        or qualified.startswith("os.exec")
        or qualified.startswith("os.spawn")
    ):
        categories.add("process_execution")
    if qualified in _DYNAMIC_CODE_CALLS:
        categories.add("dynamic_code_execution")
    if tail in {"getenv", "get"} and (
        qualified.startswith("os.getenv") or "environ" in qualified
    ):
        categories.add("environment_read")
    if tail in {"putenv", "setdefault", "update"} and (
        qualified.startswith("os.putenv") or "environ" in qualified
    ):
        categories.add("environment_write")
    if tail == "open" and len(node.args) >= 2:
        mode = node.args[1]
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
            if any(flag in mode.value for flag in "wax+"):
                categories.add("storage_write")
    return categories


def _constant_sink_categories(value: str) -> set[str]:
    lowered = value.lower()
    categories: set[str] = set()
    if "telegram" in lowered and "http" in lowered:
        categories.add("external_delivery")
    if "chat/completions" in lowered:
        categories.add("provider_or_network")
    return categories


def _entry_path(
    entry_modules: set[str],
    graph: dict[str, set[str]],
    target: str,
) -> list[str]:
    queue: deque[tuple[str, list[str]]] = deque(
        (entry, [entry]) for entry in sorted(entry_modules)
    )
    seen: set[str] = set()
    while queue:
        module, path = queue.popleft()
        if module in seen:
            continue
        seen.add(module)
        if module == target:
            return path
        queue.extend(
            (child, [*path, child]) for child in sorted(graph.get(module, set()))
        )
    return []


def _import_names(
    tree: ast.AST,
    module: str,
    *,
    is_package: bool,
) -> tuple[set[str], set[str]]:
    imports: set[str] = set()
    required: set[str] = set()
    package_parts = module.split(".") if is_package else module.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name for alias in node.names}
            imports.update(names)
            required.update(names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                keep = len(package_parts) - (node.level - 1)
                if keep < 0:
                    continue
                prefix = package_parts[:keep]
                if node.module:
                    prefix.extend(node.module.split("."))
                base = ".".join(prefix)
            else:
                base = node.module or ""
            if base:
                imports.add(base)
                required.add(base)
                imports.update(
                    f"{base}.{alias.name}"
                    for alias in node.names
                    if alias.name != "*"
                )
    return imports, required


def static_import_closure(
    root_path: Path,
    *,
    entrypoint: str,
) -> dict[str, object]:
    """Return a public-safe hash-bound static import closure without execution."""

    root = Path(root_path).resolve(strict=False)
    batch_queue: deque[str] = deque([entrypoint])
    module_queue: deque[str] = deque()
    visited_batches: set[str] = set()
    visited_modules: set[str] = set()
    file_hashes: dict[str, str] = {}
    blockers: set[str] = set()
    unresolved_local_imports: set[str] = set()
    dynamic_import_sites = 0
    dynamic_literal_import_sites = 0
    entry_modules: set[str] = set()
    import_graph: dict[str, set[str]] = defaultdict(set)
    sink_sites: dict[tuple[str, str, str, str], set[int]] = defaultdict(set)

    while batch_queue:
        relative = batch_queue.popleft().replace("\\", "/")
        if relative.lower() in {item.lower() for item in visited_batches}:
            continue
        candidate = _safe_candidate(root, relative)
        if candidate is None or not candidate.is_file():
            blockers.add("entrypoint-or-batch-missing")
            continue
        label = candidate.relative_to(root).as_posix()
        visited_batches.add(label)
        raw = candidate.read_bytes()
        file_hashes[label] = _sha256(raw)
        text = raw.decode("utf-8-sig", errors="replace")
        active = "\n".join(
            line
            for line in text.splitlines()
            if not line.lstrip().lower().startswith(("rem ", "::"))
        )
        for called in _BATCH_CALL.findall(active):
            called_path = called.strip().replace("\\", "/")
            if "%" in called_path:
                blockers.add("dynamic-batch-edge")
            else:
                batch_queue.append(called_path)
        discovered = set(_PYTHON_MODULE.findall(active))
        discovered.update(_POWERSHELL_MODULE.findall(active))
        entry_modules.update(discovered)
        module_queue.extend(sorted(discovered))

    while module_queue:
        if len(visited_batches) + len(visited_modules) >= _MAX_FILES:
            blockers.add("closure-file-cap-exceeded")
            break
        module = module_queue.popleft()
        if module in visited_modules:
            continue
        candidate = _module_path(root, module)
        if candidate is None:
            continue
        visited_modules.add(module)
        label = candidate.relative_to(root).as_posix()
        raw = candidate.read_bytes()
        file_hashes[label] = _sha256(raw)
        try:
            tree = ast.parse(raw.decode("utf-8-sig"), filename=label)
        except (SyntaxError, UnicodeDecodeError):
            blockers.add("python-parse-error")
            continue
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        import_bindings = _import_bindings(tree)
        for node in ast.walk(tree):
            phase = _node_phase(node, parents)
            if isinstance(node, ast.Call):
                call_name = _call_name(node)
                qualified = _resolved_qualified_name(node.func, import_bindings)
                for category in _call_sink_categories(node, import_bindings):
                    sink_sites[(category, module, label, phase)].add(node.lineno)
                if call_name in _DYNAMIC_CALLS:
                    dynamic_import_sites += 1
                    if (
                        node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)
                    ):
                        dynamic_module = node.args[0].value
                        if _module_path(root, dynamic_module) is not None:
                            dynamic_literal_import_sites += 1
                            import_graph[module].add(dynamic_module)
                            module_queue.append(dynamic_module)
                    sink_sites[("dynamic_dispatch", module, label, phase)].add(
                        node.lineno
                    )
                if "exchange" in qualified.lower():
                    sink_sites[("exchange_interface", module, label, phase)].add(
                        node.lineno
                    )
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                for category in _constant_sink_categories(node.value):
                    sink_sites[(category, module, label, phase)].add(node.lineno)
            elif isinstance(node, ast.Assign):
                if any("environ" in _qualified_name(target).lower() for target in node.targets):
                    sink_sites[("environment_write", module, label, phase)].add(
                        node.lineno
                    )
            elif isinstance(node, ast.Subscript):
                if "environ" in _qualified_name(node.value).lower():
                    sink_sites[("environment_read", module, label, phase)].add(
                        node.lineno
                    )
        imports, required_imports = _import_names(
            tree,
            module,
            is_package=candidate.name == "__init__.py",
        )
        for imported in sorted(imports):
            if _module_path(root, imported) is not None:
                import_graph[module].add(imported)
                module_queue.append(imported)
                if ".exchange." in f".{imported.lower()}." or imported.lower().endswith(
                    ".exchange"
                ):
                    sink_sites[("exchange_interface", module, label, "static-import")].add(
                        0
                    )
            elif (
                imported in required_imports
                and (root / imported.split(".", 1)[0]).exists()
            ):
                unresolved_local_imports.add(imported)

    if not entry_modules:
        blockers.add("python-entry-module-missing")
    if dynamic_import_sites:
        blockers.add("dynamic-import-present")
    if unresolved_local_imports:
        blockers.add("unresolved-local-import")
    for label, expected_hash in file_hashes.items():
        candidate = _safe_candidate(root, label)
        if (
            candidate is None
            or not candidate.is_file()
            or _sha256(candidate.read_bytes()) != expected_hash
        ):
            blockers.add("source-changed-during-closure")
            break
    complete = not blockers
    sink_inventory = [
        {
            "category": category,
            "module": module,
            "file": label,
            "phase": phase,
            "site_count": len(lines),
            "line_numbers": sorted(line for line in lines if line > 0),
        }
        for (category, module, label, phase), lines in sorted(sink_sites.items())
    ]
    sink_categories = sorted({str(item["category"]) for item in sink_inventory})
    authority_paths = []
    for item in sink_inventory:
        module_name = str(item["module"])
        authority_paths.append(
            {
                "category": item["category"],
                "sink_module": module_name,
                "phase": item["phase"],
                "module_path": _entry_path(entry_modules, import_graph, module_name),
            }
        )
    high_risk_categories = {
        "dynamic_code_execution",
        "environment_load",
        "exchange_interface",
        "external_delivery",
        "process_execution",
        "provider_or_network",
    }
    security_blockers = sorted(high_risk_categories.intersection(sink_categories))
    if "environment_load" in sink_categories and "provider_or_network" in sink_categories:
        security_blockers.append("environment-to-provider-co-reachability")
    security_clear = complete and not security_blockers
    closure_projection = {
        "entrypoint": entrypoint.replace("\\", "/"),
        "entry_modules": sorted(entry_modules),
        "module_names": sorted(visited_modules),
        "file_hashes": dict(sorted(file_hashes.items())),
    }
    closure_sha256 = _sha256(
        json.dumps(
            closure_projection,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return {
        "schema_version": "0.2",
        "mode": "static-import-closure",
        "entrypoint": entrypoint.replace("\\", "/"),
        "complete": complete,
        "status": "complete" if complete else "incomplete",
        "evidence_scope": "literal-batch-and-static-local-python-import-closure",
        "non_claims": (
            "runtime branch reachability",
            "runtime configuration values",
            "dynamic dispatch not represented by static imports",
            "call ordering across independent branches",
            "absence of runtime monkeypatch or plugin resolution",
        ),
        "batch_file_count": len(visited_batches),
        "python_file_count": len(visited_modules),
        "file_count": len(file_hashes),
        "entry_modules": sorted(entry_modules),
        "module_names": sorted(visited_modules),
        "file_hashes": dict(sorted(file_hashes.items())),
        "closure_sha256": closure_sha256,
        "analyzer_source_fingerprint": component_fingerprint(_ANALYZER_COMPONENTS),
        "tool_version": __version__,
        "blockers": sorted(blockers),
        "dynamic_import_site_count": dynamic_import_sites,
        "dynamic_literal_import_site_count": dynamic_literal_import_sites,
        "unresolved_local_import_count": len(unresolved_local_imports),
        "sink_categories": sink_categories,
        "sink_inventory": sink_inventory,
        "authority_paths": authority_paths,
        "security_clear": security_clear,
        "security_status": "clear" if security_clear else "blocked-or-inconclusive",
        "security_blockers": security_blockers,
        "environment_provider_order": (
            "co-reachable-order-not-proven"
            if "environment-to-provider-co-reachability" in security_blockers
            else "not-observed"
        ),
        "target_mutation": False,
        "raw_contents_included": False,
        "source_lines_included": False,
        "absolute_paths_included": False,
    }
