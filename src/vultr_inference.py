"""Inference client — provider-configurable, Vultr by default.

Challenge pillar: every LLM call for the submitted demo MUST go through Vultr
Serverless Inference (OpenAI-compatible). That is the default and stays the
default.

Teams that already have another key (for example Claude) can point the app at it
without editing code. Configuration is read from the environment, and from a
local `.env` file if one exists:

  INFERENCE_PROVIDER        vultr (default) | anthropic | openai
  INFERENCE_API_KEY         key for Vultr / any OpenAI-compatible provider
  ANTHROPIC_API_KEY         key when INFERENCE_PROVIDER=anthropic
  INFERENCE_BASE_URL        default https://api.vultrinference.com/v1
  INFERENCE_MODEL           required — no default is bundled; set it in .env
  INFERENCE_FALLBACK_MODELS optional comma-separated list; default is none

No model id is hard-coded anywhere: the team picks the model and puts it in
`.env`. A model id that is not available on the configured provider just 404s
on every call, so verify it with `--list-models` before shipping.

Using a provider other than Vultr is fine for local development, but it breaks
the Vultr pillar for the event submission.

Fail loudly, never mock success: without a key every entrypoint raises
MissingInferenceKey with setup instructions. `require_key=False` only skips the
up-front check — it never invents a response; a missing key still raises when the
request is attempted. Callers that want to run without the LLM (for example the
containment-only path) check `have_key()` first, as `main.run_task` does.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Public defaults. Tests pin these so the Vultr pillar cannot disappear silently.
# No model id is bundled: the team supplies one via INFERENCE_MODEL.
BASE_URL = "https://api.vultrinference.com/v1"
KEY_ENV = "INFERENCE_API_KEY"

ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"
ANTHROPIC_KEY_ENV = "ANTHROPIC_API_KEY"
ANTHROPIC_VERSION = "2023-06-01"

SYSTEM_PROMPT = (
    "You are a code-generating agent. Reply with ONE python code block and nothing else: "
    "no prose, no explanation, no markdown fences beyond the single block. "
    "The code must be self-contained, read its input from stdin as text, print its result to "
    "stdout, and terminate on its own. Prefer the standard library."
)

REPAIR_PROMPT = (
    "You are a code-repairing agent. The previous program failed. Return ONE corrected "
    "python code block and nothing else: no prose, no explanation. Keep the same input "
    "contract (read stdin, print the answer to stdout, terminate on its own) and prefer "
    "the standard library."
)


class MissingInferenceKey(RuntimeError):
    """Raised when the configured provider has no API key."""


class InferenceError(RuntimeError):
    """Raised when the inference endpoint returns an error."""


def _load_dotenv() -> None:
    """Load repo-root .env once, without overriding real environment variables.

    No dependency needed: the file only needs simple KEY=VALUE lines.
    """
    path = Path(__file__).resolve().parent.parent / ".env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        if name and name not in os.environ:
            os.environ[name] = value


_load_dotenv()


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def provider() -> str:
    """Return the active provider: explicit INFERENCE_PROVIDER wins.

    When it is unset we infer from the keys present so a teammate with only a
    Claude key does not have to set the provider explicitly. The submitted demo
    must set INFERENCE_PROVIDER=vultr; this helper never overrides that.
    """
    chosen = _env("INFERENCE_PROVIDER").lower()
    if chosen:
        return chosen
    if _env(ANTHROPIC_KEY_ENV) and not _env(KEY_ENV):
        return "anthropic"
    return "vultr"


def base_url() -> str:
    if provider() == "anthropic":
        return _env("INFERENCE_BASE_URL").rstrip("/") or ANTHROPIC_BASE_URL
    return _env("INFERENCE_BASE_URL").rstrip("/") or BASE_URL


def model_name() -> str:
    """The model id supplied by the team in .env. Empty means not configured."""
    return _env("INFERENCE_MODEL")


def _key_name() -> str:
    """Name of the env var that holds the key for the active provider."""
    return ANTHROPIC_KEY_ENV if provider() == "anthropic" else KEY_ENV


def _provider_key() -> str:
    """Return only the key for the active provider.

    Deliberately no cross-provider fallback: an INFERENCE_API_KEY is a Vultr /
    OpenAI-compatible key and must never be sent to Anthropic (or the reverse).
    Sending the wrong key produces a confusing 401 on demo day instead of a
    clear "missing key" message.
    """
    return _env(_key_name())


def have_key() -> bool:
    return bool(_provider_key())


def key() -> str:
    k = _provider_key()
    if not k:
        raise MissingInferenceKey(
            f"No key configured for provider '{provider()}'.\n"
            f"Create .env from the template:  cp .env.example .env\n"
            f"Then fill in either one:\n"
            f"  {KEY_ENV}=<key>                (Vultr, default)\n"
            f"  {ANTHROPIC_KEY_ENV}=<key>       (Claude, if your team has one)\n"
            "Verify with: python3 src/vultr_inference.py --list-models"
        )
    return k


def _request(method: str, url: str, payload: dict | None = None,
             headers: dict | None = None, timeout: int = 90) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    hdrs = {"Content-Type": "application/json"} if payload is not None else {}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # keep the body: it names the failing model
        body = exc.read().decode("utf-8", "replace")[:400]
        raise InferenceError(f"Inference HTTP {exc.code} ({provider()}): {body}") from exc
    except urllib.error.URLError as exc:
        raise InferenceError(f"Could not reach {url}: {exc.reason}") from exc


def list_models() -> list[str]:
    """List models for the configured provider.

    Vultr's GET /v1/models is public (no key needed), which lets us verify a model
    id without spending a request. Other providers are queried with the key.
    """
    url = base_url() + "/models"
    if provider() == "vultr":
        data = _request("GET", url, timeout=30)
    elif provider() == "anthropic":
        data = _request("GET", url, timeout=30, headers={
            "x-api-key": key(), "anthropic-version": ANTHROPIC_VERSION})
    else:
        data = _request("GET", url, timeout=30, headers={
            "Authorization": f"Bearer {key()}"})
    return sorted(m.get("id", "") for m in data.get("data", []) if m.get("id"))


def _chat_openai(messages: list[dict], model: str) -> str:
    data = _request(
        "POST", base_url() + "/chat/completions",
        {"model": model, "messages": messages, "temperature": 0.2},
        {"Authorization": f"Bearer {key()}"},
    )
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError) as exc:
        raise InferenceError(f"Unexpected response: {json.dumps(data)[:300]}") from exc


def _chat_anthropic(messages: list[dict], model: str) -> str:
    system = "".join(m["content"] for m in messages if m["role"] == "system")
    convo = [m for m in messages if m["role"] != "system"]
    data = _request(
        "POST", base_url() + "/messages",
        {"model": model, "max_tokens": 4096, "system": system, "messages": convo},
        {"x-api-key": key(), "anthropic-version": ANTHROPIC_VERSION},
    )
    try:
        return "".join(block.get("text", "") for block in data["content"]
                       if block.get("type") == "text")
    except (KeyError, TypeError) as exc:
        raise InferenceError(f"Unexpected response: {json.dumps(data)[:300]}") from exc


def _chat(messages: list[dict], model: str) -> str:
    if provider() == "anthropic":
        return _chat_anthropic(messages, model)
    return _chat_openai(messages, model)


def _candidate_models(model: str | None = None) -> list[str]:
    """The explicit model first, then the optional fallback list from .env."""
    models = [model or model_name()]
    if not models[0]:
        raise InferenceError(
            "No model configured. Set INFERENCE_MODEL in .env to an id that the "
            "configured provider actually serves.\n"
            "List valid ids with: python3 src/vultr_inference.py --list-models"
        )
    extra = _env("INFERENCE_FALLBACK_MODELS")
    models += [m.strip() for m in extra.split(",") if m.strip()]
    return models


def _complete(system: str, user: str, model: str | None = None,
              require_key: bool = True) -> str:
    """Run one completion across the candidate models and return code."""
    if require_key and not have_key():
        key()  # raises with setup instructions

    last: Exception | None = None
    for m in _candidate_models(model):
        try:
            raw = _chat(
                [{"role": "system", "content": system},
                 {"role": "user", "content": user}],
                m,
            )
            code = strip_fences(raw)
            if code.strip():
                return code
        except InferenceError as exc:
            last = exc
            continue
    raise InferenceError(f"No configured model could return code. Last error: {last}")


def generate_code(task: str, model: str | None = None, require_key: bool = True) -> str:
    """Ask the configured model for a self-contained python program.

    The model id comes from INFERENCE_MODEL (or the explicit `model` argument);
    there is no built-in default. Returns the raw python source with markdown
    fences stripped. Raises MissingInferenceKey when the key is absent and
    require_key is True, and InferenceError when no model is configured or every
    candidate model fails.
    """
    return _complete(SYSTEM_PROMPT, task, model=model, require_key=require_key)


def repair_code(task: str, previous_code: str, stdout: str, stderr: str,
                attempt: int, model: str | None = None) -> str:
    """Ask the model to fix a program that ran but failed.

    This is what makes the agent multi-step: the app reads the real sandbox
    result and feeds the failure back into the model, up to a small retry budget.
    Infrastructure failures (no Docker, image pull error) are never repaired —
    the caller filters those out first, because retrying cannot fix them.
    """
    user = (
        f"Task:\n{task}\n\n"
        f"Attempt {attempt} exited non-zero.\n"
        f"--- stdout ---\n{stdout[-2000:] or '(empty)'}\n"
        f"--- stderr ---\n{stderr[-2000:] or '(empty)'}\n"
        "--- previous code ---\n"
        f"{previous_code[:8000]}\n"
        "Return the corrected program."
    )
    return _complete(REPAIR_PROMPT, user, model=model)


def strip_fences(raw: str) -> str:
    """Pull the python body out of a fenced block; pass through bare code."""
    text = raw.strip()
    if "```" not in text:
        return text
    chunks = text.split("```")
    for chunk in chunks[1:]:
        body = chunk.split("\n", 1)
        if len(body) == 2 and body[0].strip().lower().lstrip("{").startswith("python"):
            return body[1]
    for chunk in chunks[1:]:
        if chunk.strip():
            return chunk.split("\n", 1)[1] if "\n" in chunk else chunk
    return text


def _self_test() -> int:
    """Check the configured endpoint. Vultr's model list needs no key."""
    prov = provider()
    chosen = model_name()
    print(f"provider: {prov}")
    print(f"base_url: {base_url()}")
    print(f"model   : {chosen or '(NOT SET)'}")

    if prov == "vultr":
        try:
            models = list_models()
        except InferenceError as exc:
            print(f"FAIL: {exc}")
            return 1
        print(f"OK: {len(models)} models available")
        for m in models:
            print(" -", m)
        if not chosen:
            print("!! Set INFERENCE_MODEL in .env to one of the ids above.")
            return 1
        if chosen not in models:
            print(f"!! WARNING: {chosen} is not in the list — every call will 404")
            return 1
    elif have_key():
        try:
            models = list_models()
            print(f"OK: {len(models)} models available")
            if not chosen:
                print("!! Set INFERENCE_MODEL in .env to one of the ids above.")
                return 1
            if chosen not in models:
                print(f"!! WARNING: {chosen} is not in the list")
                return 1
        except InferenceError as exc:
            print(f"Could not list models ({exc}); calls may still work if the id is correct.")
    else:
        print("No key configured — config checked, no model call made.")
        if not chosen:
            print("!! INFERENCE_MODEL is not set; add it to .env before running a task.")
            return 1

    print(f"\nKey required for model calls: {_key_name()} "
          f"({'set' if have_key() else 'NOT set'})")
    return 0


if __name__ == "__main__":
    if "--list-models" in sys.argv[1:]:
        try:
            for model_id in list_models():
                print(model_id)
        except (InferenceError, MissingInferenceKey) as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            raise SystemExit(1)
        raise SystemExit(0)
    raise SystemExit(_self_test())
