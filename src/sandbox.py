"""Disposable execution sandbox for BLAST RADIUS.

Two runtimes, and the report always says which one actually ran:

  container  — `docker run` with --network none, --memory, --cpus, --pids-limit,
               --read-only, --cap-drop ALL, non-root user, fresh tmpfs /tmp.
               This is the mode the event requires (execution must live behind
               a sandbox boundary, not in the app process).
  rlimits    — POSIX setrlimit + scrubbed env + hard timeout in a child process.
               Honest fallback for machines without a Docker daemon. Real limits
               are applied and measured, but it is NOT a security boundary:
               reports built in this mode are marked DEGRADED.

Safety rule that must never be violated: destructive payloads (rm -rf) only ever
run in container mode. In rlimits mode they are refused, because "containment"
is exactly the property that is missing there.
"""
from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field

DEFAULT_IMAGE = "python:3.11-slim"
TIMEOUT_DEFAULT = 20.0
MEMORY_MB_DEFAULT = 256
CPUS_DEFAULT = 0.5
PIDS_LIMIT_DEFAULT = 64
# A payload that prints forever must not exhaust host memory through our pipes.
MAX_OUTPUT_BYTES = 64 * 1024


@dataclass
class ExecResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False
    killed_by_limit: bool = False
    duration_s: float = 0.0
    runtime: str = "none"
    container_id: str = ""
    degraded: bool = False
    runtime_error: bool = False
    note: str = ""
    limits: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        p = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=10)
        return p.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _limits_dict(memory_mb: int, cpus: float, pids: int, timeout: float) -> dict:
    return {"memory_mb": memory_mb, "cpus": cpus, "pids_limit": pids, "timeout_s": timeout}


_IMAGE_READY: set[str] = set()


def ensure_image(image: str = DEFAULT_IMAGE, timeout: float = 120.0) -> tuple[bool, str]:
    """Make sure the sandbox image is local before a run.

    Without this, the first `docker run` on a fresh VM pulls the image inside the
    probe timeout — the probe gets killed by the clock and can be misread as
    containment. Pulling once, up front, keeps the measurement honest.
    """
    if image in _IMAGE_READY:
        return True, ""
    try:
        found = subprocess.run(["docker", "image", "inspect", image],
                               capture_output=True, text=True, timeout=20)
        if found.returncode != 0:
            pulled = subprocess.run(["docker", "pull", image],
                                    capture_output=True, text=True, timeout=timeout)
            if pulled.returncode != 0:
                return False, (pulled.stderr or pulled.stdout).strip()[:200]
        _IMAGE_READY.add(image)
        return True, ""
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def _run_bounded(cmd: list[str], *, timeout: float, stdin_data: str | None = None,
                 cwd: str | None = None, env: dict | None = None,
                 preexec_fn=None) -> tuple[str, str, int, bool]:
    """Run a command and capture stdout/stderr up to MAX_OUTPUT_BYTES.

    The child is still drained after the cap (its output is discarded) so it
    cannot block, and the memory cost is bounded no matter how much it prints.
    Returns (stdout, stderr, returncode, timed_out).
    """
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=cwd, env=env, preexec_fn=preexec_fn,
    )
    kept = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    lock = threading.Lock()

    def drain(stream, name: str) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            with lock:
                room = MAX_OUTPUT_BYTES - len(kept[name])
                if room > 0:
                    kept[name].extend(chunk[:room])
                if len(chunk) > room:
                    truncated[name] = True

    def feed() -> None:
        try:
            if stdin_data:
                data = stdin_data.encode("utf-8") if isinstance(stdin_data, str) else stdin_data
                proc.stdin.write(data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    readers = [threading.Thread(target=drain, args=(proc.stdout, "stdout"), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, "stderr"), daemon=True)]
    writer = threading.Thread(target=feed, daemon=True)
    for thread in readers:
        thread.start()
    writer.start()

    timed_out = False
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        rc = proc.wait()

    for thread in readers:
        thread.join(timeout=5)
    writer.join(timeout=5)

    out = bytes(kept["stdout"]).decode("utf-8", "replace")
    err = bytes(kept["stderr"]).decode("utf-8", "replace")
    if truncated["stdout"]:
        out += f"\n...[stdout truncated at {MAX_OUTPUT_BYTES} bytes]"
    if truncated["stderr"]:
        err += f"\n...[stderr truncated at {MAX_OUTPUT_BYTES} bytes]"
    return out, err, rc, timed_out


# --------------------------------------------------------------------------- container


def docker_argv(*, container_id: str, workdir: str, image: str = DEFAULT_IMAGE,
                memory_mb: int = MEMORY_MB_DEFAULT, cpus: float = CPUS_DEFAULT,
                pids_limit: int = PIDS_LIMIT_DEFAULT) -> list[str]:
    """The containment argv. Every flag here is load-bearing for the demo:
    drop one and the containment claim becomes a lie. Tested in
    test_containment.test_container_argv_keeps_every_containment_flag."""
    return [
        "docker", "run", "--rm", "-i", "--name", container_id,
        "--network", "none",                  # axis: no egress
        "--memory", f"{memory_mb}m",           # axis: resource limit
        "--memory-swap", f"{memory_mb}m",     # forbid swap escape
        "--cpus", str(cpus),
        "--pids-limit", str(pids_limit),
        "--read-only",                        # axis: process isolation
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "65534:65534",              # non-root
        "--tmpfs", "/tmp:rw,size=64m,noexec",
        "--workdir", "/tmp",
        "-v", f"{workdir}:/task:ro",
        image, "python", "/task/payload.py",
    ]


def run_container(code: str, *, stdin_data: str | None = None,
                  image: str = DEFAULT_IMAGE, timeout: float = TIMEOUT_DEFAULT,
                  memory_mb: int = MEMORY_MB_DEFAULT, cpus: float = CPUS_DEFAULT,
                  pids_limit: int = PIDS_LIMIT_DEFAULT) -> ExecResult:
    """Run `code` in a throwaway container with containment flags applied."""
    container_id = ""
    workdir = tempfile.mkdtemp(prefix="blastradius-")
    path = os.path.join(workdir, "payload.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(code)
    # Docker bind mounts keep host permissions. mkdtemp is 0700 and the payload
    # runs as uid 65534, so on Linux the container would not be able to read its
    # own script. macOS hides this; the VM does not.
    os.chmod(workdir, 0o755)
    os.chmod(path, 0o644)
    limits = _limits_dict(memory_mb, cpus, pids_limit, timeout)
    started = time.monotonic()
    try:
        ready, why = ensure_image(image)
        if not ready:
            return ExecResult(exit_code=125, runtime="container",
                              duration_s=time.monotonic() - started,
                              degraded=True, runtime_error=True,
                              note=f"sandbox image unavailable: {why}", limits=limits)
        cid = f"br-{uuid.uuid4().hex[:12]}"
        cmd = docker_argv(container_id=cid, workdir=workdir, image=image,
                          memory_mb=memory_mb, cpus=cpus, pids_limit=pids_limit)
        container_id = cid
        out, err, rc, timed_out = _run_bounded(
            cmd, timeout=timeout + 5, stdin_data=stdin_data)
        duration = time.monotonic() - started
        # 137 = SIGKILL (OOM/cap), 124 = timeout(1) style clock kill. 139 is
        # SIGSEGV: an unrelated crash, not evidence that a limit was enforced.
        killed = timed_out or rc in (137, 124)
        # 125 is docker's own failure code (bad image, daemon error). Treat it as
        # "not measured" — a probe that never ran must never score CONTAINED.
        runtime_error = (not timed_out) and rc == 125
        return ExecResult(
            stdout=out, stderr=err, exit_code=rc,
            timed_out=timed_out, killed_by_limit=killed, duration_s=duration,
            runtime="container", container_id=cid, degraded=runtime_error,
            runtime_error=runtime_error,
            note=(f"docker error (exit 125): {err.strip()[:160]}"
                  if runtime_error else
                  f"docker {image}, --network none, --read-only, non-root"),
            limits=limits,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ExecResult(exit_code=125, stderr=str(exc), runtime="container",
                          duration_s=time.monotonic() - started,
                          degraded=True, runtime_error=True,
                          note=f"docker error: {exc}", limits=limits)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        _reap(container_id)


def _reap(container_id: str) -> None:
    """Lifecycle discipline: nothing survives the run.

    Cleanup runs in a finally block, so it must never raise — an error here would
    mask the real execution result.
    """
    if not container_id:
        return
    try:
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True,
                       timeout=15)
    except (subprocess.SubprocessError, OSError):
        pass


# --------------------------------------------------------------------------- rlimits


def _apply_limits(workdir: str, mem: int, cpu: int, nproc: int) -> None:
    """Apply POSIX limits in the child process (called via preexec_fn).

    Each limit is guarded: one unsupported limit must degrade only that limit,
    never abort the run. Applied-vs-skipped is reported by limits_support() so
    the report cannot over-claim.

    preexec_fn is not thread-safe on CPython. The rlimits path is a CI/dev
    fallback only; generated (untrusted) code always requires a container, so
    this never runs under the threaded Gradio server.
    """
    os.chdir(workdir)
    try:
        os.setsid()
    except OSError:
        pass
    for res, soft, hard in (
        (resource.RLIMIT_AS, mem, mem),
        (resource.RLIMIT_CPU, cpu, cpu + 1),
        (resource.RLIMIT_NPROC, nproc, nproc),
        (resource.RLIMIT_FSIZE, 32 << 20, 32 << 20),
        (resource.RLIMIT_CORE, 0, 0),
    ):
        try:
            resource.setrlimit(res, (soft, hard))
        except (ValueError, OSError):
            pass


_SUPPORT_CACHE: dict | None = None


def limits_support() -> dict:
    """Which rlimits this platform actually accepts — probed once, reported honestly."""
    global _SUPPORT_CACHE
    if _SUPPORT_CACHE is not None:
        return _SUPPORT_CACHE
    code = (
        "import resource,json\n"
        "out={}\n"
        "for n in ('RLIMIT_AS','RLIMIT_CPU','RLIMIT_NPROC','RLIMIT_FSIZE','RLIMIT_CORE'):\n"
        "    r=getattr(resource,n)\n"
        "    try:\n"
        "        resource.setrlimit(r,resource.getrlimit(r)); out[n]=True\n"
        "    except Exception: out[n]=False\n"
        "print(json.dumps(out))\n"
    )
    try:
        p = subprocess.run([os.sys.executable, "-c", code], capture_output=True,
                           text=True, timeout=15)
        _SUPPORT_CACHE = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:
        _SUPPORT_CACHE = {}
    return _SUPPORT_CACHE


def run_rlimits(code: str, *, stdin_data: str | None = None,
                timeout: float = TIMEOUT_DEFAULT,
                memory_mb: int = MEMORY_MB_DEFAULT,
                pids_limit: int = PIDS_LIMIT_DEFAULT) -> ExecResult:
    """POSIX fallback: real limits, but NOT a security boundary.

    Every result is marked `degraded=True` and the caller must not present it as
    containment. This path exists so the probe suite can run in CI without
    Docker; it is never used for model-written code (see `execute`).
    """
    workdir = tempfile.mkdtemp(prefix="blastradius-fallback-")
    path = os.path.join(workdir, "payload.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(code)
    mem = memory_mb * 1024 * 1024
    support = limits_support()
    limits = _limits_dict(memory_mb, 0.0, pids_limit, timeout)
    limits["applied"] = sorted(k.replace("RLIMIT_", "").lower() for k, ok in support.items() if ok)
    limits["unsupported"] = sorted(k.replace("RLIMIT_", "").lower() for k, ok in support.items() if not ok)
    limits["degraded"] = True

    def _apply() -> None:
        _apply_limits(workdir, mem, int(timeout) + 1, pids_limit)

    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": workdir,
           "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": workdir}
    started = time.monotonic()
    try:
        out, err, rc, timed_out = _run_bounded(
            [os.sys.executable, "-I", path], timeout=timeout, stdin_data=stdin_data,
            cwd=workdir, env=env, preexec_fn=_apply)
        duration = time.monotonic() - started
        # Only a real limit signal counts: SIGKILL (-9/137, memory cap) or
        # SIGXCPU (-24, CPU cap), plus our own wall-clock timeout. SIGABRT (-6)
        # and SIGSEGV (139) are ordinary crashes, not evidence of a limit.
        return ExecResult(stdout=out, stderr=err, exit_code=rc, timed_out=timed_out,
                          killed_by_limit=timed_out or rc in (-9, 137, -24),
                          duration_s=duration, runtime="rlimits", degraded=True,
                          note="DEGRADED: setrlimit + scrubbed env, NOT a security boundary",
                          limits=limits)
    except (OSError, subprocess.SubprocessError) as exc:
        return ExecResult(exit_code=125, stderr=str(exc), runtime="rlimits",
                          duration_s=time.monotonic() - started, degraded=True,
                          runtime_error=True, note=f"fallback error: {exc}", limits=limits)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------- entrypoint


def execute(code: str, *, allow_container: bool = True, allow_rlimits: bool = True,
            require_container: bool = False, stdin_data: str | None = None,
            **kw) -> ExecResult:
    """Pick the strongest runtime available and run `code` once.

    `require_container` refuses to fall back to rlimits. Destructive payloads set
    it, because "run rm -rf where containment is not a boundary" is exactly the
    mistake this project exists to prevent.
    """
    if allow_container and docker_available():
        return run_container(code, stdin_data=stdin_data, **kw)
    if require_container:
        return ExecResult(
            exit_code=125, runtime="none", degraded=True, runtime_error=True,
            note="container required; no Docker daemon — payload was not run")
    if allow_rlimits:
        return run_rlimits(code, stdin_data=stdin_data,
                           **{k: v for k, v in kw.items() if k in
                              ("timeout", "memory_mb", "pids_limit")})
    return ExecResult(exit_code=125, stderr="no runtime available", runtime="none",
                      degraded=True, runtime_error=True,
                      note="Needs Docker (sandbox boundary) or enable the rlimits fallback")
