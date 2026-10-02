#!/usr/bin/env python3
"""Unix CI smoke test using two real processes with different OS identities.

Requires an ordinary account with passwordless sudo. Does not install services.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(base, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data, {"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=15) as response:
        return json.load(response)


def wait_ready(base, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("daemon exited during startup")
        try:
            return request(base, "/health")
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise RuntimeError("daemon did not become ready")


def main():
    assert os.name == "posix" and os.geteuid() != 0, "run as an ordinary Unix user with sudo access"
    binary = Path(sys.argv[1]).resolve()
    subprocess.run(["sudo", "-n", "true"], check=True)
    root_port, user_port = port(), port()
    while user_port == root_port:
        user_port = port()
    processes = []
    with tempfile.TemporaryDirectory(prefix="localshelld-dual-") as directory:
        temp = Path(directory)
        password = "localshelld CI test password"
        credential = {"type": "password", "value": password}
        try:
            for user, listen in [(False, root_port), (True, user_port)]:
                config = temp / ("user" if user else "root") / "config.toml"
                mode = ["--user"] if user else []
                subprocess.run([str(binary), "init", *mode, "--config", str(config), "--password-stdin"],
                               input=password + "\n", text=True, check=True, stdout=subprocess.DEVNULL)
                text = config.read_text().replace(
                    f'bind = "127.0.0.1:{32120 if user else 32119}"', f'bind = "127.0.0.1:{listen}"'
                ).replace('privileged_daemon = "127.0.0.1:32119"', f'privileged_daemon = "127.0.0.1:{root_port}"')
                config.write_text(text)
                prefix = [] if user else ["sudo", "-n", "--"]
                process = subprocess.Popen([*prefix, str(binary), "serve", *mode, "--config", str(config)],
                                           start_new_session=True, stdout=subprocess.DEVNULL)
                processes.append((process, not user))
                health = wait_ready(f"http://127.0.0.1:{listen}", process)
                assert health["daemon"] == ("user" if user else "privileged")
            root_url, user_url = f"http://127.0.0.1:{root_port}", f"http://127.0.0.1:{user_port}"
            token = request(root_url, "/v1/admin/tokens/issue", {"credential": credential})["token"]
            entered = request(user_url, "/v1/sessions/enter", {"token": token})
            assert entered["sudo_available"]
            handle = entered["handle"]
            for sudo, uid in [(False, os.geteuid()), (True, 0)]:
                result = request(user_url, "/v1/commands/run", {"handle": handle, "command": "id -u", "sudo": sudo})
                assert result["success"] and int(result["output"].strip()) == uid, result
            local_token = request(user_url, "/v1/admin/tokens/issue", {"credential": credential})["token"]
            local = request(user_url, "/v1/sessions/enter", {"token": local_token})
            assert not local["sudo_available"]
            try:
                request(user_url, "/v1/commands/run", {"handle": local["handle"], "command": "id -u", "sudo": True})
                raise AssertionError("user token was elevated")
            except urllib.error.HTTPError as error:
                assert error.code == 403
            request(root_url, "/v1/tokens/revoke", {"token": token})
            try:
                request(user_url, "/v1/commands/run", {"handle": handle, "command": "id -u", "sudo": False})
                raise AssertionError("revoked token remained usable")
            except urllib.error.HTTPError as error:
                assert error.code == 401
            rejected = subprocess.run(["sudo", "-n", "--", str(binary), "serve", "--user", "--config", str(config)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            assert rejected.returncode != 0 and "non-elevated" in rejected.stderr
            print("Dual daemon identities verified: sudo=false is current user; sudo=true is root.")
        finally:
            for process, elevated in reversed(processes):
                if process.poll() is None:
                    prefix = ["sudo", "-n"] if elevated else []
                    subprocess.run([*prefix, "/bin/kill", "-TERM", f"-{process.pid}"], check=False)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        subprocess.run([*prefix, "/bin/kill", "-KILL", f"-{process.pid}"], check=False)
                        process.wait(timeout=5)


if __name__ == "__main__":
    main()
