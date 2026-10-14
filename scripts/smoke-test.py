#!/usr/bin/env python3
"""Check mimictl against real sing-box, including a local Reality round trip.

Requires Python 3.10+, sing-box with Reality/uTLS/QUIC support, and OpenSSL.
All listeners and traffic use loopback. Generated keys, certificates and configs
live below target/smoke and are removed when the test finishes. No root, mount,
systemd service, Internet connection or pre-existing node config is needed.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import errno
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import parse_qs, unquote, urlsplit


REPO = Path(__file__).resolve().parents[1]
SECRETS: list[str] = []
PORTS: set[tuple[int, int]] = set()


def redact(value: str) -> str:
    for secret in sorted(SECRETS, key=len, reverse=True):
        if secret:
            value = value.replace(secret, "<test credential>")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def executable(value: str) -> str:
    resolved = shutil.which(value)
    if resolved is None:
        raise RuntimeError(f"Required executable not found: {value}")
    return str(Path(resolved).resolve())


def run(
    command: list[str],
    *,
    env: dict[str, str],
    label: str,
    stdin: str | None = None,
    fails: bool = False,
) -> str:
    result = subprocess.run(
        command,
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
        check=False,
    )
    if (result.returncode == 0) == fails:
        detail = redact((result.stdout + result.stderr)[-4000:])
        raise RuntimeError(f"{label}: unexpected exit {result.returncode}\n{detail}")
    return result.stdout


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    while True:
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if (kind, port) not in PORTS:
            PORTS.add((kind, port))
            return port


@contextlib.contextmanager
def background(command: list[str], directory: Path, env: dict[str, str], name: str):
    log_path = directory / f"{name}.log"
    with log_path.open("w+", encoding="utf-8") as log:
        process = subprocess.Popen(
            command,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        try:
            yield process
        except Exception:
            log.flush()
            log.seek(0)
            detail = redact(log.read()[-4000:])
            if detail.strip():
                print(f"{name} diagnostics:\n{detail}", file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def wait_tcp(process: subprocess.Popen, port: int) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        require(process.poll() is None, "A test service exited before it became ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Timed out waiting for a loopback test listener")


def wait_udp(process: subprocess.Popen, port: int) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        require(process.poll() is None, "The UDP test service exited before it became ready")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    return
                raise
        time.sleep(0.05)
    raise RuntimeError("Timed out waiting for the loopback UDP test listener")


def receive(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("Proxy closed the connection before completing its response")
        data.extend(part)
    return bytes(data)


def request_through_socks(socks_port: int, http_port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(b"\x05\x01\x00")
        require(receive(sock, 2) == b"\x05\x00", "SOCKS authentication negotiation failed")
        sock.sendall(
            b"\x05\x01\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", http_port)
        )
        reply = receive(sock, 4)
        require(reply[:3] == b"\x05\x00\x00", "SOCKS connection was rejected")
        if reply[3] == 1:
            receive(sock, 4)
        elif reply[3] == 4:
            receive(sock, 16)
        elif reply[3] == 3:
            receive(sock, receive(sock, 1)[0])
        else:
            raise RuntimeError("SOCKS returned an unknown address type")
        receive(sock, 2)
        sock.sendall(b"GET /smoke HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        result = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            require(len(result) < 1024 * 1024, "Unexpectedly large HTTP response")


def smoke(binary: str, sing_box: str, openssl: str, directory: Path, rounds: int) -> None:
    root = directory / "root"
    config = root / "etc/sing-box/config.json"
    staging = config.with_name("config.new")
    pubkey = config.with_name("PUBKEY")
    staged_pubkey = config.with_name("PUBKEY.new")
    default = root / "usr/share/mimic-node/default/config.json"
    config.parent.mkdir(parents=True)
    default.parent.mkdir(parents=True)
    template = REPO / "overlay/usr/share/mimic-node/default/config.json"
    shutil.copyfile(template, config)
    shutil.copyfile(template, default)

    # A stale/unsafe mimictl build must never reach the real host service tools.
    # Record attempts even when the caller ignores the command's failure.
    guard = directory / "guard-bin"
    guard.mkdir()
    guard_marker = directory / "forbidden-host-operation"
    for tool in ("systemctl", "chattr", "mount", "umount", "mountpoint"):
        script = guard / tool
        script.write_text(
            "#!/bin/sh\n: > \"$MIMIC_SMOKE_HOST_GUARD\"\n"
            "echo 'Forbidden host operation during isolated smoke test' >&2\nexit 99\n",
            encoding="utf-8",
        )
        script.chmod(0o700)
    env = dict(os.environ)
    env.update(
        MIMIC_NODE_ROOT=str(root),
        SING_BOX_BIN=sing_box,
        MIMIC_SMOKE_HOST_GUARD=str(guard_marker),
        PATH=str(guard) + os.pathsep + env.get("PATH", ""),
        NO_COLOR="1",
        MIMIC_SERVER_IP="127.0.0.1",
    )

    def ctl(*args: str, stdin: str | None = None, fails: bool = False) -> str:
        result = run(
            [binary, *args], env=env, label=f"mimictl {args[0]}", stdin=stdin, fails=fails
        )
        require(not guard_marker.exists(), "mimictl attempted a host operation with MIMIC_NODE_ROOT set")
        return result

    def check(path: Path) -> None:
        run([sing_box, "check", "-c", str(path)], env=env, label="real sing-box check")

    original = config.read_bytes()
    ctl("add", "smoke@localhost")
    require(config.read_bytes() == original, "Adding a user changed active config before apply")
    initialized = read_json(staging)
    reality = initialized["inbounds"][0]["tls"]["reality"]
    user = initialized["inbounds"][0]["users"][0]
    SECRETS.extend([reality["private_key"], user["uuid"], *reality["short_id"]])
    uuid.UUID(user["uuid"])
    require(bool(reality["short_id"]), "Initialization did not generate a Reality short ID")
    require(staged_pubkey.is_file(), "Initialization did not stage the public key")
    ctl("check")
    ctl("verify", "--config", str(staging))

    valid = staging.read_bytes()
    invalid = copy.deepcopy(initialized)
    invalid["smoke_invalid_field"] = True
    write_json(staging, invalid)
    ctl("apply", fails=True)
    require(config.read_bytes() == original, "Invalid apply changed active configuration")
    require(staged_pubkey.is_file() and not pubkey.exists(), "Invalid apply changed public key state")
    staging.write_bytes(valid)
    ctl("apply")
    require(not staging.exists() and not staged_pubkey.exists(), "Apply left staged files behind")
    require(config.read_bytes() == valid and pubkey.is_file(), "Apply did not promote configuration and key")
    ctl("verify")
    active = config.read_bytes()
    ctl("update", "smoke@localhost", "--level", "2", "--dry-run")
    require(not staging.exists() and config.read_bytes() == active, "User dry-run changed configuration")
    ctl("update", "smoke@localhost", "--level", "2")
    require(config.read_bytes() == active, "User update changed active config before apply")
    require(read_json(staging)["inbounds"][0]["users"][0]["name"].endswith(":2"), "User update was not staged")
    ctl("check")
    ctl("discard", "--force")
    require(not staging.exists() and config.read_bytes() == active, "Discard changed active configuration")
    ctl("gen-keys")
    SECRETS.append(read_json(staging)["inbounds"][0]["tls"]["reality"]["private_key"])
    ctl("check")
    ctl("apply")
    ctl("verify")
    print("PASS: default initialization, real validation, failed-apply safety, stage/apply/discard and key rotation")

    active = config.read_bytes()
    for index, arguments in enumerate(
        [
            ("dns", "setup-do-h3", "--dry-run"),
            ("dns", "add-server", "--tag", "smoke-dns", "--server", "127.0.0.1", "--type", "udp", "--dry-run"),
        ]
    ):
        candidate = directory / f"dns-{index}.json"
        write_json(candidate, json.loads(ctl(*arguments)))
        check(candidate)
        require(config.read_bytes() == active and not staging.exists(), "DNS dry-run changed configuration")
    print("PASS: DNS dry-run output accepted by real sing-box")

    cert = directory / "localhost.crt"
    key = directory / "localhost.key"
    run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ],
        env=env,
        label="ephemeral localhost certificate generation",
    )
    password = "auth:@/?#% 密码 " + uuid.uuid4().hex
    obfs_password = "obfs&+:#? 密钥 " + uuid.uuid4().hex
    SECRETS.extend([password, password + "2", obfs_password])
    ctl(
        "hysteria2", "setup", "--port", str(free_port(socket.SOCK_DGRAM)),
        "--password", password, "--cert", str(cert), "--key", str(key),
        "--masquerade", "https://127.0.0.1", "--domain", "localhost",
        "--obfs", "--obfs-password", obfs_password,
    )
    ctl("check")
    ctl("hysteria2", "add-user", "--name", "second", "--password", password + "2")
    ctl("check")
    ctl("add", "second@localhost")
    ctl("check")
    require(
        any(inbound["type"] == "hysteria2" for inbound in read_json(staging)["inbounds"]),
        "VLESS user mutation discarded the Hysteria2 inbound",
    )
    hy2_inbound = copy.deepcopy(next(
        inbound for inbound in read_json(staging)["inbounds"] if inbound["type"] == "hysteria2"
    ))
    hy2_inbound["listen"] = "127.0.0.1"
    hy2_server_path = directory / "hy2-server.json"
    write_json(hy2_server_path, {
        "log": {"level": "warn"},
        "inbounds": [hy2_inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    })
    check(hy2_server_path)
    hy2_link = urlsplit(ctl("hysteria2", "link", "--name", "admin").strip())
    hy2_query = parse_qs(hy2_link.query, strict_parsing=True)
    require(hy2_link.scheme == "hysteria2" and hy2_link.hostname == "127.0.0.1", "Hysteria2 link did not retain explicit loopback address")
    require(unquote(hy2_link.username or "") == password, "Hysteria2 link corrupted Unicode or special authentication characters")
    require(hy2_query.get("obfs-password") == [obfs_password], "Hysteria2 link corrupted its obfuscation password")
    require(hy2_query.get("sni") == ["localhost"], "Hysteria2 link omitted the certificate server name")
    hy2_socks_port = free_port()
    hy2_client = {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": hy2_socks_port}],
        "outbounds": [{
            "type": "hysteria2", "tag": "hy2-out",
            "server": hy2_link.hostname, "server_port": hy2_link.port,
            "password": unquote(hy2_link.username or ""),
            "obfs": {"type": hy2_query["obfs"][0], "password": hy2_query["obfs-password"][0]},
            "tls": {"enabled": True, "server_name": hy2_query["sni"][0], "certificate_path": str(cert), "alpn": ["h3"]},
        }],
        "route": {"final": "hy2-out"},
    }
    hy2_client_path = directory / "hy2-client.json"
    write_json(hy2_client_path, hy2_client)
    check(hy2_client_path)
    ctl("discard", "--force")
    print("PASS: Hysteria2 certificate setup and mixed-protocol user changes accepted by real sing-box")

    handshake_port = free_port()
    server_port = free_port()
    socks_port = free_port()
    server_config = read_json(config)
    inbound = server_config["inbounds"][0]
    inbound["listen"] = "127.0.0.1"
    inbound["listen_port"] = server_port
    inbound["tls"]["server_name"] = "localhost"
    inbound["tls"]["reality"]["handshake"] = {
        "server": "127.0.0.1", "server_port": handshake_port
    }
    write_json(staging, server_config)
    ctl("check")
    ctl("apply")
    links = json.loads(ctl("link", "smoke@localhost", "127.0.0.1"))
    require(
        isinstance(links, list) and len(links) == 1 and links[0].startswith("vless://"),
        "Expected exactly one explicit loopback VLESS share link",
    )
    ctl("verify", "--link", links[0])
    client_path = directory / "client.json"
    ctl("from-link", "--socks", "--out", str(client_path), stdin=json.dumps(links) + "\n")
    check(client_path)
    tun_path = directory / "tun-client.json"
    ctl("from-link", "--tun", "--out", str(tun_path), stdin=json.dumps(links) + "\n")
    check(tun_path)
    client = read_json(client_path)
    require(client["inbounds"][0]["listen"] == "127.0.0.1", "Generated SOCKS inbound is not loopback-only")
    client["inbounds"][0]["listen_port"] = socks_port
    write_json(client_path, client)
    check(client_path)

    payload = ("mimic-node-local-reality-smoke:" + uuid.uuid4().hex).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        hits = 0

        def do_GET(self):
            type(self).hits += 1
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", free_port()), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        with contextlib.ExitStack() as stack:
            handshake = stack.enter_context(background(
                [openssl, "s_server", "-accept", f"127.0.0.1:{handshake_port}",
                 "-cert", str(cert), "-key", str(key), "-tls1_3", "-groups", "X25519", "-www", "-quiet"],
                directory, env, "tls-handshake",
            ))
            wait_tcp(handshake, handshake_port)
            server = stack.enter_context(background(
                [sing_box, "run", "-c", str(config)], directory, env, "vless-server"
            ))
            wait_tcp(server, server_port)
            proxy = stack.enter_context(background(
                [sing_box, "run", "-c", str(client_path)], directory, env, "vless-client"
            ))
            wait_tcp(proxy, socks_port)
            for _ in range(rounds):
                response = request_through_socks(socks_port, httpd.server_port)
                require(response.startswith(b"HTTP/1.0 200 "), "Tunnel did not return HTTP 200")
                require(response.split(b"\r\n\r\n", 1)[1] == payload, "Tunnel HTTP response body differed")
            require(Handler.hits == rounds, "Unexpected HTTP traffic outside the tested tunnel")

            invalid_client = copy.deepcopy(client)
            invalid_port = free_port()
            invalid_client["inbounds"][0]["listen_port"] = invalid_port
            next(out for out in invalid_client["outbounds"] if out["type"] == "vless")["uuid"] = str(uuid.uuid4())
            invalid_path = directory / "invalid-client.json"
            write_json(invalid_path, invalid_client)
            check(invalid_path)
            wrong_proxy = stack.enter_context(background(
                [sing_box, "run", "-c", str(invalid_path)], directory, env, "rejected-client"
            ))
            wait_tcp(wrong_proxy, invalid_port)
            try:
                rejected = request_through_socks(invalid_port, httpd.server_port)
            except (OSError, RuntimeError):
                rejected = b""
            require(payload not in rejected and Handler.hits == rounds, "An invalid VLESS UUID reached the HTTP target")
            require(all(proc.poll() is None for proc in (handshake, server, proxy)), "A tunnel service exited during testing")
        with contextlib.ExitStack() as stack:
            hy2_server = stack.enter_context(background(
                [sing_box, "run", "-c", str(hy2_server_path)], directory, env, "hy2-server"
            ))
            wait_udp(hy2_server, hy2_inbound["listen_port"])
            hy2_proxy = stack.enter_context(background(
                [sing_box, "run", "-c", str(hy2_client_path)], directory, env, "hy2-client"
            ))
            wait_tcp(hy2_proxy, hy2_socks_port)
            for _ in range(rounds):
                response = request_through_socks(hy2_socks_port, httpd.server_port)
                require(response.startswith(b"HTTP/1.0 200 "), "Hysteria2 tunnel did not return HTTP 200")
                require(response.split(b"\r\n\r\n", 1)[1] == payload, "Hysteria2 tunnel HTTP response body differed")
            require(Handler.hits == rounds * 2, "Unexpected HTTP traffic outside the tested tunnels")
            for rejection in ("password", "certificate"):
                invalid_hy2 = copy.deepcopy(hy2_client)
                rejected_port = free_port()
                invalid_hy2["inbounds"][0]["listen_port"] = rejected_port
                if rejection == "password":
                    invalid_hy2["outbounds"][0]["password"] += "-invalid"
                else:
                    invalid_hy2["outbounds"][0]["tls"]["server_name"] = "wrong.localhost"
                rejected_path = directory / f"hy2-rejected-{rejection}.json"
                write_json(rejected_path, invalid_hy2)
                check(rejected_path)
                with background(
                    [sing_box, "run", "-c", str(rejected_path)], directory, env, f"hy2-rejected-{rejection}"
                ) as rejected_proxy:
                    wait_tcp(rejected_proxy, rejected_port)
                    try:
                        rejected = request_through_socks(rejected_port, httpd.server_port)
                    except (OSError, RuntimeError):
                        rejected = b""
                    require(payload not in rejected and Handler.hits == rounds * 2, f"Hysteria2 accepted an invalid {rejection}")
            require(hy2_server.poll() is None and hy2_proxy.poll() is None, "A Hysteria2 service exited during testing")
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)
    require(not guard_marker.exists(), "Test attempted a host service or mount operation")
    print(f"PASS: {rounds} HTTP round trips through generated SOCKS → VLESS/Reality client/server links; invalid UUID rejected")
    print(f"PASS: {rounds} HTTP round trips over Hysteria2/QUIC UDP with salamander and encoded Unicode credentials; password and TLS hostname verified")

    active = config.read_bytes()
    wizard_port = free_port()
    ctl(
        "setup",
        stdin=f"0\n0\n{wizard_port}\nn\nlocalhost\n1\nwizard@localhost\nn\ny\n\n5\n",
    )
    require(config.read_bytes() == active, "Setup wizard changed active configuration before apply")
    wizard = read_json(staging)
    require(wizard["inbounds"][0]["listen_port"] == wizard_port, "Setup wizard ignored selected port")
    require(wizard["inbounds"][0]["users"][0]["name"].startswith("wizard@localhost:"), "Setup wizard did not create the selected user")
    require(staged_pubkey.is_file(), "Setup wizard did not stage its Reality public key")
    SECRETS.append(wizard["inbounds"][0]["tls"]["reality"]["private_key"])
    ctl("check")
    ctl("verify", "--config", str(staging))
    ctl("discard", "--force")
    print("PASS: scripted setup wizard stages a valid authenticated VLESS server; SOCKS and TUN client configs validate")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=str(REPO / "target/debug/mimictl"))
    parser.add_argument("--sing-box", default=os.environ.get("SING_BOX_BIN", "sing-box"))
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    try:
        require(args.rounds > 0, "--rounds must be positive")
        binary = executable(args.binary)
        sing_box = executable(args.sing_box)
        openssl = executable("openssl")
        version = run([sing_box, "version"], env=dict(os.environ), label="sing-box version").splitlines()[0]
        print(f"Integration smoke test: {version}")
        parent = REPO / "target/smoke"
        parent.mkdir(parents=True, exist_ok=True)
        previous_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory(prefix="local-", dir=parent) as temp:
                smoke(binary, sing_box, openssl, Path(temp), args.rounds)
        finally:
            os.umask(previous_umask)
        print("PASS: all temporary services stopped and generated test credentials removed")
        return 0
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL: {redact(str(error))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
