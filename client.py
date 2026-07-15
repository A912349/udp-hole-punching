"""Universal UDP hole-punching client.

The NAT mode is detected automatically from STUN mappings.
"""
import select
import secrets
import socket
import struct
import sys
import threading
import time

import requests


MAGIC_COOKIE = 0x2112A442
RELAY_URL = "http://94.159.96.158:8001"

# Cone scanner settings
INITIAL_OFFSET_START = -1000
INITIAL_OFFSET_END = 2000
ROUND_EXPAND_START = 2000
ROUND_EXPAND_END = 2000
INTER_PACKET_DELAY = 0.0005

# Symmetric-NAT burst setting
BURST_SIZE = 500
KEEPALIVE_INTERVAL = 15
KEEPALIVE_PACKET = b"KEEPALIVE"

STUN_SERVERS = [
    ("stun.nextcloud.com", 3478),
    ("stun.miwifi.com", 3478),
    ("stun.voip.blackberry.com", 3478),
    ("stun.sipgate.net", 3478),
]


def stun_request(sock, host, port):
    txid = secrets.token_bytes(12)
    request = struct.pack("!HHI12s", 0x0001, 0, MAGIC_COOKIE, txid)
    try:
        sock.sendto(request, (host, port))
        data, _ = sock.recvfrom(2048)
    except socket.timeout:
        return None

    if len(data) < 20:
        return None
    pos = 20
    while pos + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[pos:pos + 4])
        value = data[pos + 4:pos + 4 + attr_len]
        if attr_type == 0x0020 and attr_len >= 8 and value[1] == 1:
            mapped_port = struct.unpack("!H", value[2:4])[0] ^ (MAGIC_COOKIE >> 16)
            mapped_ip = struct.unpack("!I", value[4:8])[0] ^ MAGIC_COOKIE
            return socket.inet_ntoa(struct.pack("!I", mapped_ip)), mapped_port
        pos += 4 + ((attr_len + 3) & ~3)
    return None


def get_external_and_nat_type(sock):
    """Return the first STUN address and NAT type for this local UDP socket.

    Endpoint-independent mappings remain identical for different STUN servers.
    A changed mapping means that the NAT is symmetric for our purposes.
    """
    sock.settimeout(5)
    mappings = []
    try:
        for host, port in STUN_SERVERS:
            try:
                result = stun_request(sock, host, port)
                if result:
                    mappings.append(result)
                    if len(mappings) == 2:
                        nat_type = "cone" if mappings[0] == mappings[1] else "symmetric"
                        return mappings[0], nat_type
            except OSError:
                pass
    finally:
        sock.settimeout(None)
    if mappings:
        raise RuntimeError("Не удалось определить тип NAT: ответил только один STUN-сервер")
    raise RuntimeError("Не удалось получить внешний адрес через STUN")


def wait_for_peer(session_id, peer_id, external, nat_type):
    try:
        requests.post(
            f"{RELAY_URL}/register",
            json={
                "session": session_id,
                "id": peer_id,
                "external": external,
                "nat_type": nat_type,
            },
        ).raise_for_status()
        print("[*] Ожидание второго пира...")
        response = requests.get(
            f"{RELAY_URL}/wait",
            params={"session": session_id, "id": peer_id, "timeout": 60},
        )
        payload = response.json()
    except requests.RequestException as error:
        print(f"[!] Ошибка relay: {error}")
        sys.exit(1)

    if response.status_code != 200 or payload.get("status") != "ready":
        print("[!] Таймаут или ошибка:", payload)
        sys.exit(1)

    host, port = payload["peer"].rsplit(":", 1)
    return host, int(port), payload["peer_nat_type"]


def chat(sock, peer_address):
    stopped = threading.Event()

    def receiver():
        while not stopped.is_set():
            try:
                data, address = sock.recvfrom(65535)
                if data == KEEPALIVE_PACKET:
                    continue
                try:
                    message = data.decode()
                except UnicodeDecodeError:
                    message = repr(data)
                print(f"[{address[0]}:{address[1]}] {message}")
            except OSError:
                return

    def keepalive():
        while not stopped.wait(KEEPALIVE_INTERVAL):
            try:
                sock.sendto(KEEPALIVE_PACKET, peer_address)
            except OSError:
                return

    threading.Thread(target=receiver, daemon=True).start()
    threading.Thread(target=keepalive, daemon=True).start()
    try:
        while True:
            message = input("> ")
            if not message:
                break
            sock.sendto(message.encode(), peer_address)
    except KeyboardInterrupt:
        print("\nЗавершение.")
    finally:
        stopped.set()


def run_cone(session_id, sock, external, nat_type):
    try:
        external_ip, external_port = external
        print(f"[*] Мой внешний адрес: {external_ip}:{external_port}; тип NAT: {nat_type}")
        peer_ip, peer_base_port, peer_nat_type = wait_for_peer(
            session_id,
            f"{nat_type}-{secrets.token_hex(4)}",
            f"{external_ip}:{external_port}",
            nat_type,
        )
        print(f"[+] Пир ({peer_nat_type}, база): {peer_ip}:{peer_base_port}")

        handshake_done = threading.Event()
        peer_actual_address = [None]
        scanned_ports = set()

        def receiver():
            while not handshake_done.is_set():
                try:
                    data, address = sock.recvfrom(65535)
                    if data == b"HELLO_MOBILE":
                        peer_actual_address[0] = address
                        print(f"\n[+] Получен HELLO_MOBILE от {address[0]}:{address[1]}")
                        sock.sendto(b"HELLO_SERVER", address)
                        handshake_done.set()
                    elif peer_nat_type == "cone" and data == b"cone_punch":
                        peer_actual_address[0] = address
                        sock.sendto(b"HELLO_CONE", address)
                    elif peer_nat_type == "cone" and data == b"HELLO_CONE":
                        peer_actual_address[0] = address
                        sock.sendto(b"HELLO_CONE_ACK", address)
                        print(f"\n[+] Получен HELLO_CONE от {address[0]}:{address[1]}")
                        handshake_done.set()
                    elif peer_nat_type == "cone" and data == b"HELLO_CONE_ACK":
                        peer_actual_address[0] = address
                        print(f"\n[+] Получен HELLO_CONE_ACK от {address[0]}:{address[1]}")
                        handshake_done.set()
                except OSError:
                    return

        def scanner():
            start_offset, end_offset = INITIAL_OFFSET_START, INITIAL_OFFSET_END
            round_number = 1
            while not handshake_done.is_set():
                # Continue widening around the peer's reported port until the
                # complete UDP port range has been covered.
                start = max(1, peer_base_port + start_offset)
                end = min(65535, peer_base_port + end_offset)
                ports = [port for port in range(start, end + 1) if port not in scanned_ports]
                print(f"[*] Раунд {round_number}: {start}-{end}, новых портов: {len(ports)}")
                for port in ports:
                    if handshake_done.is_set():
                        return
                    try:
                        sock.sendto(b"cone_punch", (peer_ip, port))
                        scanned_ports.add(port)
                    except OSError:
                        return
                    time.sleep(INTER_PACKET_DELAY)

                if start == 1 and end == 65535:
                    break
                start_offset -= ROUND_EXPAND_START
                end_offset += ROUND_EXPAND_END
                round_number += 1
            if not handshake_done.is_set():
                print("[!] Все UDP-порты просканированы без рукопожатия.")

        threading.Thread(target=receiver, daemon=True).start()
        threading.Thread(target=scanner, daemon=True).start()
        handshake_done.wait()
        print("[+] Связь установлена. Можно общаться.")
        chat(sock, peer_actual_address[0])
    finally:
        sock.close()


def run_symmetric(session_id, external, nat_type):
    # The temporary STUN socket deliberately remains separate: this preserves
    # the original port-prediction/burst behaviour for symmetric NATs.
    external_ip, external_port = external

    print(f"[*] Базовый STUN-адрес: {external_ip}:{external_port}; тип NAT: {nat_type}")
    peer_ip, peer_port, peer_nat_type = wait_for_peer(
        session_id,
        f"{nat_type}-{secrets.token_hex(4)}",
        f"{external_ip}:{external_port}",
        nat_type,
    )
    print(f"[+] Пир ({peer_nat_type}): {peer_ip}:{peer_port}")

    sockets = []
    try:
        print(f"[*] Создаю {BURST_SIZE} сокетов и отправляю punch...")
        for index in range(BURST_SIZE):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("0.0.0.0", 0))
                sock.sendto(b"burst_punch", (peer_ip, peer_port))
                sockets.append(sock)
            except OSError as error:
                print(f"[!] Ошибка создания сокета {index}: {error}")

        handshake_done = threading.Event()
        active_socket = [None]
        peer_actual_address = [None]

        def receiver():
            while not handshake_done.is_set():
                readable, _, _ = select.select(sockets, [], [], 1.0)
                for sock in readable:
                    try:
                        data, address = sock.recvfrom(65535)
                        active_socket[0] = sock
                        peer_actual_address[0] = address
                        print(f"\n[+] Получен пакет от {address[0]}:{address[1]}")
                        sock.sendto(b"HELLO_MOBILE", address)
                        handshake_done.set()
                        return
                    except OSError:
                        return

        threading.Thread(target=receiver, daemon=True).start()
        handshake_done.wait()
        print("[+] Связь установлена. Можно общаться.")
        chat(active_socket[0], peer_actual_address[0])
    finally:
        for sock in sockets:
            sock.close()


def main():
    session_id = input("Session ID: ").strip()
    if not session_id:
        print("Session ID не может быть пустым.")
        sys.exit(2)
    # Cone NAT keeps this socket for scanning; symmetric NAT closes it before
    # making its burst sockets, preserving the original prediction behaviour.
    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe_sock.bind(("0.0.0.0", 0))
    try:
        external, nat_type = get_external_and_nat_type(probe_sock)
        print(f"[*] Автоопределён тип NAT: {nat_type}")
        if nat_type == "cone":
            run_cone(session_id, probe_sock, external, nat_type)
            probe_sock = None
        else:
            run_symmetric(session_id, external, nat_type)
    finally:
        if probe_sock is not None:
            probe_sock.close()


if __name__ == "__main__":
    main()
