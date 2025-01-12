#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from hashlib import sha256
import argparse
import base64
import os
import wallycore as wally
import urllib.parse
import signal
import ssl
import sys
import json

tls_cert_path = "key_data/server.pem"
server_keys_path = "key_data/server_keys"
pins_path = "key_data/pins"

class GracefulExitHandler:
    def __init__(self, server):
        self.server = server
        signal.signal(signal.SIGTERM, self.graceful_shutdown)
        signal.signal(signal.SIGINT, self.graceful_shutdown)

    def graceful_shutdown(self, signum, frame):
        self.server.server_close()
        print("Server stopped")
        sys.exit(0)

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        content_len = int(self.headers.get('Content-length', '0'))
        post_body = self.rfile.read(content_len)
        try:
            params = json.loads(post_body)
        except json.JSONDecodeError:
            params = {}

        request = urllib.parse.urlparse(self.path)

        if request.path == "/set_pin":
            print("set_pin")

            if not 'data' in params:
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes("<html><head><title>Bad request</title></head><body>Bad request</body></html>", "utf-8"))
                return

            data = base64.b64decode(params['data'])
            assert len(data) > 37
            cke = data[:33]
            replay_counter = data[33:37]
            encrypted_data = data[37:]

            private_key, public_key = generate_ec_key_pair(replay_counter, cke)

            payload = wally.aes_cbc_with_ecdh_key(private_key, None, encrypted_data, cke, b'blind_oracle_request', wally.AES_FLAG_DECRYPT)

            # set_pin requires client-passed entropy
            assert len(payload) == 32 + 32 + 65
            pin_secret = payload[:32]
            entropy = payload[32:64]
            sig = payload[64:]
            signed_msg = bytearray(sha256(cke + replay_counter + pin_secret + entropy).digest())
            pin_pubkey = wally.ec_sig_to_public_key(signed_msg, sig)

            pin_pubkey_hash = sha256(pin_pubkey).digest()

            replay_local = None
            try:
                _, _, _, replay_local = load_pin_fields(pin_pubkey_hash, pin_pubkey)

                # Enforce anti replay (client counter must be greater than the server counter)
                client_counter = int.from_bytes(replay_counter, byteorder='little', signed=False)
                server_counter = int.from_bytes(replay_local, byteorder='little', signed=False)
                assert client_counter > server_counter
            except FileNotFoundError:
                pass

            our_random = os.urandom(32)
            new_key = wally.hmac_sha256(our_random, entropy)

            hash_pin_secret = sha256(pin_secret).digest()
            replay_bytes = b'\x00\x00\x00\x00'
            save_pin_fields(pin_pubkey_hash, hash_pin_secret, new_key, pin_pubkey, 0, replay_bytes)
            aes_key = wally.hmac_sha256(new_key, pin_secret)

            iv = os.urandom(16)
            encrypted_key = wally.aes_cbc_with_ecdh_key(private_key, iv, aes_key, cke, b'blind_oracle_response', wally.AES_FLAG_ENCRYPT)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data":"' + base64.b64encode(encrypted_key) + b'"}')
        elif request.path == "/get_pin":
            print("get_pin")

            if not 'data' in params:
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes("<html><head><title>Bad request</title></head><body>Bad request</body></html>", "utf-8"))
                return

            data = base64.b64decode(params['data'])
            assert len(data) > 37
            cke = data[:33]
            replay_counter = data[33:37]
            encrypted_data = data[37:]

            private_key, public_key = generate_ec_key_pair(replay_counter, cke)

            payload = wally.aes_cbc_with_ecdh_key(private_key, None, encrypted_data, cke, b'blind_oracle_request', wally.AES_FLAG_DECRYPT)

            # get_pin does not need client-passed entropy
            assert len(payload) == 32 + 65
            pin_secret = payload[:32]
            sig = payload[32:]
            signed_msg = bytearray(sha256(cke + replay_counter + pin_secret).digest())
            pin_pubkey = wally.ec_sig_to_public_key(signed_msg, sig)

            pin_pubkey_hash = sha256(pin_pubkey).digest()

            try:
                saved_hash_pin_secret, saved_key, counter, replay_local = load_pin_fields(pin_pubkey_hash, pin_pubkey)

                # Enforce anti replay (client counter must be greater than the server counter)
                client_counter = int.from_bytes(replay_counter, byteorder='little', signed=False)
                server_counter = int.from_bytes(replay_local, byteorder='little', signed=False)
                assert client_counter > server_counter
            except FileNotFoundError:
                # Return a random incorrect key to the Jade
                saved_key = os.urandom(32)
            else:
                hash_pin_secret = sha256(pin_secret).digest()

                if hash_pin_secret == saved_hash_pin_secret:
                    print("Correct pin on the " + str(counter + 1) + ". attempt")
                    save_pin_fields(pin_pubkey_hash, hash_pin_secret, saved_key, pin_pubkey, 0, replay_counter)
                else:
                    print("Wrong pin (" + str(counter + 1) + ". attempt)")

                    if counter >= 2:
                        os.remove(pins_path + "/" + bytes2hex(pin_pubkey_hash) + ".pin")
                        print("Too many wrong attempts")
                    else:
                        save_pin_fields(pin_pubkey_hash, saved_hash_pin_secret, saved_key, pin_pubkey, counter + 1, replay_counter)

                    # Return a random incorrect key to the Jade
                    saved_key = os.urandom(32)

            aes_key = wally.hmac_sha256(saved_key, pin_secret)

            iv = os.urandom(16)
            encrypted_key = wally.aes_cbc_with_ecdh_key(private_key, iv, aes_key, cke, b'blind_oracle_response', wally.AES_FLAG_ENCRYPT)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data":"' + base64.b64encode(encrypted_key) + b'"}')
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("<html><head><title>Not found</title></head><body>Not found</body></html>", "utf-8"))

    def do_GET(self):
        request = urllib.parse.urlparse(self.path)

        if request.path == "/qrcode.js":
            self.send_response(200)
            self.send_header("Content-type", "text/javascript")
            self.end_headers()

            with open("qrcode.js", "r") as file:
                self.wfile.write(bytes(file.read(), "utf-8"))
        elif request.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            with open("index.html", "r") as file:
                self.wfile.write(bytes(file.read(), "utf-8"))
        elif request.path == "/oracle_qr.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            with open("oracle_qr.html", "r") as file:
                file_contents = file.read()
                file_contents = file_contents.replace("{STATIC_SERVER_PUBLIC_KEY}", bytes2hex(STATIC_SERVER_PUBLIC_KEY))
                self.wfile.write(bytes(file_contents, "utf-8"))
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("<html><head><title>Not found</title></head><body>Not found</body></html>", "utf-8"))

def save_pin_fields(pin_pubkey_hash, hash_pin_secret, aes_key, pin_pubkey, counter, replay_counter):
    storage_aes_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey)
    count_bytes = counter.to_bytes(1)
    plaintext = hash_pin_secret + aes_key + count_bytes + replay_counter
    iv = os.urandom(16)
    encrypted = iv + wally.aes_cbc(storage_aes_key, iv, plaintext, wally.AES_FLAG_ENCRYPT)
    pin_auth_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey_hash)
    version_bytes = b'\x01'
    hmac_payload = wally.hmac_sha256(pin_auth_key, version_bytes + encrypted)

    os.makedirs(pins_path, exist_ok=True)

    with open(pins_path + "/" + bytes2hex(pin_pubkey_hash) + ".pin", "wb") as f:
        f.write(version_bytes + hmac_payload + encrypted)

def load_pin_fields(pin_pubkey_hash, pin_pubkey):
    with open(pins_path + "/" + bytes2hex(pin_pubkey_hash) + ".pin", "rb") as f:
        data = f.read()

    assert len(data) == 129
    version_bytes = data[:1]
    assert version_bytes[0] == 1
    hmac_received = data[1:33]
    encrypted = data[33:]
    pin_auth_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey_hash)
    hmac_payload = wally.hmac_sha256(pin_auth_key, version_bytes + encrypted)
    assert hmac_payload == hmac_received

    storage_aes_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey)
    iv = encrypted[:16]
    plaintext = wally.aes_cbc(storage_aes_key, iv, encrypted[16:], wally.AES_FLAG_DECRYPT)
    assert len(plaintext) == 32 + 32 + 1 + 4

    saved_hash_pin_secret = plaintext[:32]
    saved_key = plaintext[32:64]
    counter = plaintext[64]
    replay_counter_persisted = plaintext[65:69]

    return saved_hash_pin_secret, saved_key, counter, replay_counter_persisted

def bytes2hex(byte_array):
    return ''.join('{:02x}'.format(x) for x in byte_array)

def hex2bytes(hex):
    return bytearray(bytes.fromhex(hex))

def generate_ec_key_pair(replay_counter, cke):
    tweak = sha256(wally.hmac_sha256(cke, replay_counter)).digest()
    private_key = wally.ec_private_key_bip341_tweak(STATIC_SERVER_PRIVATE_KEY, tweak, 0)
    wally.ec_private_key_verify(private_key)
    public_key = wally.ec_public_key_from_private_key(private_key)

    return private_key, public_key

def generate_private_key():
    while True:
        private_key = bytearray(os.urandom(32))
        try:
            wally.ec_private_key_verify(private_key)
            break
        except Exception:
            pass

    return private_key

def get_static_server_key_pair():
    os.makedirs(server_keys_path, exist_ok=True)
    private_key_path = server_keys_path + "/private.key"
    public_key_path = server_keys_path + "/public.key"

    if os.path.isfile(private_key_path):
        with open(private_key_path, "rb") as f:
            private_key = bytearray(f.read())
    else:
        private_key = generate_private_key()

        with open(private_key_path, "wb") as f:
            f.write(private_key)

    public_key = wally.ec_public_key_from_private_key(private_key)

    with open(public_key_path, "wb") as f:
        f.write(public_key)

    return private_key, public_key

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple reimplementation of the blind_pin_server for the Blockstream Jade, "
                    "along with a basic web interface"
    )
    parser.add_argument(
        "-p", "--port",
        type=int, default=4443,
        help="port number to listen on"
    )
    parser.add_argument(
        "--tls",
        action=argparse.BooleanOptionalAction, default=True,
        help="whether to use HTTPS (HTTP over TLS) for secure access, required by modern browsers "
             "to enable webcam access on non-localhost connections. "
             "Enabled by default; use --no-tls to disable."
    )
    args = parser.parse_args()

    listen_ip = "0.0.0.0"
    server = HTTPServer((listen_ip, args.port), MyServer)

    if args.tls:
        if not os.path.isfile(tls_cert_path):
            print(
                f"TLS certificate not found at {tls_cert_path}. "
                "Either provide a certificate or use --no-tls to disable TLS. "
                "Note that TLS is required by modern browsers to enable webcam access on "
                "non-localhost connections."
            )
            sys.exit(1)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=tls_cert_path)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)

    print(f"Server starting on {'https' if args.tls else 'http'}://{listen_ip}:{args.port}")

    global STATIC_SERVER_PRIVATE_KEY, STATIC_SERVER_PUBLIC_KEY, STATIC_SERVER_AES_PIN_DATA
    STATIC_SERVER_PRIVATE_KEY, STATIC_SERVER_PUBLIC_KEY = get_static_server_key_pair()
    STATIC_SERVER_AES_PIN_DATA = wally.hmac_sha256(STATIC_SERVER_PRIVATE_KEY, b'pin_data')

    GracefulExitHandler(server)
    server.serve_forever()
