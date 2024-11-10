#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from hashlib import sha256
import argparse
import os
import wallycore as wally
import urllib.parse
import ssl
import sys

tls_cert_path = "key_data/server.pem"
server_keys_path = "key_data/server_keys"
pins_path = "key_data/pins"

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        request = urllib.parse.urlparse(self.path)

        if request.path == "/start_handshake":
            print("start_handshake")
            global private_key
            private_key = generate_private_key()
            ske = wally.ec_public_key_from_private_key(private_key)
            public_key_hash = sha256(ske).digest()
            sig = wally.ec_sig_from_bytes(STATIC_SERVER_PRIVATE_KEY, public_key_hash, wally.EC_FLAG_ECDSA)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes('{"id":"0","method":"handshake_init","params":{"sig":"' + bytes2hex(sig) + '","ske":"' + bytes2hex(ske) + '"}}', "utf-8"))
        elif request.path == "/set_pin":
            print("set_pin")
            params = urllib.parse.parse_qs(request.query)

            if not ('ske' in params and 'cke' in params and 'encrypted_data' in params and 'hmac_encrypted_data' in params):
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes("<html><head><title>Bad request</title></head><body>Bad request</body></html>", "utf-8"))
                return

            if not 'private_key' in globals():
                self.send_response(409)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes("<html><head><title>Conflict</title></head><body>You have to start_handshake first</body></html>", "utf-8"))
                return

            ske = hex2bytes(params['ske'][0])
            cke = hex2bytes(params['cke'][0])
            encrypted_data = hex2bytes(params['encrypted_data'][0])
            hmac_encrypted_data = hex2bytes(params['hmac_encrypted_data'][0])

            master_shared_key = wally.ecdh(cke, private_key)
            request_encryption_key = wally.hmac_sha256(master_shared_key, bytearray([0]))
            request_hmac_key = wally.hmac_sha256(master_shared_key, bytearray([1]))
            response_encryption_key = wally.hmac_sha256(master_shared_key, bytearray([2]))
            response_hmac_key = wally.hmac_sha256(master_shared_key, bytearray([3]))
            hmac_calculated = wally.hmac_sha256(request_hmac_key, cke + encrypted_data)

            iv = encrypted_data[:16]
            payload = wally.aes_cbc(request_encryption_key, iv, encrypted_data[16:], wally.AES_FLAG_DECRYPT)

            pin_secret = payload[:32]
            entropy = payload[32:64]
            sig = payload[64:]
            signed_msg = bytearray(sha256(cke + pin_secret + entropy).digest())
            pin_pubkey = wally.ec_sig_to_public_key(signed_msg, sig)

            our_random = bytearray(os.urandom(32))
            new_key = wally.hmac_sha256(our_random, entropy)

            pin_pubkey_hash = sha256(pin_pubkey).digest()
            hash_pin_secret = sha256(pin_secret).digest()

            save_pin_fields(pin_pubkey_hash, hash_pin_secret, new_key, pin_pubkey, 0)

            response = wally.hmac_sha256(new_key, pin_secret)

            iv = os.urandom(16)
            encrypted_key = iv + wally.aes_cbc(response_encryption_key, iv, response, wally.AES_FLAG_ENCRYPT)
            hmac = wally.hmac_sha256(response_hmac_key, encrypted_key)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes('{"id":"0","method":"handshake_complete","params":{"encrypted_key":"' + bytes2hex(encrypted_key) + '","hmac":"' + bytes2hex(hmac) + '"}}', "utf-8"))
        elif request.path == "/get_pin":
            print("get_pin")
            params = urllib.parse.parse_qs(request.query)

            if not ('ske' in params and 'cke' in params and 'encrypted_data' in params and 'hmac_encrypted_data' in params):
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes("<html><head><title>Bad request</title></head><body>Bad request</body></html>", "utf-8"))
                return

            if not 'private_key' in globals():
                self.send_response(409)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(bytes("<html><head><title>Conflict</title></head><body>You have to start_handshake first</body></html>", "utf-8"))
                return

            ske = hex2bytes(params['ske'][0])
            cke = hex2bytes(params['cke'][0])
            encrypted_data = hex2bytes(params['encrypted_data'][0])
            hmac_encrypted_data = hex2bytes(params['hmac_encrypted_data'][0])

            master_shared_key = wally.ecdh(cke, private_key)
            request_encryption_key = wally.hmac_sha256(master_shared_key, bytearray([0]))
            request_hmac_key = wally.hmac_sha256(master_shared_key, bytearray([1]))
            response_encryption_key = wally.hmac_sha256(master_shared_key, bytearray([2]))
            response_hmac_key = wally.hmac_sha256(master_shared_key, bytearray([3]))
            hmac_calculated = wally.hmac_sha256(request_hmac_key, cke + encrypted_data)

            iv = encrypted_data[:16]
            payload = wally.aes_cbc(request_encryption_key, iv, encrypted_data[16:], wally.AES_FLAG_DECRYPT)

            pin_secret = payload[:32]
            entropy = payload[32:64]
            sig = payload[64:]
            signed_msg = bytearray(sha256(cke + pin_secret + entropy).digest())
            pin_pubkey = wally.ec_sig_to_public_key(signed_msg, sig)

            pin_pubkey_hash = sha256(pin_pubkey).digest()

            saved_hash_pin_secret, saved_key, counter = load_pin_fields(pin_pubkey_hash, pin_pubkey)

            hash_pin_secret = sha256(pin_secret).digest()

            if hash_pin_secret == saved_hash_pin_secret:
                print("Correct pin on the " + str(counter + 1) + ". attempt")

                if counter != 0:
                    save_pin_fields(pin_pubkey_hash, hash_pin_secret, saved_key, pin_pubkey, 0)
            else:
                print("Wrong pin (" + str(counter + 1) + ". attempt)")

                if counter >= 2:
                    os.remove(bytes2hex(pin_pubkey_hash) + ".pin")
                    print("Too many wrong attempts")
                else:
                    save_pin_fields(pin_pubkey_hash, saved_hash_pin_secret, saved_key, pin_pubkey, counter + 1)

                # Return a random incorrect key to the Jade
                saved_key = os.urandom(32)

            response = wally.hmac_sha256(saved_key, pin_secret)

            iv = os.urandom(16)
            encrypted_key = iv + wally.aes_cbc(response_encryption_key, iv, response, wally.AES_FLAG_ENCRYPT)
            hmac = wally.hmac_sha256(response_hmac_key, encrypted_key)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes('{"id":"0","method":"handshake_complete","params":{"encrypted_key":"' + bytes2hex(encrypted_key) + '","hmac":"' + bytes2hex(hmac) + '"}}', "utf-8"))
        elif request.path == "/qrcode.js":
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

def save_pin_fields(pin_pubkey_hash, hash_pin_secret, aes_key, pin_pubkey, counter):
    storage_aes_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey)
    count_bytes = counter.to_bytes(1)
    plaintext = hash_pin_secret + aes_key + count_bytes
    iv = os.urandom(16)
    encrypted = iv + wally.aes_cbc(storage_aes_key, iv, plaintext, wally.AES_FLAG_ENCRYPT)
    pin_auth_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey_hash)
    version_bytes = b'\x00'
    hmac_payload = wally.hmac_sha256(pin_auth_key, version_bytes + encrypted)

    os.makedirs(pins_path, exist_ok=True)

    with open(pins_path + "/" + bytes2hex(pin_pubkey_hash) + ".pin", "wb") as f:
        f.write(version_bytes + hmac_payload + encrypted)

def load_pin_fields(pin_pubkey_hash, pin_pubkey):
    with open(pins_path + "/" + bytes2hex(pin_pubkey_hash) + ".pin", "rb") as f:
        data = f.read()

    assert len(data) == 129
    version_bytes = data[:1]
    assert version_bytes[0] == 0
    hmac_received = data[1:33]
    encrypted = data[33:]
    pin_auth_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey_hash)
    hmac_payload = wally.hmac_sha256(pin_auth_key, version_bytes + encrypted)
    assert hmac_payload == hmac_received

    storage_aes_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey)
    iv = encrypted[:16]
    plaintext = wally.aes_cbc(storage_aes_key, iv, encrypted[16:], wally.AES_FLAG_DECRYPT)
    assert len(plaintext) == 32 + 32 + 1

    saved_hash_pin_secret = plaintext[:32]
    saved_key = plaintext[32:64]
    counter = plaintext[64]

    return saved_hash_pin_secret, saved_key, counter

def bytes2hex(byte_array):
    return ''.join('{:02x}'.format(x) for x in byte_array)

def hex2bytes(hex):
    return bytearray(bytes.fromhex(hex))

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

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("Server stopped")
