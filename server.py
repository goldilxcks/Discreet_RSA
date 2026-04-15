import socket
import threading
import json
import random
import hashlib
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, prev_x, prev_y = extended_gcd(b, a % b)
    x = prev_y
    y = prev_x - (a // b) * prev_y
    return g, x, y
def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % phi
def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for divisor in range(3, int(n ** 0.5) + 1, 2):
        if n % divisor == 0:
            return False
    return True
def generate_prime(start=200, end=500):
    number = random.randint(start, end)
    while not is_prime(number):
        number = random.randint(start, end)
    return number
def generate_rsa_keys():
    p = generate_prime()
    q = generate_prime()
    while p == q:
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = mod_inverse(e, phi)
    return (e, n), (d, n)
def rsa_encrypt_number(number, public_key):
    e, n = public_key
    return pow(number, e, n)
def rsa_decrypt_number(number, private_key):
    d, n = private_key
    return pow(number, d, n)
def get_hash(message):
    return hashlib.sha256(message.encode("utf-8")).hexdigest()

def xor_encrypt(message, secret_key):
    key_stream = hashlib.sha256(str(secret_key).encode("utf-8")).digest()
    source = message.encode("utf-8")
    result = bytearray()
    for index, value in enumerate(source):
        result.append(value ^ key_stream[index % len(key_stream)])
    return result.hex()
def xor_decrypt(encrypted_hex, secret_key):
    key_stream = hashlib.sha256(str(secret_key).encode("utf-8")).digest()
    source = bytes.fromhex(encrypted_hex)
    result = bytearray()
    for index, value in enumerate(source):
        result.append(value ^ key_stream[index % len(key_stream)])

    return result.decode("utf-8")

class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.secret_keys = {}
        self.client_files = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_json(self, client, data):
        packet = json.dumps(data) + "\n"
        client.sendall(packet.encode("utf-8"))
    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        while True:
            c, addr = self.s.accept()
            client_file = c.makefile("r", encoding="utf-8")
            self.client_files[c] = client_file

            username_data = json.loads(client_file.readline())
            username = username_data["username"]

            print(f"{username} tries to connect")

            self.username_lookup[c] = username
            self.clients.append(c)

            key_data = json.loads(client_file.readline())
            client_public_key = (key_data["e"], key_data["n"])

            secret_key = random.randint(1000, 9999)
            self.secret_keys[c] = secret_key
            encrypted_secret = rsa_encrypt_number(secret_key, client_public_key)

            self.send_json(c, {
                "type": "secret_key",
                "value": encrypted_secret
            })

            self.broadcast(f"new person has joined: {username}")
            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients:
            try:
                client_secret = self.secret_keys[client]
                encrypted_message = xor_encrypt(msg, client_secret)
                message_hash = get_hash(msg)

                self.send_json(client, {
                    "type": "message",
                    "hash": message_hash,
                    "encrypted_message": encrypted_message
                })
            except Exception:
                pass

    def handle_client(self, c: socket.socket, addr):
        while True:
            try:
                raw_data = self.client_files[c].readline()
                if not raw_data:
                    break
                payload = json.loads(raw_data)
                if payload["type"] != "message":
                    continue
                sender_secret = self.secret_keys[c]
                encrypted_message = payload["encrypted_message"]
                received_hash = payload["hash"]
                plain_text = xor_decrypt(encrypted_message, sender_secret)
                if get_hash(plain_text) != received_hash:
                    continue

                sender_name = self.username_lookup[c]
                final_text = f"{sender_name}: {plain_text}"
                for client in self.clients:
                    if client != c:
                        client_secret = self.secret_keys[client]
                        new_encrypted = xor_encrypt(final_text, client_secret)
                        new_hash = get_hash(final_text)

                        self.send_json(client, {
                            "type": "message",
                            "hash": new_hash,
                            "encrypted_message": new_encrypted
                        })

            except Exception:
                if c in self.clients:
                    self.clients.remove(c)
                if c in self.username_lookup:
                    del self.username_lookup[c]
                if c in self.secret_keys:
                    del self.secret_keys[c]
                if c in self.client_files:
                    del self.client_files[c]
                break

if __name__ == "__main__":
    s = Server(9001)
    s.start()
