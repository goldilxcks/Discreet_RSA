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

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.secret_key = None
    def send_json(self, data):
        packet = json.dumps(data) + "\n"
        self.s.sendall(packet.encode("utf-8"))
    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        # self.s.send(self.username.encode())
        self.socket_file = self.s.makefile("r", encoding="utf-8")

        self.send_json({
            "type": "username",
            "username": self.username
        })

        # create key pairs
        self.public_key, self.private_key = generate_rsa_keys()

        # exchange public keys
        self.send_json({
            "type": "public_key",
            "e": self.public_key[0],
            "n": self.public_key[1]
        })

        response = self.socket_file.readline()
        if response:
            payload = json.loads(response)
            if payload.get("type") == "secret_key":
                self.secret_key = rsa_decrypt_number(
                    payload["value"],
                    self.private_key
                )
                print("[client]: secret key received")

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        while True:
            try:
                raw_data = self.socket_file.readline()
                if not raw_data:
                    break

                payload = json.loads(raw_data)

                if payload["type"] != "message":
                    continue

                encrypted_message = payload["encrypted_message"]
                incoming_hash = payload["hash"]

                # decrypt message with the secrete key
                message = xor_decrypt(encrypted_message, self.secret_key)

                if get_hash(message) != incoming_hash:
                    print("[client]: message integrity check failed")
                    continue

                print(message)

            except Exception as e:
                print("[client]: read error:", e)
                break
    def write_handler(self):
        while True:
            try:
                message = input()

                message_hash = get_hash(message)
                encrypted_message = xor_encrypt(message, self.secret_key)

                self.send_json({
                    "type": "message",
                    "hash": message_hash,
                    "encrypted_message": encrypted_message
                })

            except Exception as e:
                print("[client]: write error:", e)
                break

if __name__ == "__main__":
    name = input("Enter your secret name: ")
    cl = Client("127.0.0.1", 9001, name)
    cl.init_connection()
