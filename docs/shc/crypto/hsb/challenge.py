#!/usr/bin/env python3

from inspect import signature
from secrets import choice

from Crypto.PublicKey import RSA
from secret import FLAG

RSA_LEN = 256

TYPE_USER = b"\x01"
TYPE_INTERNAL = b"\x02"


def b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def i2b(i: int) -> bytes:
    return i.to_bytes((i.bit_length() + 7) // 8, "big")


def get_random_bytes(length: int):
    alph = list(range(1, 256))
    return b"".join([bytes([choice(alph)]) for _ in range(length)])


def pad(p: bytes) -> bytes:
    return get_random_bytes(RSA_LEN - len(p) - 2) + b"\x00" + p


def unpad(p: bytes) -> bytes:
    pad_end = 1
    while pad_end < len(p) and p[pad_end] != 0:
        pad_end += 1
    return p[pad_end + 1 :]


class HSM:
    def __init__(self):
        self.vendor = "Cybersecurity Competence Center"
        self.model = "Perfection v2.1"
        self.rsa = None
        self.running = False

    def info(self):
        print(f"Vendor: {self.vendor}\nModel: {self.model}")

    def stop(self):
        if not self.running:
            print("HSM is already stopped.")
            return
        self.running = False

    def gen_key(self):
        bits = RSA_LEN * 8
        self.rsa = RSA.generate(bits)
        print(f"Generated new RSA-{bits} keys")

    def sign(self, m: int):
        m_pad = int.from_bytes(pad(i2b(m)), "big")
        sig = pow(m_pad, self.rsa.d, self.rsa.n)
        print(f"Signature: {sig}")

    def verify(self, sig: int, m: int):
        recovered = b2i(unpad(pow(sig, self.rsa.e, self.rsa.n).to_bytes(RSA_LEN, "big")))
        if recovered == m:
            print("Valid signature.")
        else:
            print("Invalid signature.")

    def _enc(self, m: bytes):
        c = pow(int.from_bytes(pad(m), "big"), self.rsa.e, self.rsa.n)
        print(f"Ciphertext: {c}")

    def enc(self, m: int):
        self._enc(TYPE_USER + i2b(m))

    def dec(self, c: int):
        m = unpad(pow(c, self.rsa.d, self.rsa.n).to_bytes(RSA_LEN, "big"))
        t, m = m[:1], b2i(m[1:])

        if t == TYPE_USER:
            print(f"Plaintext: {m}")
        else:
            print("Cannot decrypt internal secrets")

    def export_secret(self):
        self._enc(TYPE_INTERNAL + FLAG.encode())

    def run(self):
        self.running = True
        options = [self.info, self.stop, self.gen_key, self.sign, self.verify, self.enc, self.dec, self.export_secret]

        while self.running:
            print("Available operations:")
            for i, opt in enumerate(options):
                print(f"\t[{i}] {opt.__name__}")
            print()

            try:
                opt = int(input("Enter selected option: "))
                print()
                if opt > 2 and not self.rsa:
                    print("No RSA key available. Use gen_key() first.")
                else:
                    fn = options[opt]
                    args = []
                    for i in range(len(signature(fn).parameters)):
                        try:
                            args.append(int(input(f"input {i}: ")))
                        except ValueError:
                            print("Invalid input format, must be integer")
                            raise
                    fn(*args)
            except (ValueError, IndexError):
                print("Invalid option")
                pass
            print()


if __name__ == "__main__":
    HSM().run()
