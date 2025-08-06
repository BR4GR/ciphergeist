# hsb

## Description

Do you usually screw up your crypto implementation? You're not alone, most companies do! But fear not, our newest HSM is the end of all your worries of being hacked. You can use it as a black box for your crypto operations and never need to worry about storing your keys again!

```python
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


def get_random_bytes(l: int):
    alph = list(range(1, 256))
    return b"".join([bytes([choice(alph)]) for _ in range(l)])


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
                        except ValueError as e:
                            print("Invalid input format, must be integer")
                            raise e
                    fn(*args)
            except (ValueError, IndexError):
                print("Invalid option")
                pass
            print()


if __name__ == "__main__":
    HSM().run()
```
```python
FLAG = "FLAG{not_your_real_flag!}"

```
## Author
_MH_

## Solution
The critical issue is that **signing and decryption use identical RSA private key operations** (`pow(data, d, n)`), but have different access controls:

1. **`dec()` function**: Checks message type and blocks `TYPE_INTERNAL` messages
2. **`sign()` function**: No access control checks - accepts any integer input


```bash
ciphergeist$ uv run docs/shc/crypto/hsb/challenge.py
Available operations:
        [0] info
        [1] stop
        [2] gen_key
        [3] sign
        [4] verify
        [5] enc
        [6] dec
        [7] export_secret

Enter selected option: 2

Generated new RSA-2048 keys

Available operations:
        [0] info
        [1] stop
        [2] gen_key
        [3] sign
        [4] verify
        [5] enc
        [6] dec
        [7] export_secret

Enter selected option: 7

Ciphertext: 13258340471726017476632389564224178243428925276647152130120647238616051584136896959156820463563983903446988462454427883433442053593728598341654420554227159801208865717706638614810070836438978967007524905711761899780672020315151182579121015143110463878680441492977001705849872848692165458051367828207362720682404998135964352578316072735911915758542519717070311231382856812132147209642562329070549308600083356159964266142015412575369935045836549940501928326643783862587152275268283820240017302902197383341172204786443682204389581934581158810365794753816733654545363919515545438522924730975517613273656169104267823717158

Available operations:
        [0] info
        [1] stop
        [2] gen_key
        [3] sign
        [4] verify
        [5] enc
        [6] dec
        [7] export_secret

Enter selected option: 3

input 0: 13258340471726017476632389564224178243428925276647152130120647238616051584136896959156820463563983903446988462454427883433442053593728598341654420554227159801208865717706638614810070836438978967007524905711761899780672020315151182579121015143110463878680441492977001705849872848692165458051367828207362720682404998135964352578316072735911915758542519717070311231382856812132147209642562329070549308600083356159964266142015412575369935045836549940501928326643783862587152275268283820240017302902197383341172204786443682204389581934581158810365794753816733654545363919515545438522924730975517613273656169104267823717158
Signature: 65525678152548408827864480691794476748099783502407975229514115525606456211654140414844427187249996075037093010655566785539096478745529139696022978292810451351730851974102632818890811211864816536799445826111357387608760239767821083770231101002837829686157606268844528017282341740450040462166546803476965343023274272257732174707188870472039865317158292948235599104128801018091628663537019235628852087767160003515192426555500274288311180779362032486007373273364228763908752827596525831849267288629912260488309056191851545312724607803183706848696256018533619544689768040190314653100170701060430159497406839639297696125
```

### Flag Extraction

The signature output is the decrypted padded message. Extract the flag:

```python
def decode_signature_to_flag(signature):
    """
    Convert the signature back to the original flag
    """
    try:
        # Convert signature to integer
        sig_int = int(signature)
        print(f"Signature as integer: {sig_int}")

        # Convert to bytes (256 bytes for RSA_LEN)
        decrypted_bytes = sig_int.to_bytes(256, "big")
        print(f"Decrypted bytes length: {len(decrypted_bytes)}")

        # Unpad the data (find the null byte separator)
        pad_end = 1
        while pad_end < len(decrypted_bytes) and decrypted_bytes[pad_end] != 0:
            pad_end += 1

        print(f"Padding ends at position: {pad_end}")
        unpadded = decrypted_bytes[pad_end + 1 :]
        print(f"Unpadded data: {unpadded}")
        print(f"Unpadded hex: {unpadded.hex()}")

        # Check if first byte is TYPE_INTERNAL (0x02)
        if len(unpadded) > 0:
            print(f"First byte: 0x{unpadded[0]:02x}")

            if unpadded[0] == 0x02:  # TYPE_INTERNAL
                print("Found TYPE_INTERNAL marker!")
                flag_bytes = unpadded[1:]
                flag = flag_bytes.decode("utf-8", errors="ignore")
                print(f"\n🎉 FLAG EXTRACTED: {flag}")
                return flag
            else:
                print("TYPE_INTERNAL marker not found, trying to decode whole message...")
                flag = unpadded.decode("utf-8", errors="ignore")
                print(f"Decoded message: {flag}")
                return flag

        return None

    except Exception as e:
        print(f"Error processing signature: {e}")
        return None
```

output

```bash
Signature as integer: 65525678152548408827864480691794476748099783502407975229514115525606456211654140414844427187249996075037093010655566785539096478745529139696022978292810451351730851974102632818890811211864816536799445826111357387608760239767821083770231101002837829686157606268844528017282341740450040462166546803476965343023274272257732174707188870472039865317158292948235599104128801018091628663537019235628852087767160003515192426555500274288311180779362032486007373273364228763908752827596525831849267288629912260488309056191851545312724607803183706848696256018533619544689768040190314653100170701060430159497406839639297696125
Decrypted bytes length: 256
Padding ends at position: 229
Unpadded data: b'\x02FLAG{not_your_real_flag!}'
Unpadded hex: 02464c41477b6e6f745f796f75725f7265616c5f666c6167217d
First byte: 0x02
Found TYPE_INTERNAL marker!

🎉 FLAG EXTRACTED: FLAG{not_your_real_flag!}
```
