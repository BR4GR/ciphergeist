# Farm Life

## Description
Susan from HR decided that to improve team spirit in the office, they would all go volunteer on a farm.
This caused terrible drama with Veronica, who claimed to have had the idea first.
Marcel chimed in that he hated stinky farms and, like probably everybody else, would not want to join a trip where he would only ruin his brand new white sneakers.
Rumor has it that after weeks of bickering, Veronica booby-trapped the office kitchen and caused Susan to trip...

```python
#!/usr/bin/env python3
import secrets

FLAG = "FAKE_FLAG"

def encrypt(key, plaintext):
    return ''.join(str(int(a) ^ int(b)) for a, b in zip(key, plaintext))


def main():
    # keygen
    key = format(secrets.randbits(365), 'b')
    print("Welcome to the CryptoFarm!")
    while True:
        command = input('Would you like to encrypt a message yourself [1], get the flag [2], or exit [3] \n>').strip()
        try:
            if command == "1":
                data = input('Enter the binary string you want to encrypt \n>')
                print("Ciphertext = ", encrypt(key, data))
                key = format(secrets.randbits(365), 'b')
            elif command == "2":
                print("Flag = ", encrypt(key, format(int.from_bytes(FLAG.encode(), 'big'), 'b')))
            elif command == "3":
                print("Exiting...")
                break
            else:
                print("Please enter a valid input")
        except Exception:
            print("Something went wrong.")

if __name__ == "__main__":
    main()
```

## Author
Roxy

## Solution
```bash
~$ ncat --ssl db5547ac-85da-4ad7-be77-6f3eeaab70ef.library.m0unt41n.ch 31337
Welcome to the CryptoFarm!
Would you like to encrypt a message yourself [1], get the flag [2], or exit [3]
>2
Flag =  000110001011101011000010010010111010010001010011010010010101101100111101000001110111111111001010100001001011100010000001101100100111011110001010101010011111110010011001111111100101100111001111000100000000001110000010010000010101001100010101011100001010000010000100010000100100100001101001011010100110001
Would you like to encrypt a message yourself [1], get the flag [2], or exit [3]
>1
Enter the binary string you want to encrypt
>000110001011101011000010010010111010010001010011010010010101101100111101000001110111111111001010100001001011100010000001101100100111011110001010101010011111110010011001111111100101100111001111000100000000001110000010010000010101001100010101011100001010000010000100010000100100100001101001011010100110001
Ciphertext =  111001101101000011000110011001000110000001100100011010001111011010011110110110001100100010111110101011001100101011011100110111101101110011000010101111101001000011000010110010001011111010000010101111101001011010001010101100101011111010001010110010101101001011001010110010101101001011011110110100001111101
Would you like to encrypt a message yourself [1], get the flag [2], or exit [3]
```

```python
binary_flag = "111001101101000011000110011001000110000001100100011010001111011010011110110110001100100010111110101011001100101011011100110111101101110011000010101111101001000011000010110010001011111010000010101111101001011010001010101100101011111010001010110010101101001011001010110010101101001011011110110100001111101"
flag_int = int(binary_flag, 2)
flag_bytes = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, "big")

print(flag_bytes.decode())
```
