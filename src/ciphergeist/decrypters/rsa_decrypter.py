"""RSA decryption tools with various attack methods."""

import math
from typing import Optional

from Crypto.Util.number import GCD, inverse, long_to_bytes

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


class RSADecrypter:
    """RSA decryption toolkit with multiple attack vectors.

    EDUCATIONAL NOTE - ATTACK METHOD EFFECTIVENESS:

    This toolkit implements multiple RSA attack methods for educational purposes.
    In practice, the effectiveness order is:

    1. FactorDB lookup - Covers ~95% of solvable CTF cases instantly by querying
       a database of millions of pre-computed factorizations

    2. Small exponent attack - Targets a different vulnerability class (small e
       with small messages), independent of factorization difficulty

    3-5. Local factorization methods (small primes, Pollard's rho, Fermat) -
         Mostly educational after FactorDB fails, since if FactorDB doesn't have
         the factorization, these methods are very unlikely to succeed. FactorDB
         contains all "easy" cases these methods would find. Mainly useful for
         offline scenarios, network issues, or out of curiosity.

    The local factorization methods are included for completeness, education,
    and understanding of classical cryptanalysis techniques.
    """

    def __init__(self, n: int, e: int, ciphertext: int, verbose: bool = False):
        """Initialize RSA decrypter with public parameters and ciphertext.

        Args:
            n: Public modulus
            e: Public exponent
            ciphertext: Encrypted message
            verbose: Whether to print detailed information (default False)
        """
        self.n = n
        self.e = e
        self.ciphertext = ciphertext
        self.p = None
        self.q = None
        self.d = None
        self.verbose = verbose

    def _extract_rsa_factors(self, data: dict) -> Optional[tuple[int, int]]:
        """Extract RSA factors from FactorDB response data.

        Args:
            data: JSON response from FactorDB API

        Returns:
            Tuple of (p, q) if valid RSA factors found, None otherwise
        """
        factors = data.get("factors", [])

        # Look for exactly 2 prime factors (typical RSA)
        prime_factors = []
        for factor_info in factors:
            factor_str = factor_info[0]
            exponent = factor_info[1]

            if exponent == 1:  # Only consider factors with exponent 1
                try:
                    factor_int = int(factor_str)
                    prime_factors.append(factor_int)
                except ValueError:
                    continue

        if len(prime_factors) == 2:
            p, q = prime_factors[0], prime_factors[1]
            if p * q == self.n:
                if self.verbose:
                    print(f"FactorDB found factors: p = {p}, q = {q}")
                else:
                    print(f"FactorDB found factors: p = {min(p, q)}, q = (use verbose mode)")
                self.p, self.q = p, q
                return p, q

        print("FactorDB found factorization but not suitable for RSA")
        return None

    def factordb_lookup(self) -> Optional[tuple[int, int]]:
        """Query FactorDB.com for known factorizations.

        Returns:
            Tuple of (p, q) if factorization found, None otherwise
        """
        if not HTTPX_AVAILABLE:
            if self.verbose:
                print("FactorDB lookup skipped: httpx not available")
            return None

        print("Checking FactorDB.com for known factorization...")

        try:
            url = f"https://factordb.com/api?query={self.n}"
            response = httpx.get(url, timeout=10.0)

            if response.status_code != 200:
                print("FactorDB lookup failed: HTTP error")
                return None

            data = response.json()

            # Check if the number is factored
            if data.get("status") == "FF":  # Fully Factored
                return self._extract_rsa_factors(data)
            else:
                print("FactorDB: Number not fully factored")
                return None

        except Exception as e:
            if self.verbose:
                print(f"FactorDB lookup failed: {e}")
            else:
                print("FactorDB lookup failed")
            return None

    def factor_small_primes(self, max_prime: int = 10000) -> Optional[tuple[int, int]]:
        """Attempt to factor n by testing small prime factors.

        Args:
            max_prime: Maximum prime to test (default 10000)

        Returns:
            Tuple of (p, q) if factorization found, None otherwise
        """
        print(f"Attempting to factor n with small primes up to {max_prime}...")

        # Test small prime factors
        # Use a more efficient approach for very large numbers
        sqrt_limit = min(max_prime, 100000)  # Cap the search to avoid overflow

        for i in range(2, sqrt_limit):
            if self.n % i == 0:
                p = i
                q = self.n // i
                if self.verbose:
                    print(f"Found factors: p = {p}, q = {q}")
                else:
                    print(f"Found factors: p = {p}, q = (use verbose mode)")
                self.p, self.q = p, q
                return p, q

        print("No small prime factors found")
        return None

    def pollards_rho(self, max_iterations: int = 100000) -> Optional[tuple[int, int]]:
        """Pollard's rho algorithm for factorization.

        Args:
            max_iterations: Maximum iterations to attempt

        Returns:
            Tuple of (p, q) if factorization found, None otherwise
        """
        print("Attempting Pollard's rho factorization...")

        def f(x):
            return (x * x + 1) % self.n

        x = 2
        y = 2

        for _ in range(max_iterations):
            x = f(x)
            y = f(f(y))

            gcd_val = GCD(abs(x - y), self.n)

            if 1 < gcd_val < self.n:
                p = gcd_val
                q = self.n // p
                if self.verbose:
                    print(f"Pollard's rho found factors: p = {p}, q = {q}")
                else:
                    print(f"Pollard's rho found factors: p = {p}, q = (use verbose mode)")
                self.p, self.q = p, q
                return p, q

        print("Pollard's rho failed to find factors")
        return None

    def fermat_factorization(self, max_iterations: int = 100000) -> Optional[tuple[int, int]]:
        """Fermat's factorization method (works well when p and q are close).

        Args:
            max_iterations: Maximum iterations to attempt

        Returns:
            Tuple of (p, q) if factorization found, None otherwise
        """
        print("Attempting Fermat factorization...")

        a = math.isqrt(self.n) + 1

        for _ in range(max_iterations):
            b_squared = a * a - self.n
            if b_squared < 0:
                a += 1
                continue

            b = math.isqrt(b_squared)

            if b * b == b_squared:
                p = a - b
                q = a + b
                if p * q == self.n and p > 1 and q > 1:
                    if self.verbose:
                        print(f"Fermat found factors: p = {p}, q = {q}")
                    else:
                        print(f"Fermat found factors: p = {p}, q = (use verbose mode)")
                    self.p, self.q = p, q
                    return p, q

            a += 1

        print("Fermat factorization failed")
        return None

    def calculate_private_key(self) -> Optional[int]:
        """Calculate private key from known factors.

        Returns:
            Private exponent d if successful, None otherwise
        """
        if not (self.p and self.q):
            print("Need factors p and q to calculate private key")
            return None

        phi = (self.p - 1) * (self.q - 1)

        try:
            self.d = inverse(self.e, phi)
            if self.verbose:
                print(f"Calculated private key: d = {self.d}")
                return self.d
            else:
                print("Calculated private key: d = (use verbose mode)")
                return self.d
        except ValueError as e:
            print(f"Failed to calculate private key: {e}")
            return None

    def decrypt(self) -> Optional[bytes]:
        """Decrypt the ciphertext using the private key.

        Returns:
            Decrypted message as bytes if successful, None otherwise
        """
        if not self.d:
            print("Private key not available for decryption")
            return None

        try:
            plaintext_int = pow(self.ciphertext, self.d, self.n)
            plaintext_bytes = long_to_bytes(plaintext_int)
            if self.verbose:
                print(f"Decrypted message: {plaintext_bytes}")
                return plaintext_bytes
            else:
                return plaintext_bytes
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

    def small_exponent_attack(self) -> Optional[bytes]:
        """Attempt small exponent attack (when e is small and message^e < n).

        Returns:
            Decrypted message if successful, None otherwise
        """
        if self.e >= 10:  # Only try for very small exponents
            return None

        print(f"Attempting small exponent attack with e = {self.e}")

        # Try taking the eth root directly
        for k in range(100):  # Try different k values
            potential_message = int(pow(self.ciphertext + k * self.n, 1 / self.e))

            if pow(potential_message, self.e) == self.ciphertext:
                try:
                    plaintext_bytes = long_to_bytes(potential_message)
                except (ValueError, OverflowError):
                    continue
                else:
                    print(f"Small exponent attack successful: {plaintext_bytes}")
                    return plaintext_bytes

        print("Small exponent attack failed")
        return None

    def auto_decrypt(self) -> Optional[bytes]:
        """Automatically try various attack methods in order of likelihood.

        Returns:
            Decrypted message if any method succeeds, None otherwise
        """
        # Method 1: FactorDB lookup (fastest for known factorizations)
        factors = self.factordb_lookup()
        if factors:
            self.calculate_private_key()
            return self.decrypt()

        # Method 2: Small exponent attack
        result = self.small_exponent_attack()
        if result:
            return result

        # Method 3: Small prime factorization
        factors = self.factor_small_primes()
        if factors:
            self.calculate_private_key()
            return self.decrypt()

        # Method 4: Pollard's rho
        factors = self.pollards_rho()
        if factors:
            self.calculate_private_key()
            return self.decrypt()

        # Method 5: Fermat factorization
        factors = self.fermat_factorization()
        if factors:
            self.calculate_private_key()
            return self.decrypt()

        print("All decryption methods failed")
        return None


if __name__ == "__main__":
    # Example usage with the challenge from really_secure_application.md
    n = 1186029292037952909983792432306452587425266074685148559256411524118533884795954832993947356308189843827916747393770934033391200656633881903962557992375311329821223845429093776689672634207483637282457856395284891548748666784553146529707500135533133296584880911894111872112018935683414189955943902732488471774953
    e = 65537
    ciphertext = 733568336222790589470096969949196690400886881122508612017162580799729948344126319987475331014669434677564792251353760238087218803592587521385878004071493183548939254573853401155722047457350634791379651022516512709399603944845196902930993851922578027579933013748262257897144604228176365756268938687669643000231

    # Set verbose=True to see detailed output with large numbers
    decrypter = RSADecrypter(n, e, ciphertext, verbose=False)
    result = decrypter.auto_decrypt()
    if result:
        print(f"\n🎉 SUCCESS! Decrypted flag: {result.decode('utf-8', errors='ignore')}")
    else:
        print("\n❌ Failed to decrypt the message")
