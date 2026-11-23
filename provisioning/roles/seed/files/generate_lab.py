#!/usr/bin/env python3
"""
RSA lab - generator of the per-student challenge material.

Runs ONCE during sandbox provisioning (as root, on the "seed" VM) and is deleted afterwards.
Input : a JSON file with the six per-sandbox flags (APG variables), the lab directory and the
        owner of the files.
Output: the directory tree ~/rsa-lab/task1 ... task6 with numbers that are DIFFERENT for every
        sandbox.

Design (anti-cheating):
  * Every number (primes, keys, ciphertexts, certificates) is unique per sandbox.
  * The flags are never stored in clear text on the VM.
      - Task 1, Task 3: the flag is the plaintext of an RSA ciphertext (textbook RSA).
        The student recovers it by performing the RSA decryption asked by the lab.
      - Task 2, 4, 5, 6: the flag is stored AES-256 encrypted (openssl enc -pbkdf2).
        The AES passphrase is the exact result of the computation requested by the lab
        (ciphertext, signatures, verification result, recovered PKCS#1 block...).
        Only a student who really performs the computation on HIS numbers can decrypt it.
  * Everything is derived deterministically from the flags with a SHA-256 based DRBG, except
    the X.509 certificates of Task 6 (they are made by openssl).

Only the Python 3 standard library and the openssl command line tool are required.
"""
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

TOKEN_RE = re.compile(r"^[A-Za-z0-9]{6,32}$")
SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")
SMALL_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


# --------------------------------------------------------------------------------------------
# deterministic random generator + prime numbers
# --------------------------------------------------------------------------------------------
class DRBG:
    """Tiny deterministic generator: SHA-256(key || counter)."""

    def __init__(self, seed: bytes):
        self.key = hashlib.sha256(b"rsa-lab-seed|" + seed).digest()
        self.counter = 0
        self.buf = b""

    def getrandbits(self, k: int) -> int:
        nbytes = (k + 7) // 8
        while len(self.buf) < nbytes:
            self.buf += hashlib.sha256(self.key + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        out, self.buf = self.buf[:nbytes], self.buf[nbytes:]
        return int.from_bytes(out, "big") >> (nbytes * 8 - k)

    def randrange(self, lo: int, hi: int) -> int:
        span = hi - lo
        k = span.bit_length()
        while True:
            r = self.getrandbits(k)
            if r < span:
                return lo + r


def is_probable_prime(n: int, rng: DRBG, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for sp in SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int, rng: DRBG) -> int:
    """Random prime with exactly `bits` bits; the two top bits are set so that p*q has 2*bits bits."""
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(c, rng):
            return c


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def make_rsa(rng: DRBG, bits: int = 128, e: int = 65537) -> dict:
    """RSA key with two `bits`-bit primes (n has 2*bits bits). Private key d = e^-1 mod (p-1)(q-1)."""
    while True:
        p, q = gen_prime(bits, rng), gen_prime(bits, rng)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue
        return {"p": p, "q": q, "n": p * q, "e": e, "phi": phi, "d": pow(e, -1, phi)}


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------
def hexu(x: int) -> str:
    """Upper-case hexadecimal with an even number of digits (same style as OpenSSL BN_bn2hex)."""
    h = format(x, "X")
    return ("0" + h) if len(h) % 2 else h


def norm_hex(x: int) -> str:
    """Canonical form used for AES passphrases: upper-case hex, no leading zeros."""
    return format(x, "X")


def text_to_int(s: str) -> int:
    return int.from_bytes(s.encode("utf-8"), "big")


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


def aes_encrypt_flag(token: str, passphrase: str) -> str:
    """openssl enc -aes-256-cbc -pbkdf2 -salt -a  (the passphrase goes through the environment)."""
    env = dict(os.environ, RSALAB_PASS=passphrase)
    res = run(
        ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-a", "-pass", "env:RSALAB_PASS"],
        input=(token + "\n").encode(),
        env=env,
    )
    return res.stdout.decode()


def aes_decrypt_flag(data: str, passphrase: str) -> str:
    env = dict(os.environ, RSALAB_PASS=passphrase)
    res = run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-a", "-pass", "env:RSALAB_PASS"],
        input=data.encode(),
        env=env,
    )
    return res.stdout.decode().strip()


class Lab:
    def __init__(self, lab_dir: str, owner):
        self.lab_dir = lab_dir
        self.uid = self.gid = None
        if owner:
            pw = pwd.getpwnam(owner)
            self.uid, self.gid = pw.pw_uid, pw.pw_gid

    def write(self, rel: str, text: str, mode: int = 0o644):
        path = os.path.join(self.lab_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(path, mode)

    def fix_owner(self):
        for root, dirs, files in os.walk(self.lab_dir):
            for name in dirs + files + ["."]:
                full = os.path.join(root, name)
                if self.uid is not None:
                    os.chown(full, self.uid, self.gid)


# --------------------------------------------------------------------------------------------
# the six tasks
# --------------------------------------------------------------------------------------------
def task1(lab: Lab, rng: DRBG, token: str):
    """Derive the private key d from p, q, e. Proof: decrypt a ciphertext whose plaintext is the flag."""
    e = gen_prime(20, rng)  # a 20-bit prime exponent, like 0x0D88C3 in the lab sheet
    k = make_rsa(rng, 128, e)  # p, q such that gcd(e, (p-1)(q-1)) = 1
    m = text_to_int(token)
    assert m < k["n"]
    c = pow(m, k["e"], k["n"])
    assert pow(c, k["d"], k["n"]) == m
    lab.write(
        "task1/params.txt",
        "# Task 1 - Deriving the Private Key (all numbers are hexadecimal)\n"
        "# p, q and e are prime numbers. n = p*q. (e, n) is the public key.\n"
        f"p = {hexu(k['p'])}\n"
        f"q = {hexu(k['q'])}\n"
        f"e = {hexu(k['e'])}\n"
        "\n"
        "# Proof of work: C was encrypted with the public key (e, n) (textbook RSA, no padding).\n"
        "# Decrypt it with the private key d you derived. The plaintext is an ASCII string: your flag.\n"
        f"C = {hexu(c)}\n",
    )


def keypair_for_tasks_2_3_4(rng: DRBG) -> dict:
    return make_rsa(rng, 128, 65537)


def task2(lab: Lab, k: dict, token: str):
    """Encrypt "A top secret!" ; the ciphertext is the AES passphrase of the flag."""
    msg = "A top secret!"
    c = pow(text_to_int(msg), k["e"], k["n"])
    lab.write(
        "task2/params.txt",
        "# Task 2 - Encrypting a Message (all numbers are hexadecimal)\n"
        f"n = {hexu(k['n'])}\n"
        f"e = {hexu(k['e'])}\n"
        f"M = {msg}\n"
        "# The private key is given only to help you verify your result (decrypt your ciphertext).\n"
        f"d = {hexu(k['d'])}\n",
    )
    lab.write("task2/flag2.enc", aes_encrypt_flag(token, norm_hex(c)))


def task3(lab: Lab, k: dict, token: str):
    """Decrypt a ciphertext whose plaintext is the flag."""
    m = text_to_int(token)
    c = pow(m, k["e"], k["n"])
    lab.write(
        "task3/params.txt",
        "# Task 3 - Decrypting a Message (same keys as Task 2; all numbers are hexadecimal)\n"
        f"n = {hexu(k['n'])}\n"
        f"e = {hexu(k['e'])}\n"
        f"d = {hexu(k['d'])}\n"
        "\n"
        f"C = {hexu(c)}\n",
    )


def task4(lab: Lab, k: dict, token: str):
    """Sign two messages ; the two signatures form the AES passphrase of the flag."""
    m1, m2 = "I owe you $2000.", "I owe you $3000."
    s1, s2 = pow(text_to_int(m1), k["d"], k["n"]), pow(text_to_int(m2), k["d"], k["n"])
    lab.write(
        "task4/params.txt",
        "# Task 4 - Signing a Message (same keys as Task 2; all numbers are hexadecimal)\n"
        "# Sign the messages DIRECTLY (do not hash them): S = M^d mod n\n"
        f"n = {hexu(k['n'])}\n"
        f"e = {hexu(k['e'])}\n"
        f"d = {hexu(k['d'])}\n"
        f"M1 = {m1}\n"
        f"M2 = {m2}\n",
    )
    lab.write("task4/flag4.enc", aes_encrypt_flag(token, norm_hex(s1) + ":" + norm_hex(s2)))


def task5(lab: Lab, rng: DRBG, token: str):
    """Verify Alice's signature, then verify a corrupted copy ; both results form the passphrase."""
    k = make_rsa(rng, 128, 65537)
    msg = "Launch a missile."
    m = text_to_int(msg)
    s = pow(m, k["d"], k["n"])
    v1 = pow(s, k["e"], k["n"])
    s_bad = s ^ 0x10  # last byte: second-to-last hex digit XOR 1  (e.g. 2F -> 3F)
    v2 = pow(s_bad, k["e"], k["n"])
    assert v1 == m and v2 != m
    lab.write(
        "task5/params.txt",
        "# Task 5 - Verifying a Signature (all numbers are hexadecimal)\n"
        "# Bob received the message M from Alice, together with her signature S.\n"
        "# Alice's public key is (e, n).\n"
        f"M = {msg}\n"
        f"S = {hexu(s)}\n"
        f"e = {hexu(k['e'])}\n"
        f"n = {hexu(k['n'])}\n",
    )
    lab.write("task5/flag5.enc", aes_encrypt_flag(token, norm_hex(v1) + ":" + norm_hex(v2)))


def der_item(buf: bytes, off: int):
    tag = buf[off]
    b = buf[off + 1]
    if b < 0x80:
        return tag, 2, b
    nb = b & 0x7F
    return tag, 2 + nb, int.from_bytes(buf[off + 2 : off + 2 + nb], "big")


OPENSSL_CNF = """\
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = placeholder
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ v3_srv ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:{host}
"""


def task6(lab: Lab, rng: DRBG, token: str):
    """Own mini PKI: CA certificate (c1.pem) + server certificate (c0.pem). The PKCS#1 v1.5 block
    obtained by S^e mod n (Step 5 of the lab sheet) is the AES passphrase of the flag."""
    label = "%08x" % rng.getrandbits(32)
    host = f"www.{label}.rsa-lab.example"
    serial = "0x%016x" % (rng.getrandbits(62) | 1)
    tmp = tempfile.mkdtemp(prefix="rsalab-pki-")
    try:
        cnf = os.path.join(tmp, "openssl.cnf")
        with open(cnf, "w") as fh:
            fh.write(OPENSSL_CNF.format(host=host))
        ca_key, ca_crt = os.path.join(tmp, "ca.key"), os.path.join(tmp, "c1.pem")
        srv_key, srv_csr, srv_crt = (os.path.join(tmp, x) for x in ("srv.key", "srv.csr", "c0.pem"))
        run(["openssl", "genrsa", "-out", ca_key, "1024"])
        run([
            "openssl", "req", "-new", "-x509", "-key", ca_key, "-sha256", "-days", "3650", "-config", cnf,
            "-extensions", "v3_ca", "-subj", f"/C=DZ/O=RSA Lab/CN=RSA Lab Root CA {label}", "-out", ca_crt,
        ])
        run(["openssl", "genrsa", "-out", srv_key, "1024"])
        run([
            "openssl", "req", "-new", "-key", srv_key, "-sha256", "-config", cnf,
            "-subj", f"/C=DZ/O=RSA Lab/CN={host}", "-out", srv_csr,
        ])
        run([
            "openssl", "x509", "-req", "-in", srv_csr, "-CA", ca_crt, "-CAkey", ca_key, "-set_serial", serial,
            "-sha256", "-days", "825", "-extfile", cnf, "-extensions", "v3_srv", "-out", srv_crt,
        ])

        # ---- compute the expected verification result (what the student's program must print)
        der = run(["openssl", "x509", "-in", srv_crt, "-outform", "DER"]).stdout
        tag, hl, ln = der_item(der, 0)
        assert tag == 0x30 and hl == 4, "unexpected certificate header (lab sheet assumes offset 4)"
        off = hl
        tag, hl_t, ln_t = der_item(der, off)
        assert tag == 0x30
        tbs = der[off : off + hl_t + ln_t]
        off += hl_t + ln_t
        tag, hl_a, ln_a = der_item(der, off)
        off += hl_a + ln_a
        tag, hl_s, ln_s = der_item(der, off)
        assert tag == 0x03
        sig = der[off + hl_s + 1 : off + hl_s + ln_s]  # skip the "unused bits" byte
        n_ca = int(run(["openssl", "x509", "-in", ca_crt, "-noout", "-modulus"]).stdout.decode().split("=")[1], 16)
        assert n_ca.bit_length() in (1023, 1024) and len(sig) == 128
        digest_info = SHA256_DIGESTINFO + hashlib.sha256(tbs).digest()
        em = b"\x00\x01" + b"\xff" * (128 - 3 - len(digest_info)) + b"\x00" + digest_info
        recovered = pow(int.from_bytes(sig, "big"), 65537, n_ca)
        assert recovered == int.from_bytes(em, "big"), "certificate self-check failed"

        with open(srv_crt) as fh:
            lab.write("task6/c0.pem", fh.read())
        with open(ca_crt) as fh:
            lab.write("task6/c1.pem", fh.read())
        lab.write("task6/flag6.enc", aes_encrypt_flag(token, norm_hex(recovered)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        sys.exit("usage: generate_lab.py params.json")
    with open(sys.argv[1]) as fh:
        params = json.load(fh)
    flags = {k: str(v) for k, v in params["flags"].items()}
    for i in range(1, 7):
        t = flags.get(f"task{i}")
        if not t or not TOKEN_RE.match(t):
            sys.exit(f"flag task{i} is missing or has an invalid format")
    if len(set(flags.values())) != len(flags):
        sys.exit("flags must be different from each other")

    lab = Lab(params["lab_dir"], params.get("owner"))
    seed = "|".join(f"{k}={flags[k]}" for k in sorted(flags)).encode()
    rng = DRBG(seed)

    task1(lab, rng, flags["task1"])
    k234 = keypair_for_tasks_2_3_4(rng)
    task2(lab, k234, flags["task2"])
    task3(lab, k234, flags["task3"])
    task4(lab, k234, flags["task4"])
    task5(lab, rng, flags["task5"])
    task6(lab, rng, flags["task6"])
    lab.fix_owner()
    print("RSA lab material generated for 6 tasks")


if __name__ == "__main__":
    main()
