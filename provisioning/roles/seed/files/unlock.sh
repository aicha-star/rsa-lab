#!/bin/bash
# RSA Lab helper - unlocks the flag of Tasks 2, 4, 5 and 6.
#
# The flag of these tasks is stored encrypted (AES-256). The passphrase is the RESULT of the
# computation requested by the lab. If your numbers are right, the flag is revealed.
#
#   ./unlock.sh 2 <C>            C  = ciphertext of "A top secret!"          (Task 2)
#   ./unlock.sh 4 <S1> <S2>      S1 = signature of M1, S2 = signature of M2   (Task 4)
#   ./unlock.sh 5 <V1> <V2>      V1 = S^e mod n, V2 = (corrupted S)^e mod n   (Task 5)
#   ./unlock.sh 6 <EM>           EM = S^e mod n computed on the certificate   (Task 6)
#
# Values are hexadecimal; upper/lower case, a 0x prefix, spaces, colons and leading zeros are
# ignored. (Tasks 1 and 3 have no unlock: the flag is the decrypted plaintext.)

cd "$(dirname "$(readlink -f "$0")")" || exit 1

usage() {
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
    exit 2
}

norm() {
    python3 - "$1" <<'EOF'
import re, sys
s = re.sub(r"^\s*0[xX]", "", sys.argv[1])
s = re.sub(r"[^0-9a-fA-F]", "", s)
if not s:
    sys.exit(1)
print(format(int(s, 16), "X"))
EOF
}

task="${1:-}"
case "$task" in
    2|6) need=1 ;;
    4|5) need=2 ;;
    1|3) echo "Task $task has no unlock: the flag is the plaintext obtained by RSA decryption."; exit 2 ;;
    *)   usage ;;
esac

if [ "$#" -ne $((need + 1)) ]; then
    echo "Task $task needs $need hexadecimal value(s)."
    usage
fi

key=""
shift
for v in "$@"; do
    n=$(norm "$v") || { echo "[-] '$v' is not a hexadecimal number."; exit 2; }
    key="${key:+$key:}$n"
done

enc="task${task}/flag${task}.enc"
[ -f "$enc" ] || { echo "[-] $enc not found."; exit 1; }

out=$(openssl enc -d -aes-256-cbc -pbkdf2 -a -in "$enc" -pass "pass:$key" 2>/dev/null)
if [ $? -eq 0 ] && [[ "$out" =~ ^[A-Za-z0-9]{6,32}$ ]]; then
    echo "[+] Correct! The flag of Task $task is: $out"
else
    echo "[-] Wrong value(s): nothing was unlocked. Re-check your computation (and the order of the values)."
    exit 1
fi
