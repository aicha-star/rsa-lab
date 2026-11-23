RSA Public-Key Encryption and Signature Lab  -  your personal workspace
=======================================================================

Everything in this folder was generated for YOUR sandbox only: the numbers of your classmates
are different from yours, so do not compare or copy results - they will not work for you.

  task1/ ... task6/   the data of each task (params.txt = numbers in hexadecimal, c0.pem, c1.pem ...)
  bn_sample.c         example program that uses the OpenSSL BIGNUM library
  unlock.sh           reveals the flag of Tasks 2, 4, 5 and 6 once you give it YOUR computed result

Compile a C program that uses BIGNUM:     gcc myprog.c -o myprog -lcrypto
ASCII text -> hex:                         python3 -c 'print("A top secret!".encode("utf-8").hex())'
hex -> ASCII text:                         python3 -c 'print(bytes.fromhex("4120746f702073656372657421").decode("utf-8"))'

Flag of every task = a 10 character string made of letters and digits (case sensitive).
Submit it on the CyberRangeCZ portal, in the level of the task.

   Task 1, Task 3 : the flag is the plaintext you get by decrypting the ciphertext C.
   Task 2, 4, 5, 6: run  ./unlock.sh <task number> <your result(s)>   (see ./unlock.sh without arguments)
