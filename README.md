# Cybersecurity game "RSA Public-Key Encryption and Signature Lab"

Linear game for [CyberRangeCZ Platform](https://docs.platform.cyberrange.cz/), based on the
[SEED Labs](https://seedsecuritylabs.org) lab *RSA Public-Key Encryption and Signature* (Wenliang Du).

This repository contains the **sandbox definition** (`topology.yml`, `variables.yml`, `provisioning/`) and the
**training definition** (`training.json`, imported in the platform), like `library-junior-hacker`.

## Game Levels Summary
- connect to the sandbox and read the briefing
- Task 1: derive an RSA private key with the OpenSSL BIGNUM library
- Task 2: encrypt a message
- Task 3: decrypt a message
- Task 4: sign a message
- Task 5: verify a signature (and a corrupted one)
- Task 6: manually verify an X.509 certificate
- final quiz about the observations

Every sandbox gets **different numbers** (keys, ciphertexts, signatures, certificates) and **different flags**.

## Topology summary
|Host|Image|Flavor|mgmt_user|
|-|-|-|-|
|seed|seed-ubuntu-20.04|m1.medium|ubuntu|
|router|debian-12-x86_64|m1.small|debian|

## Repository content
|Path|Purpose|
|-|-|
|`topology.yml`|topology definition (one `seed` workstation + a router for Internet access)|
|`variables.yml`|APG variables: six random flags generated per sandbox|
|`provisioning/playbook.yml`|Ansible playbook (student account, lab files, command logging)|
|`provisioning/roles/seed`|creates `~/rsa-lab` with the per-sandbox numbers (`generate_lab.py`, `unlock.sh`, `bn_sample.c`)|

## License

This repository uses a dual licensing approach:

* The code (Ansible, scripts, custom code) is licensed under the terms of the MIT License (see `LICENSE`).
* The lab content is derived from the SEED Labs lab sheet *RSA Public-Key Encryption and Signature Lab*,
  Copyright 2018 Wenliang Du, licensed under CC BY-NC-SA 4.0 (non-commercial use, share alike).
  The game format is based on the junior-hacker training (CC BY 4.0). See `ATTRIBUTION.txt`.
# rsa-lab
