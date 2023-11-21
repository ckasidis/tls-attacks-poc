# TLS Attacks

This project is a part of NTU CZ4010 Applied Cryptography module.

## How to run

1. Make sure you have Go installed on your system
2. Run the following command in the terminal to demonstrate the TLS attacks

```
go run main.go
```

## POODLE Attack (CVE-2014-3566)

### Files

- `poodle/aes_cbc.go` = Functions related to SSL 3.0 AES CBC Implementation
- `poodle/attack.go` = Functions related to POODLE attack on SSL 3.0 AES CBC Implementation

## Acknowledgements

The concepts applied in this project are referenced from these repositories:

- https://github.com/mpgn/poodle-PoC
