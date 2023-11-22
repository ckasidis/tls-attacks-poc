# TLS Attacks on AES CBC implementation of SSL 3.0 / TLS 1.0 (BEAST, POODLE)

This project is a part of NTU CZ4010 Applied Cryptography module.

## How to run

1. Make sure you have Go installed on your system
2. Run the following command in the terminal to demonstrate the BEAST and POODLE attacks

```
go run main.go
```

## Files

- `beast/attack.go` = Functions to execute BEAST attack on AES CBC Implementation
- `poodle/attack.go` = Functions to execute POODLE attack on AES CBC Implementation
- `aescbc/implementation.go` = Functions related to SSL 3.0 / TLS 1.0 AES CBC Implementation

## Acknowledgements

The concepts applied in this project are referenced from these repositories:

- https://github.com/mpgn/poodle-PoC
- https://github.com/mpgn/BEAST-PoC
