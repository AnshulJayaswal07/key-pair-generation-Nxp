# 🔐 Secure Message Encryption using ECC + AES-GCM on NXP LPC55S69

This project demonstrates secure communication on the **NXP LPC55S69** microcontroller by generating an ECC key pair, performing ECDH key exchange, deriving an AES-128 key using SHA-256, and encrypting/decrypting a message using AES-GCM mode.

## 📁 Project Structure

```

LPC55S69\_SecureComm/
├── benchmark.c             # Main application logic
├── semihost\_hardfault.c    # Semihosting-safe HardFault handler
├── README.md               # Project documentation
└── .gitignore              # (Recommended) Git ignore list

```

## 🚀 Features

- ✅ ECC key generation using `secp256r1`
- ✅ ECDH shared secret derivation
- ✅ Key derivation with SHA-256 → AES-128 key
- ✅ Authenticated encryption using AES-GCM
- ✅ User input handling and secure message display
- ✅ Debug console output via `fsl_debug_console`

## 🔧 Requirements

- **MCU**: NXP LPC55S69
- **IDE**: MCUXpresso IDE (or compatible)
- **SDK**: MCUXpresso SDK for LPC55S69
- **Library**: [mbedTLS](https://github.com/ARMmbed/mbedtls)

## 📦 Dependencies

Make sure the following libraries are included in your project:
- `mbedtls/ecp.h`
- `mbedtls/ctr_drbg.h`
- `mbedtls/entropy.h`
- `mbedtls/sha256.h`
- `mbedtls/gcm.h`

These are used to perform all the cryptographic operations including:
- ECC Key Pair generation
- ECDH key agreement
- AES-GCM authenticated encryption/decryption

## 🛠 Build and Flash Instructions

1. Open the project in **MCUXpresso IDE**.
2. Link your SDK for LPC55S69.
3. Ensure `benchmark.c` is set as the main source file.
4. Optionally include `semihost_hardfault.c` to handle semihosted `printf()` without debugger.
5. Build the project and flash it to your LPC55S69 board.

## 🔍 Example Output

```

\=== ECC + AES-GCM Secure Message Demo ===
\[OK] Random generator seeded.
\[OK] ECC Key Pair Generated.
Public Key X: 00123ABCD...
Public Key Y: 00F456789...
\[OK] Simulated peer public key ready.
\[OK] Shared secret derived.
\[OK] AES-128 key derived: 9F12A...
Enter message (max 127 chars): Hello LPC secure world!
\[OK] Message encrypted.
Encrypted (hex): A123B...
Auth Tag (hex): F45A...
\[OK] Decryption success.
Decrypted Message: Hello LPC secure world!

```

## 🔒 Security Note

This project is meant for **educational and prototyping purposes**. It uses simulated peer key exchange and shared secret derivation for demonstration. In real-world applications, secure key exchange over real channels and proper IV management are essential.

## 📎 References

- [mbedTLS Documentation](https://armmbed.github.io/mbedtls/)
- [NXP MCUXpresso IDE](https://www.nxp.com/mcuxpresso/ide)
- [LPC55S69 Product Page](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/lpc55s6x-secure-arm-cortex-m33-mcus:LPC55S6x)

## 📜 License

This project is licensed under the **BSD 3-Clause License** (see `semihost_hardfault.c` for included licensing).
