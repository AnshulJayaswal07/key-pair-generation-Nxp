#include "fsl_debug_console.h"
#include "board.h"

#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"

#include <string.h>
#include <stdio.h>

#define KEY_SIZE 32  // 256 bits
#define AES_KEY_SIZE 16 // AES-128
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16
#define MAX_INPUT_LEN 128

uint8_t user_input[MAX_INPUT_LEN];
uint8_t encrypted_output[MAX_INPUT_LEN + AES_TAG_SIZE];
uint8_t decrypted_output[MAX_INPUT_LEN];

uint8_t iv[AES_IV_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};

void to_hex(const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        PRINTF("%02X", in[i]);
    }
    PRINTF("\r\n");
}

void print_mbedtls_error(int ret, const char *msg) {
    char err_buf[100];
    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    PRINTF("%s: -0x%04X (%s)\r\n", msg, -ret, err_buf);
}

int main(void) {
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    PRINTF("=== ECC + AES-GCM Secure Message Demo ===\r\n");

    int ret;
    size_t olen = 0;

    // === 1. Setup RNG
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecc_aes";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        print_mbedtls_error(ret, "CTR_DRBG seed failed");
        return 1;
    } else {
        PRINTF("[OK] Random generator seeded.\r\n");
    }

    // === 2. Generate ECC Key Pair
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &keypair,
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        print_mbedtls_error(ret, "ECC key generation failed");
        return 1;
    } else {
        PRINTF("[OK] ECC Key Pair Generated.\r\n");
    }

    char buf[1000];
    ret = mbedtls_mpi_write_string(&keypair.Q.X, 16, buf, sizeof(buf), &olen);
    if (ret == 0) PRINTF("Public Key X: %s\r\n", buf);
    else print_mbedtls_error(ret, "Write Q.X failed");

    ret = mbedtls_mpi_write_string(&keypair.Q.Y, 16, buf, sizeof(buf), &olen);
    if (ret == 0) PRINTF("Public Key Y: %s\r\n", buf);
    else print_mbedtls_error(ret, "Write Q.Y failed");

    // === 3. Simulate Peer Public Key (self ECDH)
    mbedtls_ecp_point peer_pub;
    mbedtls_ecp_point_init(&peer_pub);
    ret = mbedtls_ecp_copy(&peer_pub, &keypair.Q);
    if (ret != 0) {
        print_mbedtls_error(ret, "Peer public key copy failed");
        return 1;
    } else {
        PRINTF("[OK] Simulated peer public key ready.\r\n");
    }

    // === 4. ECDH Key Exchange
    mbedtls_mpi shared_secret;
    mbedtls_mpi_init(&shared_secret);
    ret = mbedtls_ecdh_compute_shared(&keypair.grp, &shared_secret,
                                      &peer_pub, &keypair.d,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        print_mbedtls_error(ret, "ECDH shared secret failed");
        return 1;
    } else {
        PRINTF("[OK] Shared secret derived.\r\n");
    }

    uint8_t raw_secret[KEY_SIZE];
    ret = mbedtls_mpi_write_binary(&shared_secret, raw_secret, KEY_SIZE);
    if (ret == 0) {
        PRINTF("Raw shared secret (hex): ");
        to_hex(raw_secret, KEY_SIZE);
    } else {
        print_mbedtls_error(ret, "Write shared secret failed");
    }

    // === 5. Derive AES Key using SHA256 → truncate to 128-bit
    uint8_t hash[32];
    uint8_t aes_key[AES_KEY_SIZE];
    mbedtls_sha256(raw_secret, KEY_SIZE, hash, 0);
    memcpy(aes_key, hash, AES_KEY_SIZE);
    PRINTF("[OK] AES-128 key derived: ");
    to_hex(aes_key, AES_KEY_SIZE);

    // === 6. Take user input
    PRINTF("Enter message (max %d chars): ", MAX_INPUT_LEN - 1);
    size_t msg_len = 0;
    while (msg_len < MAX_INPUT_LEN - 1) {
        int ch = GETCHAR();
        if (ch == '\r' || ch == '\n') break;
        user_input[msg_len++] = (uint8_t)ch;
        PUTCHAR(ch); // echo
    }
    user_input[msg_len] = '\0';
    PRINTF("\r\n[OK] Message received: %s\r\n", user_input);

    // === 7. AES-GCM Encryption
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        print_mbedtls_error(ret, "AES-GCM setkey failed");
        return 1;
    }

    uint8_t tag[AES_TAG_SIZE];
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, msg_len,
                                    iv, AES_IV_SIZE, NULL, 0,
                                    user_input, encrypted_output, AES_TAG_SIZE, tag);
    if (ret != 0) {
        print_mbedtls_error(ret, "AES-GCM encryption failed");
        return 1;
    } else {
        PRINTF("[OK] Message encrypted.\r\nEncrypted (hex): ");
        to_hex(encrypted_output, msg_len);
        PRINTF("Auth Tag (hex): ");
        to_hex(tag, AES_TAG_SIZE);
    }

    // === 8. AES-GCM Decryption
    ret = mbedtls_gcm_auth_decrypt(&gcm, msg_len, iv, AES_IV_SIZE,
                                   NULL, 0, tag, AES_TAG_SIZE,
                                   encrypted_output, decrypted_output);
    if (ret == 0) {
        decrypted_output[msg_len] = '\0';
        PRINTF("[OK] Decryption success.\r\nDecrypted Message: %s\r\n", decrypted_output);
    } else {
        print_mbedtls_error(ret, "Decryption failed (Tag mismatch?)");
    }

    // === Cleanup
    mbedtls_gcm_free(&gcm);
    mbedtls_mpi_free(&shared_secret);
    mbedtls_ecp_point_free(&peer_pub);
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    while (1) {}
}

