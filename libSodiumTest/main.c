//
//  main.c
//  libSodiumTest
//
//  Created by Manohar Kashyap on 5/10/16.
//  Copyright © 2016 Manohar Kashyap. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "sodium.h"

#define MESSAGE (const unsigned char *) "Neil - Daddy loves you loads."
#define MESSAGE_LEN ((uint64_t) strlen(MESSAGE))
#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 0 //((int) strlen(ADDITIONAL_DATA))

#define XCHACHA20_NONCE_LEN  (crypto_core_hchacha20_OUTPUTBYTES)
#define LONG_NONCE_LEN ((crypto_core_hchacha20_INPUTBYTES) + (crypto_aead_chacha20poly1305_NPUBBYTES))
#define PREFIX_LEN (uint64_t) (LONG_NONCE_LEN + crypto_aead_chacha20poly1305_NPUBBYTES)
#define EFFECTIVE_CIPHER_TEXT_LEN (uint64_t) (PREFIX_LEN+ MESSAGE_LEN + crypto_aead_chacha20poly1305_ABYTES)

#define EXPERIMENTAL_BUFS_LEN (uint64_t) (1024)

uint8_t key[] = { 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
    0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
    0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 };


int main(int argc, const char * argv[]) {
    
    uint8_t * kStr = malloc(EXPERIMENTAL_BUFS_LEN);
    uint8_t * cStr = malloc(EXPERIMENTAL_BUFS_LEN);
    uint8_t * dStr = malloc(EXPERIMENTAL_BUFS_LEN);
    uint64_t decrypted_len;
    
    /// Transmitter side variables
    uint64_t ciphertext_len = 0;
    uint8_t * ciphertext = NULL;
    uint8_t derivedKey[XCHACHA20_NONCE_LEN] = {0};
    uint8_t longNonce[LONG_NONCE_LEN] = {0};
    uint8_t txNonce[crypto_aead_chacha20poly1305_NPUBBYTES] = { 0};
    
    /// Receiver side variables
    uint8_t receivedNonce[LONG_NONCE_LEN] = {0};
    uint8_t receiverKey[XCHACHA20_NONCE_LEN] = {0};
    uint8_t rxNonce[crypto_aead_chacha20poly1305_NPUBBYTES] = { 0};
    
    
    /// Transmitter side code : derive a key from long nonce and secret ket, prepend longNonce to ciphertext and transmit
    
    ciphertext =  malloc(EFFECTIVE_CIPHER_TEXT_LEN);
    
    printf("Message: length && message: [%llu && %s] \n", MESSAGE_LEN, MESSAGE);
    
    if (sodium_init() == -1)
    {
        return  -1; //ENC_ERR_BUF_ALLOC_FAIL;
    }
    randombytes_buf(longNonce, sizeof(longNonce));
   crypto_core_hchacha20(derivedKey, longNonce, key, NULL);
   randombytes_buf(txNonce, sizeof(txNonce));
   memcpy(ciphertext, longNonce, sizeof(longNonce));
   memcpy(&ciphertext[sizeof(longNonce)], txNonce, sizeof(txNonce));
   
    strncpy(kStr, derivedKey, sizeof(derivedKey));
    printf("Derived Key: %s\n", kStr);
    
    crypto_aead_chacha20poly1305_encrypt(&ciphertext[PREFIX_LEN], &ciphertext_len,
                                         MESSAGE, MESSAGE_LEN,
                                         ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
                                         NULL, txNonce, derivedKey);
    
    strncpy(cStr, ciphertext, ciphertext_len);
    printf("CiperText prependend with long nonce: [length & text]:: [%d & %s]\n", strlen(cStr), cStr);
    
    
    /// Code to transmit and receive ciphertext
    
    /// Receiver side code: derive a key from extracted long nonce (prefix of xiphertext) and secret ket, decrypt
    
    if (sodium_init() == -1)
    {
        return  -1; //ENC_ERR_BUF_ALLOC_FAIL;
    }
    // extract nonce
    memcpy(receivedNonce, ciphertext, sizeof(receivedNonce));
    memcpy(rxNonce, &ciphertext[sizeof(receivedNonce)], sizeof(rxNonce));
    
    // derive receiver key
    crypto_core_hchacha20(receiverKey, receivedNonce, key, NULL);
    
    //decrypt
    if (crypto_aead_chacha20poly1305_decrypt(dStr, &decrypted_len,
                                             NULL,
                                             &ciphertext[PREFIX_LEN], ciphertext_len,
                                             ADDITIONAL_DATA,
                                             ADDITIONAL_DATA_LEN,
                                             rxNonce, receiverKey) != 0) {
        /* message forged! */
        printf("Someone's FUCKING with your ciphertext \n");
        
    }
    else
    {
        printf("Decrypted Message: %s\n", dStr);
    }

    return 0;
}
