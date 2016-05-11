//
//  main.c
//  libSodiumTest
//
//  Created by Manohar Kashyap on 5/10/16.
//  Copyright © 2016 Manohar Kashyap. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "sodium.h"

#define MESSAGE (const unsigned char *) "Neil - I hope I get very rich and keep you comfortable forever"
#define MESSAGE_LEN ((int) strlen(MESSAGE))
#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN ((int) strlen(ADDITIONAL_DATA))

unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES];
unsigned char ciphertext[MESSAGE_LEN + crypto_aead_chacha20poly1305_ABYTES];
unsigned long long ciphertext_len;
unsigned char decrypted[MESSAGE_LEN];



int main(int argc, const char * argv[]) {
    // insert code here...
    
    unsigned char * kStr = malloc(100);
    unsigned char * nStr = malloc(1024);
    unsigned char * cStr = malloc(1024);
    unsigned char * dStr = malloc(1024);
    unsigned long long decrypted_len;
    
    printf("Message: %s \n", MESSAGE);
    
    randombytes_buf(key, sizeof key);
    
    strncpy(kStr, key, sizeof(key));
    printf("Key: %s\n", kStr);
    
    randombytes_buf(nonce, sizeof nonce);
    
    strncpy(nStr, nonce, sizeof(nonce));
    
    printf("Nonce: %s\n", nStr );
    
    crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                         MESSAGE, MESSAGE_LEN,
                                         ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
                                         NULL, nonce, key);
    
    strncpy(cStr, ciphertext, ciphertext_len);
    printf("CiperText and lengths is: %d, %s\n", strlen(cStr), cStr);
    


    if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
                                             NULL,
                                             ciphertext, ciphertext_len,
                                             ADDITIONAL_DATA,
                                             ADDITIONAL_DATA_LEN,
                                             nonce, key) != 0) {
        /* message forged! */
        printf("Someone's FUCKING with your ciphertext \n");
        
    }
    else
    {
        strncpy(dStr, decrypted, decrypted_len );
        printf("Decrypted Message: %s\n", dStr);
    }
    
    
    
    return 0;
}