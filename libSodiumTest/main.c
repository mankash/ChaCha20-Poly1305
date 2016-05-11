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

#define MESSAGE (const unsigned char *) "Neil - Daddy loves you loads."
#define MESSAGE_LEN ((int) strlen(MESSAGE))
#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 0 //((int) strlen(ADDITIONAL_DATA))

//unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
unsigned char nonce[] = { 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73};
//unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES];

unsigned char key[] = { 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
    0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
    0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 };
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
    
    //randombytes_buf(key, sizeof key);
    
    strncpy(kStr, key, sizeof(key));
    printf("Key: %s\n", kStr);
    
    //randombytes_buf(nonce, sizeof nonce);
    
    strncpy(nStr, nonce, sizeof(nonce));
    
    printf("Nonce: %s\n", nStr );
    
    crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                         MESSAGE, MESSAGE_LEN,
                                         NULL, ADDITIONAL_DATA_LEN,
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