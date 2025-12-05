#include "../include/dhke.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {

    char msg[1024];

    while (1) {
        printf("Inserisci messaggio (invio per uscire): ");
        if (!fgets(msg, sizeof(msg), stdin)) {
            break; 
        }
        if (strlen(msg)-1 == 0) {
            break;
        }

    	printf("Lunghezza messaggio: %ld\t\t", strlen(msg)-1);
        
        DHKE_Context alice, bob;
        
        dhke_init(&alice, NULL, NULL);
        dhke_init(&bob, alice.prime, alice.generator);
        
        dhke_generate_key_pair(&alice);
        dhke_generate_key_pair(&bob);
        
        dhke_compute_shared_secret(&alice, bob.public_key);
        dhke_compute_shared_secret(&bob, alice.public_key);
        
        uint8_t alice_hmac[DHKE_HMAC_SIZE], bob_hmac[DHKE_HMAC_SIZE];
        dhke_generate_hmac(&alice, bob.public_key, DHKE_KEY_SIZE, bob_hmac);
        dhke_generate_hmac(&bob, alice.public_key, DHKE_KEY_SIZE, alice_hmac);
            if (!dhke_verify_hmac(&alice, bob.public_key, DHKE_KEY_SIZE, bob_hmac)) {
                printf("Alice: MITM detected!\n");
                return 1;
            }
        
            if (!dhke_verify_hmac(&bob, alice.public_key, DHKE_KEY_SIZE, alice_hmac)) {
                printf("Bob: MITM detected!\n");
                return 1;
            }
        
        
            printf("HMACs Ok \n\n");
        
        
        size_t msg_len = strlen(msg) + 1;
        uint8_t ciphertext[msg_len];
        uint8_t decrypted[msg_len];
        uint8_t nonce[DHKE_NONCE_SIZE];  
        uint8_t tag[16];                 
        
        // Encrypt: nonce and tag get set here
        dhke_encrypt(&alice, (const uint8_t *)msg, msg_len, ciphertext, nonce, tag);
        
        
            printf("- Messaggio cifrato: ");
            for (size_t i = 0; i < msg_len; i++) printf("%02X ", ciphertext[i]);
            printf("\n");
        
        // Decrypt with exact nonce and tag
        if (!dhke_decrypt(&bob, ciphertext, msg_len, decrypted, nonce, tag)) {
            printf("Bob: Decryption failed!\n");
            return 1;
        }
    
        printf("- Messaggio decifrato: %s\n", decrypted);
    
        dhke_cleanup(&alice);
        dhke_cleanup(&bob);
    
        printf("\n");
    }

    return 0;
}

