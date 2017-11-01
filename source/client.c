//REFERENCE - http://www.geeksforgeeks.org/socket-programming-cc/

// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>



// REFERENCE
// https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
// http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
struct ctr_state {
    unsigned char ivec[16];  /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned int num;
    unsigned char ecount[16];
};

int init_ctr(struct ctr_state *state, const unsigned char iv[8])
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, 16);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

void fdecrypt(unsigned int len, char* cipher, char* text, const unsigned char* enc_key, struct ctr_state* state)
{
    AES_KEY key;
    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];
    int offset=0;
    //Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set decryption key.");
        exit(1);
    }

    //Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
    while(1)
    {
        memcpy(indata, cipher+offset, AES_BLOCK_SIZE);
        //printf("%i\n", state.num);
        AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state->ivec, state->ecount, &state->num);

        memcpy(text+offset, outdata, AES_BLOCK_SIZE);
        offset=offset+AES_BLOCK_SIZE;
        //if (offset > strlen(cipher))##changed
        if (offset > len)
        {
            break;
        }
    }
}

void fencrypt(char* text, char* cipher, const unsigned char* enc_key, struct ctr_state* state)
{
    AES_KEY key;
    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];
    int offset=0;
    //Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set encryption key.");
        exit(1);
    }

    //Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
    while(1)
    {
        printf("while going\n");
        memcpy(indata, text+offset, AES_BLOCK_SIZE);
        AES_ctr128_encrypt(indata, outdata, AES_BLOCK_SIZE, &key, state->ivec, state->ecount, &state->num);

        memcpy(cipher+offset, outdata, AES_BLOCK_SIZE);
        offset=offset+AES_BLOCK_SIZE;
        if (offset > strlen(text))
        {
            break;
        }
    }
}


int startClient(char *server_ip, char *d_port, char *keyfile)
{
    struct sockaddr_in address;
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(d_port));

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, server_ip, &serv_addr.sin_addr)<=0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    while(1)
    {
        // TO DO: read input
        char *hello = "Hello from client";

        unsigned char iv[8];
        struct ctr_state state;

        if (!RAND_bytes(iv, 8))
            /* Handle the error */
            exit(1);

        init_ctr(&state, iv);

        send(sock , hello , strlen(hello) , 0 );
        printf("Message sent\n");
        valread = read( sock , buffer, 1024);
        printf("%s\n",buffer );

    }
    return 0;
}

