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
// http://www.binarytides.com/server-client-example-c-sockets-linux/
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


int startClient(char *server_address, char *server_port, char *keyfile)
{
    int sock;
    struct sockaddr_in server;
    char message[1000] , server_reply[2000];

    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(8888) ;

    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }

    puts("Connected\n");

    //keep communicating with server
    while(1)
    {
        printf("Enter message : ");
        scanf("%s" , message);

        //Send some data
        if( send(sock , message , strlen(message) , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }

        //Receive a reply from the server
        if( recv(sock , server_reply , 2000 , 0) < 0)
        {
            puts("recv failed");
            break;
        }

        puts("Server reply :");
        puts(server_reply);
    }

    close(sock);
}

