/**
    CSE 508: NETWORK SECURITY
    client.c
    Purpose: PlugBoard Proxy
    Description:
    @author SHREYAS BHATIA
    shreyas.bhatia@stonybrook.edu
*/

// REFERENCES
// https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
// http://www.binarytides.com/server-client-example-c-sockets-linux/

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


#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

#define MAX_SIZE 4096

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


int startClient(char *server_address, char *server_port, char *key)
{
    int sock;
    struct sockaddr_in server;
    char message[MAX_SIZE] , server_reply[MAX_SIZE*2];
    char ciphertext[MAX_SIZE];
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    //server.sin_addr.s_addr = inet_addr("127.0.0.1");
    struct hostent *temp = gethostbyname(server_address);
    bcopy((char *)temp->h_addr, (char *)&server.sin_addr.s_addr, temp->h_length);
    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(server_port));

    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }

    puts("Connected\n");

    unsigned char iv[8];
    struct ctr_state state;

    if (!RAND_bytes(iv, 8))
     {
        puts("IV init failed");
        return 1;
    }
    else
    {
        puts("Meet IV");
        puts(iv);
    }
    init_ctr(&state, iv);
    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key)<0)
    {
        puts("Could not set encryption key.");
        exit(1);
    }
    if( send(sock , iv, 8 , 0) < 0)
    {
        puts("Send IV failed");
        return 1;
    }
    while(1)
    {
        memset(&server_reply[0],0,sizeof(char)*MAX_SIZE*2);
        memset(&message[0],0,sizeof(char)*MAX_SIZE);
        memset(&ciphertext[0],0,sizeof(char)*MAX_SIZE);
        bzero(message, MAX_SIZE);
        bzero(server_reply, MAX_SIZE*2);
        bzero(ciphertext, MAX_SIZE);

        printf("Enter message : ");
        scanf("%s" , message);
        AES_ctr128_encrypt(message, ciphertext, strlen(message), &aes_key, state.ivec, state.ecount, &state.num);
        //Send some data
        //if( send(sock , message , strlen(message) , 0) < 0)
        if( send(sock , ciphertext, strlen(ciphertext) , 0) < 0)
        {
            puts("Send failed");
            return 1;
        }

        //Receive a reply from the server
        if( recv(sock , server_reply , MAX_SIZE*2 , 0) < 0)
        {
            puts("recv failed");
            break;
        }

        puts("Server reply :");
        puts(server_reply);
    }

    close(sock);
}

