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
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include "../includes/util.h"

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
    char server_deciphered[MAX_SIZE];
    fd_set clientfds;
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        fprintf(stderr,"Could not create socket");
        return 1;
    }
    //puts("Socket created");
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

    //puts("Connected\n");

    unsigned char iv[8];
    struct ctr_state state;

    if (!RAND_bytes(iv, 8))
     {
        puts("IV init failed");
        return 1;
    }
    else
    {
        puts("IV All Set");
    }
    init_ctr(&state, iv);
    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key)<0)
    {
        puts("Could not set encryption key.");
        exit(1);
    }
    if(write(sock, iv, 8)<0)
    {
        perror("Send IV failed");
    }

    while(1)
    {
        FD_ZERO(&clientfds);
        FD_SET(STDIN_FILENO, &clientfds);
        FD_SET(sock, &clientfds);

        select(sock+1, &clientfds, NULL, NULL, NULL);

        if (FD_ISSET(STDIN_FILENO, &clientfds))
        {
            int read_bytes = read(STDIN_FILENO, message, MAX_SIZE);

            AES_ctr128_encrypt(message, ciphertext, read_bytes, &aes_key, state.ivec, state.ecount, &state.num);
            int written_bytes = write(sock, ciphertext, read_bytes);
            usleep(20000);
            if(written_bytes<0)
            {
                fprintf(stderr, "Send to destination failed");
                return 1;
            }
            memset(&ciphertext[0],0,sizeof(char)*MAX_SIZE);
            bzero(ciphertext, MAX_SIZE);
            memset(&message[0],0,sizeof(char)*MAX_SIZE);
            bzero(message, MAX_SIZE);
        }
        else if (FD_ISSET(sock, &clientfds))
        {
            int read_bytes = read(sock, server_reply, MAX_SIZE*2);
            if (read_bytes == 0)
            {
					break;
            }

            AES_ctr128_encrypt(server_reply, server_deciphered, read_bytes, &aes_key, state.ivec, state.ecount, &state.num);
            int written_bytes = write(STDOUT_FILENO, server_deciphered, read_bytes);
            usleep(20000);
            if(written_bytes<0)
            {
                fprintf(stderr,"Write Error");
                return 1;
            }
            memset(&server_reply[0],0,sizeof(char)*MAX_SIZE*2);
            bzero(server_reply, MAX_SIZE*2);
        }
    }
    close(sock);
}

