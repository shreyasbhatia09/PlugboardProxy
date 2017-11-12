/**
    CSE 508: NETWORK SECURITY
    server.c
    Purpose: PlugBoard Proxy
    Description:
    @author SHREYAS BHATIA
    shreyas.bhatia@stonybrook.edu
*/

// REFERENCES
// https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
// http://www.binarytides.com/server-client-example-c-sockets-linux/

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <sys/select.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include "../includes/util.h"

#define MAX_SIZE 4096

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

void setFailure(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

struct ctr_state {
    unsigned char ivec[16];  /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned int num;
    unsigned char ecount[16];
};

int init_ctr_s(struct ctr_state *state, const unsigned char iv[8])
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, 16);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
    return 0;
}

int beginServer(char *port, char *dest_address, char *d_port, char *key)
{
    int socket_desc , client_sock , c ;
    struct sockaddr_in server, client;
    struct sockaddr_in dest_server;
    char client_message[MAX_SIZE*2];
    char deciphertext[MAX_SIZE*2];
    char destination_server_reply[MAX_SIZE*2];
    char encrypted_destination_server_reply[MAX_SIZE*2];
    fd_set serverfds;


    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);

    if (socket_desc == -1 )
    {
        fprintf(stderr,"Could not create socket");
        return 1;
    }

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(atoi(port));

    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }

    //Listen
    listen(socket_desc , 3);
    puts("Waiting for incoming connections...");
    AES_KEY aes_key;
    if (AES_set_encrypt_key((const unsigned char*)key, 128, &aes_key)<0)
    {
        fprintf(stderr,"Could not set encryption key.");
        exit(1);
    }
    //Accept and incoming connection
    c = sizeof(struct sockaddr_in);
    while(1)
    {
        memset(&client_message[0],0,sizeof(char)*MAX_SIZE*2);
        bzero(client_message, sizeof(char)*MAX_SIZE*2);
        memset(&deciphertext[0],0,sizeof(char)*MAX_SIZE*2);
        bzero(deciphertext, sizeof(char)*MAX_SIZE*2);
        memset(&destination_server_reply[0],0,sizeof(char)*MAX_SIZE*2);
        bzero(destination_server_reply, sizeof(char)*MAX_SIZE*2);
        memset(&encrypted_destination_server_reply[0],0,sizeof(char)*MAX_SIZE*2);
        bzero(encrypted_destination_server_reply, sizeof(char)*MAX_SIZE*2);
        int destination_socket_desc ;
        int ivFlag = 0;
        char iv[MAX_SIZE];
        struct ctr_state state_server;
        //accept connection from an incoming client
        if (destination_socket_desc == -1 )
        {
            fprintf(stderr,"Could not create Destination socket");
            return 1;
        }
        destination_socket_desc = socket(AF_INET , SOCK_STREAM , 0);
        struct hostent *temp1 = gethostbyname(dest_address);
        bcopy((char *)temp1->h_addr, (char *)&dest_server.sin_addr.s_addr, temp1->h_length);
        dest_server.sin_family = AF_INET;
        dest_server.sin_port = htons(atoi(d_port));
        client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
        if (client_sock < 0)
        {
            perror("accept failed");
            return 1;
        }

        if(connect(destination_socket_desc , (struct sockaddr *)&dest_server , sizeof(dest_server)) < 0)
        {
            perror("connect failed. Error");
            return 1;
        }

        puts("Connected\n");
        //Receive a message from client
        while(1)
        {
            FD_ZERO(&serverfds);
            FD_SET(client_sock, &serverfds);
            FD_SET(destination_socket_desc, &serverfds);
            if(select(max(client_sock, destination_socket_desc)+1,&serverfds,NULL, NULL, NULL) <0)
            {
                perror("Select error");
                break;
            }
            if (FD_ISSET(client_sock, &serverfds))
            {
                memset(&client_message[0],0,sizeof(char)*MAX_SIZE*2);
                bzero(client_message, sizeof(char)*MAX_SIZE*2);
                memset(&deciphertext[0],0,sizeof(char)*MAX_SIZE*2);
                bzero(deciphertext, sizeof(char)*MAX_SIZE*2);

                int read_bytes = read(client_sock, client_message, MAX_SIZE);
				usleep(20000);
                if (read_bytes <= 0) {
                        break;
                }

                if(ivFlag == 0)
                {
                    memset(&iv[0],0,sizeof(char)*MAX_SIZE);
                    ivFlag = 1;
                    strcpy(iv , client_message);
                    init_ctr_s(&state_server, (const unsigned char *)iv);
                    if(AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key)<0)
                    {
                            fprintf(stderr, "Unable to set encryption key");
                            return 1;
                    }
                }
                else
                {
                    AES_ctr128_encrypt((const unsigned char *)client_message, (unsigned char *)deciphertext, read_bytes,&aes_key, state_server.ivec, state_server.ecount, &state_server.num);
                    int written_bytes = write(destination_socket_desc, deciphertext, read_bytes);
                    usleep(20000);
                    if(written_bytes<0)
                    {
                        fprintf(stderr,",Send to destination failed");
                        return 1;
                    }
                }
                memset(&client_message[0],0,sizeof(char)*MAX_SIZE*2);
                bzero(client_message, sizeof(char)*MAX_SIZE*2);
                memset(&deciphertext[0],0,sizeof(char)*MAX_SIZE*2);
                bzero(deciphertext, sizeof(char)*MAX_SIZE*2);
            }
            else if (FD_ISSET(destination_socket_desc, &serverfds))
            {
                memset(&encrypted_destination_server_reply[0],0,sizeof(char)*MAX_SIZE*2);
                bzero(encrypted_destination_server_reply, sizeof(char)*MAX_SIZE*2);
                memset(&destination_server_reply[0],0,sizeof(char)*MAX_SIZE*2);
                bzero(destination_server_reply, sizeof(char)*MAX_SIZE*2);
                //Receive a reply from the server
                int read_bytes = read(destination_socket_desc, destination_server_reply, MAX_SIZE);
				usleep(20000);
                if (read_bytes <= 0)
                {
                        break;
                }
                AES_ctr128_encrypt((const unsigned char *)destination_server_reply, (unsigned char *)encrypted_destination_server_reply, read_bytes,&aes_key, state_server.ivec, state_server.ecount, &state_server.num);

                int written_bytes = write(client_sock, encrypted_destination_server_reply, read_bytes);
                usleep(20000);
                if(written_bytes<0)
                {
                    fprintf(stderr,"Write Error");
                    return 1;
                }
                memset(&encrypted_destination_server_reply[0],0,sizeof(char)*MAX_SIZE*2);
                bzero(encrypted_destination_server_reply, sizeof(char)*MAX_SIZE*2);
                memset(&destination_server_reply[0],0,sizeof(char)*MAX_SIZE*2);
                bzero(destination_server_reply, sizeof(char)*MAX_SIZE*2);
            }
        }
        puts("Client disconnected");
     }
    close(socket_desc);
    return 0;
}
