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
#include <unistd.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#define MAX_SIZE 4096
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
}



int beginServer(char *port, char *dest_address, char *d_port, char *key)
{

    int socket_desc , client_sock , c , read_size;
    int destination_socket_desc , dest_sock ;
    struct sockaddr_in server, client;
    struct sockaddr_in dest_server, dest;
    char client_message[MAX_SIZE*2];
    char destination_message[MAX_SIZE*2];
    unsigned char ivec[16];
    char deciphertext[MAX_SIZE*2];
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    destination_socket_desc = socket(AF_INET , SOCK_STREAM , 0);

    if (socket_desc == -1 || destination_socket_desc)
    {
        printf("Could not create socket");
    }

    puts("Socket created");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(atoi(port));

    struct hostent *temp1 = gethostbyname(dest_address);
    bcopy((char *)temp1->h_addr, (char *)&dest_server.sin_addr.s_addr, temp1->h_length);
    dest_server.sin_family = AF_INET;
    dest_server.sin_port = htons(atoi(d_port));

        //Connect to remote server
    if (connect(destination_socket_desc , (struct sockaddr *)&dest_server , sizeof(dest_server)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
    puts("Connected to destination");
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("binding to port done");

    //Listen
    listen(socket_desc , 3);

    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key)<0)
    {
        puts("Could not set encryption key.");
        exit(1);
    }

    //Accept and incoming connection

    c = sizeof(struct sockaddr_in);
    while(1)
    {

        int ivFlag = 0;
        unsigned char iv[8];
        struct ctr_state state;
        puts("Waiting for incoming connections...");
        //accept connection from an incoming client
        client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
        if (client_sock < 0)
        {
            perror("accept failed");
            return 1;
        }
        puts("Connection accepted");

        //Receive a message from client
        while( 1)
        {
            memset(&client_message[0],0,sizeof(char)*MAX_SIZE*2);
            memset(&deciphertext[0],0,sizeof(char)*MAX_SIZE*2);

            if((read_size = recv(client_sock , client_message , MAX_SIZE*2 , 0)) <= 0 )
                break;

            if(ivFlag == 0)
            {
                puts("Setting encryption attributes");
                ivFlag = 1;
                strcpy(iv , client_message);
                init_ctr(&state, iv);
                AES_set_encrypt_key(key, 128, &aes_key);
                continue;
            }
            else
            {
                //puts("Decrypting this");
                //puts(client_message);
                //Send the message back to client
                // send response
                AES_ctr128_encrypt(client_message, deciphertext, strlen(client_message),&aes_key, state.ivec, state.ecount, &state.num);
                //puts("Deciphered:");
                //puts(deciphertext);
                //write(client_sock , deciphertext , strlen(deciphertext));
                //write(client_sock , deciphertext , strlen(deciphertext));
                puts("sending this to destination");
                puts(deciphertext);
                if( send(destination_socket_desc , deciphertext, strlen(deciphertext) , 0) < 0)
                {
                    puts("Send to destination failed");
                    return 1;
                }

            }
        }
        // open socket
        // send it to service
        if(read_size == 0)
        {
            puts("Client disconnected");
            fflush(stdout);
        }
        else if(read_size == -1)
        {
            perror("recv failed");
        }
        close(client_sock);


    }
    close(socket_desc);
    return 0;
}
