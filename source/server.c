//REFERENCE - http://www.binarytides.com/server-client-example-c-sockets-linux/

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
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
    struct sockaddr_in server , client;
    char client_message[2000];
    unsigned char ivec[16];
    char deciphertext[1000];
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8888);

    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

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
        while( (read_size = recv(client_sock , client_message , 2000 , 0)) > 0 )
        {
            if(ivFlag == 0)
            {
                puts("Setting encryption attributes");
                ivFlag = 1;
                strcpy(iv , client_message);
                puts("I received the following  IV from client");
                puts(iv);
                init_ctr(&state, iv);
                AES_set_encrypt_key(key, 128, &aes_key);
                continue;
            }
            else
            {
                puts("Decrypting this");
                puts(client_message);
                //Send the message back to client
                // send response
                AES_ctr128_encrypt(client_message, deciphertext, strlen(client_message),&aes_key, state.ivec, state.ecount, &state.num);
                puts("Deciphered:");
                puts(deciphertext);
                write(client_sock , deciphertext , strlen(deciphertext));
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

    }
    return 0;
}
