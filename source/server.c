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

int max(int a, int b)
{
    return (a>b)? a:b;
}

int beginServer(char *port, char *dest_address, char *d_port, char *key)
{

    int socket_desc , client_sock , c , read_size;

    struct sockaddr_in server, client;
    struct sockaddr_in dest_server, dest;
    char client_message[MAX_SIZE*2];
    char destination_message[MAX_SIZE*2];
    unsigned char ivec[16];
    char deciphertext[MAX_SIZE*2];
    char destination_server_reply[MAX_SIZE*2];
    fd_set serverfds;

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);

    if (socket_desc == -1 )
    {
        printf("Could not create socket");
        return 1;
    }
    puts("Socket created");

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
        int destination_socket_desc , dest_sock ;
        int ivFlag = 0;
        int cntFlag = 0;
        unsigned char iv[8];
        struct ctr_state state;
        puts("Waiting for incoming connections...");
        //accept connection from an incoming client
        if (destination_socket_desc == -1 )
        {
            printf("Could not create Destination socket");
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
        puts("Connection accepted");

        if(connect(destination_socket_desc , (struct sockaddr *)&dest_server , sizeof(dest_server)) < 0)
        {
            perror("connect failed. Error");
            return 1;
        }

        //Receive a message from client
        while(1)
        {
            FD_ZERO(&serverfds);
            FD_SET(client_sock, &serverfds);
            FD_SET(destination_socket_desc, &serverfds);
            if(select(max(client_sock, destination_socket_desc)+1,&serverfds,NULL, NULL, NULL) <0)
            {
                perror("Select error");
            }
            if (FD_ISSET(client_sock, &serverfds))
            {
//                if((read_size = recv(client_sock , client_message , MAX_SIZE*2 , 0)) <= 0 )
//                    break;
                int read_bytes = read(client_sock, client_message, MAX_SIZE);
                if (read_bytes == 0) {
                        break;
                }
                if(ivFlag == 0)
                {
                    puts("Setting encryption attributes");
                    ivFlag = 1;
                    strcpy(iv , client_message);
                    init_ctr_s(&state, iv);
                    AES_set_encrypt_key(key, 128, &aes_key);
                        //Connect to remote server

                    puts("Connected to destination");
                }
                else
                {
                    //puts("Decrypting this");
                    //puts(client_message);
                    //Send the message back to client
                    // send response
                    AES_ctr128_encrypt(client_message, deciphertext, read_bytes,&aes_key, state.ivec, state.ecount, &state.num);
                    //puts("sending this to destination");
                    //puts(deciphertext);
                    //if( send(destination_socket_desc , deciphertext, strlen(deciphertext) , 0) < 0)

                    //if( send(destination_socket_desc , client_message, strlen(deciphertext) , 0) < 0)
                    int written_bytes = write(destination_socket_desc, deciphertext, read_bytes);
                    //int written_bytes = write(destination_socket_desc, client_message, read_bytes);
                    usleep(20000);
                    if(written_bytes<0)
                    {
                        puts("Send to destination failed");
                        return 1;
                    }
                }
                memset(&client_message[0],0,sizeof(char)*MAX_SIZE*2);
                memset(&deciphertext[0],0,sizeof(char)*MAX_SIZE*2);
            }
            else if (FD_ISSET(destination_socket_desc, &serverfds))
            {
                //Receive a reply from the server
//                if( recv(destination_socket_desc , destination_server_reply , MAX_SIZE*2 , 0) < 0)
//                {
//                    puts("Destination recv failed");
//                    break;
//                }
                    int read_bytes = read(destination_socket_desc, destination_server_reply, MAX_SIZE);
                    if (read_bytes == 0) {
                            break;
                    }
//                if( send(client_sock , destination_server_reply, strlen(destination_server_reply) , 0) < 0)
//                //if( send(sock , message, strlen(ciphertext) , 0) < 0)
//                {
//                    puts("Send failed");
//                    return 1;
//                }
                int written_bytes = write(client_sock, destination_server_reply, read_bytes);
                usleep(20000);
                if(written_bytes<0)
                {
                    //puts("Send to destination failed");
                    fprintf(stderr,"Error write :");
                    return 1;
                }
                memset(&destination_server_reply[0],0,sizeof(char)*MAX_SIZE*2);
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
