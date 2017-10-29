//REFERENCE - http://www.geeksforgeeks.org/socket-programming-cc/

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

void setFailure(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void beginServer(char *port, char *server_ip, char *d_port, char *keyfile)
{
    int sockfd, new_socket, valread, sockopt;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello = "Hello from server";

    /*
    AF_INET -> IPV4
    SOCK_STREAM -> TCP
    0 -> IP protocol
    */
    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd == 0)
    {
        setFailure("Socket Failed");
    }
    sockopt = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    if(sockopt == 0)
    {
        setFailure("Sockopt Failed");
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( port );

    // Forcefully attaching socket to the port
    int bind = bind(server_fd, (struct sockaddr *)&address, sizeof(address))
    if (bind<0)
        setFailure("Bind Failure");
    if (listen(server_fd, 3) < 0)
    {
        setFailure("Listen Failure");
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                       (socklen_t*)&addrlen))<0)
    {
        setFailure("accept");
    }
    valread = read( new_socket , buffer, 1024);
    printf("Server:%s\n",buffer );
    send(new_socket , hello , strlen(hello) , 0 );
    printf("Hello message sent\n");
    return 0;
}
