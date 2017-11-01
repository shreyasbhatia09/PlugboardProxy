///Includes
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "../includes/server.h"
#include "../includes/client.h"

#define setNULL(x) x = NULL
#define isNULL(x) if (x==NULL)



int main(int argc, char **argv)
{

    char *key;
    char *destAddress;
    setNULL(key);
    setNULL(destAddress);
    char * serverPort;
    char * destPort;
    int opt;
    int reverse_proxy =0;
    while((opt = getopt(argc, argv, "l:k:")) !=-1)
    {
        switch(opt)
        {

            case 'l':
            {
                reverse_proxy = 1;
                serverPort = (optarg);
                break;
            }
            case 'k':
            {
                key = optarg;
                break;
            }
            default:
            {
                fprintf(stderr, "Invalid arguments.\n \
                                pbproxy [-l port] -k keyfile destination port\n  \
                                -l  Reverse-proxy mode: listen for inbound connections \
                                on <port> and relay them to <destination>:<port>\n \
                                -k  Use the symmetric key contained in <keyfile> \
                                (as a hexadecimal string)");
            }
        }
    }
    destAddress=argv[optind];
    optind++;
    destPort = (argv[optind]);
    isNULL(key)
    {
        fprintf(stderr, "No key passed. Exiting.");
        exit(0);
    }
    if(reverse_proxy)
    {
        beginServer(serverPort, destAddress, destPort, key);
    }
    else
    {
        fprintf(stdout, "Starting in client mode.\n");
        startClient(destAddress, destPort, key);
    }
    return 0;
}
