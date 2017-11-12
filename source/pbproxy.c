/**
    CSE 508: NETWORK SECURITY
    pbproxy.c
    Purpose: PlugBoard Proxy
    Description:
    @author SHREYAS BHATIA
    shreyas.bhatia@stonybrook.edu
*/



///Includes
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include "../includes/server.h"
#include "../includes/client.h"
#include "../includes/util.h"
#define setNULL(x) x = NULL
#define isNULL(x) (x==NULL)


int main(int argc, char **argv)
{

    char *key;
    char *destAddress;
    setNULL(key);
    setNULL(destAddress);
    char *serverPort;
    char *destPort;
    int opt;
    int flag = 1;
    int reverse_proxy = 0;
    while((opt = getopt(argc, argv, "l:k:")) !=-1)
    {
        switch(opt)
        {

            case 'l':
            {
                reverse_proxy   = 1;
                serverPort = (optarg);
                break;
            }
            case 'k':
            {
                key = optarg;
                if(readKey(key)==0)
                   flag = 0;
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
    if(destAddress==NULL || destPort==NULL)
    {
        fprintf(stderr, "No destination address or port");
        exit(0);
    }
    if(isNULL(key)|| flag ==0)
    {
        fprintf(stderr, "No key passed or Key file empty. Exiting.\n");
        exit(0);
    }
    if(reverse_proxy)
    {
        beginServer(serverPort, destAddress, destPort, key);
    }
    else
    {
        startClient(destAddress, destPort, key);
    }
    return 0;
}
