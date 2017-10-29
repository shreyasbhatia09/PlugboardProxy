///Includes
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define setNULL(x) x = NULL
#define isNULL(x) if (x==NULL)

void readArguments(int argc, char **argv,char *key, char *destAddress, int serverPort, int destPort)
{
    int opt;
    while((opt = getopt(argc, argv, "l:k:")) !=-1)
    {
        switch(opt)
        {
            case 'l':
            {
                serverPort = atoi(optarg);
                break;
            }
            case 'k':
            {
                key = optarg;
                break;
            }
            default:
            {
                fprintf(stderr, "pbproxy [-l port] -k keyfile destination port\n  \
                                -l  Reverse-proxy mode: listen for inbound connections \
                                on <port> and relay them to <destination>:<port>\n \
                                -k  Use the symmetric key contained in <keyfile> \
                                (as a hexadecimal string)");
            }
        }
    }
    destAddress=argv[optind];
    optind++;
    destPort = atoi(argv[optind]);

    return;
}
int main(int argc, char **argv)
{

    char *key;
    char *destAddress;
    setNULL(key);
    setNULL(destAddress);

    int serverPort = 0;
    int opt;
    int destPort;
    rea
}
