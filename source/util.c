#include <stdio.h>
#include <string.h>
#define BUFFERSIZE 1024

int max(int a, int b)
{
    return (a>b)? a:b;
}

int readKey(char *file)
{
    FILE *fileptr;
    char buffer[BUFFERSIZE];
    fileptr = fopen(file,"r");
    if(fileptr ==NULL)
    {
        file = NULL;
        return 0;
    }
    fgets(buffer, BUFFERSIZE, (FILE*)fileptr);
    strcpy(file, buffer);
    fclose(fileptr);
    return 1;
}
