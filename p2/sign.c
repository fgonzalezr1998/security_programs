#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>

enum{
    MinArgs = 3,
};

int
args_ok(int argc, char *argv[])
{
    /*
     * Have to finish this function
     */
     
    if(argc < MinArgs)
        return 0;
    printf("%s\n", argv[0]);
    if(strncmp(argv[1], "-v", sizeof(char) * strlen("-v")) == 0){
        printf("%s\n", "long version");
    }else{
        printf("%s\n", "short version");
    }
    return 1;
}


int
main(int argc, char *argv[]) {

    if(! args_ok(argc, argv))
        errx(EXIT_FAILURE, "%s\n", "Usage Error");


    exit(EXIT_SUCCESS);
}
