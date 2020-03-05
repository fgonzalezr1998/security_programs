#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>

enum{
    MinArgs = 3,
};

int
file_isok(char *file_path)
{
    /*
     *returns if file 'file_path' can be readen
     */

     return access(file_path, R_OK) == 0;
}

int
long_version_isok(int argc, char *argv[])
{
    if(argc < MinArgs + 2)
        return 0;
    return file_isok(argv[MinArgs - 1]) && file_isok(argv[MinArgs]) &&
            file_isok(argv[MinArgs + 1]);
}

int
is_long_version(char *arg)
{
    return strncmp(arg, "-v", sizeof(char) * strlen("-v")) == 0;
}

int
args_ok(int argc, char *argv[])
{
    if(argc < MinArgs)
        return 0;

    if(is_long_version(argv[MinArgs - 2]))
        return long_version_isok(argc, argv);
    else
        return file_isok(argv[MinArgs - 2]) && file_isok(argv[MinArgs - 1]);
}

void
check_signature(char *signature_file, char *signed_data_file, char *public_key_file)
{
    //1º decript with publick key
    ;
}

int
main(int argc, char *argv[]) {

    if(! args_ok(argc, argv))
        errx(EXIT_FAILURE, "%s\n", "Usage Error");

    if(is_long_version(argv[MinArgs - 2]))
        check_signature(argv[MinArgs - 1], argv[MinArgs], argv[MinArgs + 1]);

    exit(EXIT_SUCCESS);
}
