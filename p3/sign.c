#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

enum{
    MinArgs = 3,
    MaxFilenameBytes = 40,
    BlockSize = 64,
};

const unsigned char IDSHA12[] = {0x30, 0x51, 0x30, 0x0d,
                                    0x06, 0x09, 0x60, 0x86,
                                    0x48, 0x01, 0x65, 0x03,
                                    0x04, 0x02, 0x03, 0x05,
                                    0x00, 0x04, 0x40};

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
print_hexa(unsigned char *str, int len)
{
	/*
	 *print 'str' using hexadecimal format
	 */
	for(int i = 0; i < len; i++)
		printf("%02x", str[i]);

	printf("\n");
}

void
get_file_name(char *data_file, char *file_name)
{
    char *fn;
    fn = strrchr(data_file, '/');
    if(fn == NULL)
        strncpy(file_name, data_file, sizeof(char) * MaxFilenameBytes);
    else{
        fn++;
        strncpy(file_name, fn, sizeof(char) * MaxFilenameBytes);
    }
}

void
check_signature(char *signature_file, char *signed_data_file, char *public_key_file)
{
    //1º decript data with publick key using RSA
    //-see data len
    //int data_fd = open(signed_data_file, O_RDONLY);
}

void
get_sha512(char *data_file, char *file_name, unsigned char *hash)
{
    SHA512_CTX c;
    int fd, bytes;
    unsigned char buf[BlockSize];
    //open 'data_file'
    fd = open(data_file, O_RDONLY);
    if(fd < 0)
        errx(EXIT_FAILURE, "%s[%s]\n", "Error openning ", file_name);
    //Alimento la hash con los datosd el fichero
    if(SHA512_Init(&c) < 0)
        exit(EXIT_FAILURE);
    do{
        bytes = read(fd, buf, BlockSize);
        if(bytes > 0)
            SHA512_Update(&c, buf, bytes);
    }while(bytes > 0);
    //Alimento la hash con el nombre del fichero
    for(int i = 0; i < strlen(file_name); i++){
        buf[i] = (unsigned char)(file_name[i]);
    }
    SHA512_Update(&c, buf, strlen(file_name));

    SHA512_Final(hash, &c);
}

void
sign(char *data_file, char * pivkey_file)
{
    char file_name[MaxFilenameBytes];
    unsigned char hash[SHA512_DIGEST_LENGTH];
    get_file_name(data_file, file_name);
    //HASTA AQUI ESTA BIEN
    get_sha512(data_file, file_name, hash);
    print_hexa(hash, SHA512_DIGEST_LENGTH);
}

int
main(int argc, char *argv[]) {

    if(! args_ok(argc, argv))
        errx(EXIT_FAILURE, "%s\n", "Usage Error");

    if(is_long_version(argv[MinArgs - 2]))
        check_signature(argv[MinArgs - 1], argv[MinArgs], argv[MinArgs + 1]);
    else
        sign(argv[MinArgs - 2], argv[MinArgs - 1]);

    exit(EXIT_SUCCESS);
}
