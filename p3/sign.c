#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

enum{
    MinArgs = 3,
    MaxFilenameBytes = 40,
    BlockSize = 64,
    KeyLen = 4069 / 8,
    IDSHA512Len = 19,
};

int debug = 1;

const unsigned char IDSHA12[] = {0x30, 0x51, 0x30, 0x0d,
                                    0x06, 0x09, 0x60, 0x86,
                                    0x48, 0x01, 0x65, 0x03,
                                    0x04, 0x02, 0x03, 0x05,
                                    0x00, 0x04, 0x40};


void
text2red()
{
	fprintf(stderr, "\033[1;31m");
}

void
reset()
{
	fprintf(stderr, "\033[0m");
}

void
raise_error(char *str, int d)
{
    if(d){
        text2red();
        fprintf(stderr, "[ERROR] %s\n", str);
        reset();
    }
    exit(EXIT_FAILURE);
}

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
    printf("%s\n", "Checkeo la firma!");
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
    //Alimento la hash con los datos del fichero
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
    close(fd);
}

void
get_ps(int len, unsigned char *ps)
{
    for(int i = 0; i < len ; i++){
        ps[i] = (unsigned char)0xFF;
    }
}

void
build_t(unsigned char *hash, unsigned char *t)
{
    for(int i = 0; i < IDSHA512Len; i++){
        t[i] = IDSHA12[i];
    }
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++){
        t[IDSHA512Len + i] = hash[i];
    }
}

void
get_msg_2_sign(unsigned char *hash, unsigned char *msg2sign)
{
    int len, lent, lenps, i;

    lent = IDSHA512Len + SHA512_DIGEST_LENGTH;
    lenps = KeyLen - lent - 3;
    unsigned char ps[lenps];
    unsigned char t[lent];

    //Build PS:
    get_ps(lenps, ps);
    //Build T:
    build_t(hash, t);

    //Compose msg2sign:
    msg2sign[0] = (unsigned char)0x00;
    msg2sign[1] = (unsigned char)0x01;

    len = 2;
    for(i = 0; i < lenps; i++){
        msg2sign[len + i] = ps[i];
    }

    len += lenps;
    msg2sign[len++] = (unsigned char)0x00;
    for(i = 0; i < lent; i++){
        msg2sign[len + i] = t[i];
    }
    len += lent;
}

RSA *
read_priv_key(char *pivkey_file)
{
    FILE *file;
    file = fopen(pivkey_file, "r");
    if(file == NULL)
        raise_error("Error openning private key file!", debug);

    return PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
}

void
sign(char *data_file, char * privkey_file)
{
    char file_name[MaxFilenameBytes];
    unsigned char hash[SHA512_DIGEST_LENGTH], msg2sign[KeyLen];
    unsigned char *signed_data;
    int sign_len;
    RSA *rsa;

    get_file_name(data_file, file_name);

    get_sha512(data_file, file_name, hash);

    //Get EM
    get_msg_2_sign(hash, msg2sign);
    //***HASTA AQUI ESTA BIEN***

    //Read Private Key
    rsa = read_priv_key(privkey_file);
    if(rsa == NULL)
        raise_error("Error reading private key", debug);
    signed_data = (unsigned char *)malloc(RSA_size(rsa));
    if(signed_data == NULL)
        raise_error("Error Allocating memory", debug);
    sign_len = RSA_private_encrypt(KeyLen, msg2sign, signed_data, rsa, RSA_NO_PADDING);
    if(sign_len < 0)
        raise_error("Error signing data!", debug);
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
