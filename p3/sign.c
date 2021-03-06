#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

enum{
    MinArgs = 3,
    MaxFilenameBytes = 40,
    BlockSize = 64,
    KeyLen = 4096 / 8,
    IDSHA512Len = 19,
    SignLen = 512,
};

const unsigned char IDSHA512[] = {0x30, 0x51, 0x30, 0x0d,
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
    text2red();
    if(d)
        fprintf(stderr, "[ERROR] %s\n", str);
    else
        printf("%s\n", "Error");

    reset();

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
is_verify_version(char *arg1, char *arg2)
{
    return strncmp(arg1, "-v", sizeof(char) * strlen("-v")) == 0 ||
                strncmp(arg2, "-v", sizeof(char) * strlen("-v")) == 0;
}

int
is_debug_version(char *arg1, char *arg2)
{
    return strncmp(arg1, "-d", sizeof(char) * strlen("-d")) == 0 ||
                strncmp(arg2, "-d", sizeof(char) * strlen("-d")) == 0;
}

int
args_ok(int argc, char *argv[])
{
    if(argc < MinArgs)
        return 0;

    if(is_verify_version(argv[MinArgs - 2], argv[MinArgs - 1]))
        return long_version_isok(argc, argv);
    else
        return file_isok(argv[MinArgs - 2]) && file_isok(argv[MinArgs - 1]);
}

RSA *
private_key(char *privkey_file, int debug)
{
    FILE *file;
    RSA *r;
    file = fopen(privkey_file, "r");
    if(file == NULL)
        raise_error("Error openning private key file!", debug);

    r = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
    fclose(file);

    return r;
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
read_sign(char *sf, unsigned char *signature, int debug)
{
    BIO *bio;
    BIO *b64;
    FILE *file;
    int nb;

    file = fopen(sf, "r");
    if(file == NULL)
        raise_error("Error opening signature file!", debug);

    b64 = BIO_new(BIO_f_base64());
    bio=BIO_new_fp(file, BIO_NOCLOSE);
    BIO_push(b64, bio);

    nb = BIO_read(b64, signature, SignLen);
    fclose(file);
    BIO_free(b64);

    if(nb < 0)
        raise_error("Error reading signature!", debug);
}

void
decrypt_signature(unsigned char *s, char *pkf, unsigned char *ds, int debug)
{
    FILE *file;
    RSA *rsa;
    int pubkeylen;

    file = fopen(pkf, "r");
    if(file == NULL)
        raise_error("Error openning public key file!", debug);

    rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);

    if(rsa == NULL){
        raise_error("Error reading public key!", debug);
    }

    pubkeylen = RSA_public_decrypt(SignLen, s, ds, rsa, RSA_NO_PADDING);

    if(pubkeylen < 0)
        raise_error("Error decrpting signature!", debug);
}

void
get_sha512(char *data_file, char *file_name, unsigned char *hash, int debug)
{
    SHA512_CTX c;
    int fd, bytes;
    unsigned char buf[BlockSize];
    //open 'data_file'
    fd = open(data_file, O_RDONLY);
    if(fd < 0)
        raise_error("Error Openning file!", debug);

    if(SHA512_Init(&c) < 0){
        close(fd);
        exit(EXIT_FAILURE);
    }

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

int
padding_ok(unsigned char *decrypted_signature)
{
    int lenps, lent;

    lent = IDSHA512Len + SHA512_DIGEST_LENGTH;
    lenps = KeyLen - lent - 3;

    if(decrypted_signature[0] != 0x00 || decrypted_signature[1] != 0x01)
        return 0;
    //check ps:
    for(int i = 0; i < lenps; i++){
        if(decrypted_signature[2 + i] != 0xFF)
            return 0;
    }
    if(decrypted_signature[lenps + 2] != 0x00)
        return 0;

    return 1;
}

int
hash_ok(char *data_file, unsigned char *decrypted_signature, int debug)
{
    int lenps, lent;
    lent = IDSHA512Len + SHA512_DIGEST_LENGTH;
    lenps = KeyLen - lent - 3;

    char file_name[MaxFilenameBytes];
    unsigned char hash1[SHA512_DIGEST_LENGTH], hash2[SHA512_DIGEST_LENGTH];

    memcpy(hash1, &decrypted_signature[lenps + 3 + IDSHA512Len], SHA512_DIGEST_LENGTH);

    get_file_name(data_file, file_name);

    get_sha512(data_file, file_name, hash2, debug);

    return memcmp(hash1, hash2, SHA512_DIGEST_LENGTH) == 0;
}

int
ID_ok(unsigned char *decrypted_signature)
{
    int lenps, lent;
    lent = IDSHA512Len + SHA512_DIGEST_LENGTH;
    lenps = KeyLen - lent - 3;
    unsigned char id[IDSHA512Len];

    memcpy(id, &decrypted_signature[lenps + 3], IDSHA512Len);

    return memcmp(id, IDSHA512, IDSHA512Len) == 0;
}

int
decrypted_sign_is_ok(unsigned char *decrypted_signature, char *data_file, int debug)
{
    return padding_ok(decrypted_signature) && ID_ok(decrypted_signature) &&
                        hash_ok(data_file, decrypted_signature, debug);
}

void
check_signature(char *signature_file, char *data_file, char *public_key_file, int debug)
{
    unsigned char signature[SignLen], decrypted_signature[SignLen];
    //Read sign:
    read_sign(signature_file, signature, debug);
    //Decrypt signature:
    decrypt_signature(signature, public_key_file, decrypted_signature, debug);

    if(! decrypted_sign_is_ok(decrypted_signature, data_file, debug))
        raise_error("BAD SIGNATURE", 1);
}

void
get_ps(int len, unsigned char *ps)
{
    memset(ps, (unsigned char)0xFF, len);
}

void
build_t(unsigned char *hash, unsigned char *t)
{
    for(int i = 0; i < IDSHA512Len; i++){
        t[i] = IDSHA512[i];
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

    //put PS:
    len = 2;
    for(i = 0; i < lenps; i++){
        msg2sign[len + i] = ps[i];
    }

    len += lenps;
    msg2sign[len++] = (unsigned char)0x00;

    //put T:
    for(i = 0; i < lent; i++){
        msg2sign[len + i] = t[i];
    }
    len += lent;
}

void
print_sign(unsigned char *signed_data, int sign_len, int debug)
{
    BIO *bio;
    BIO *b64;
    int nb;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_push(b64, bio);

    printf("%s\n", "-----BEGIN SRO SIGNATURE-----");

    nb = BIO_write(b64, signed_data, sign_len);

    if(nb < 0)
        raise_error("BIO_write eror", debug);

    BIO_flush(b64);
    BIO_free_all(b64);

    printf("%s\n", "-----END SRO SIGNATURE-----");
}

void
sign(char *data_file, char * privkey_file, int debug)
{
    char file_name[MaxFilenameBytes];
    unsigned char hash[SHA512_DIGEST_LENGTH], msg2sign[KeyLen];
    unsigned char *signed_data;
    int sign_len;
    RSA *rsa;

    get_file_name(data_file, file_name);

    get_sha512(data_file, file_name, hash, debug);
    //Get EM
    get_msg_2_sign(hash, msg2sign);

    //Read Private Key
    rsa = private_key(privkey_file, debug);

    if(rsa == NULL)
        raise_error("Error reading private key", debug);

    //Allocate memory to save signed data:
    signed_data = (unsigned char *)malloc(RSA_size(rsa));
    if(signed_data == NULL)
        raise_error("Error Allocating memory", debug);

    sign_len = RSA_private_encrypt(KeyLen, msg2sign, signed_data, rsa, RSA_NO_PADDING);

    if(sign_len < 0){
        free(signed_data);
        raise_error("Data sign failed!", debug);
    }

    print_sign(signed_data, sign_len, debug);

    free(signed_data);
}

void
reorganize_args(char *args[], int *len_args)
{
    for(int i = MinArgs - 2; i < *len_args - 1; i++){
        args[i] = args[i + 1];
    }
    (*len_args)--;

    if(strncmp(args[MinArgs - 2], "-d", sizeof(char) * strlen("-d")) == 0)
        args[MinArgs - 2] = "-v";

}

int
main(int argc, char *argv[])
{
    int debug = 0;

    if(is_debug_version(argv[MinArgs - 2], argv[MinArgs - 1]))
    {
        reorganize_args(argv, &argc);
        debug = 1;
    }

    if(! args_ok(argc, argv))
        errx(EXIT_FAILURE, "%s\n", "Usage Error");

    if(is_verify_version(argv[MinArgs - 2], argv[MinArgs - 1]))
        check_signature(argv[MinArgs - 1], argv[MinArgs], argv[MinArgs + 1], debug);
    else
        sign(argv[MinArgs - 2], argv[MinArgs - 1], debug);

    exit(EXIT_SUCCESS);
}
