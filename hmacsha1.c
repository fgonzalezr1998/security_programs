#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <string.h>

enum{

	NArgs = 3,
	BlockSize = 64,
	MaxKeyLen = 2048,
	IPadByte = 0x36,
	OPadByte = 0x5C,
};

int
n_args_is_ok(int n)
{
	return n == NArgs;
}

int
files_ok(char * argv[])
{
	int permissions_ok;

	for(int i = NArgs - 2; i < NArgs; i++){
		permissions_ok = access(argv[i], R_OK);
		if(permissions_ok != 0){
			fprintf(stderr, "File [%s] has not required permissions\n", argv[i]);
			return 0;
		}
	}
	return 1;
}

int
args_ok(int argc, char *argv[])
{
	return n_args_is_ok(argc) && files_ok(argv);
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
yellow()
{
	fprintf(stderr, "\033[1;33m");
}

void
reset()
{
	fprintf(stderr, "\033[0m");
}

void
raise_warning_len()
{
	yellow();
	fprintf(stderr, "[WARN] Key length is shorter than %d, you should use a longer key\n", SHA_DIGEST_LENGTH);
	reset();
}

void
make_xor(char *op1, char * op2, int size, unsigned char *dest)
{
	for(int i = 0; i < size; i++){
		dest[i] = (unsigned char)op1[i] ^ (unsigned char)op2[i];
	}
}

void
get_first_sha1(char *data_file, char *key, char *ipad, unsigned char *sha1_hash)
{
	/*
	 *get sha1 hash from 'data_file' file
	 */
	int data_fd, eof, n_bytes_rode;
	eof = 0;
	SHA_CTX c;
	unsigned char xor[BlockSize];

	make_xor(key, ipad, BlockSize, xor);

	data_fd = open(data_file, O_RDONLY);
	if(data_fd == -1)
		errx(EXIT_FAILURE, "%s\n", "open file failed");

	//read data
	char data_buf[BlockSize];

	if(! SHA1_Init(&c)){
		errx(EXIT_FAILURE, "%s\n", "Hash failed");
	}
	SHA1_Update(&c, data_buf, strlen(data_buf));
	while(! eof){
		n_bytes_rode = read(data_fd, data_buf, BlockSize);

		if(n_bytes_rode < 0)
			errx(EXIT_FAILURE, "%s\n", "Error reading data file!");

		if(n_bytes_rode < BlockSize)
			eof = 1;

		SHA1_Update(&c, data_buf, n_bytes_rode);
	}
	SHA1_Final(sha1_hash, &c);
	close(data_fd);
}

void
add_padding(char *str, int len)
{
	/*
	 * Add padding to 'src' until BlockSize
	 */
	int padding_len;

	padding_len = BlockSize - len;
	printf("%d\n", padding_len);

	for(int i = len - 1; i < len + padding_len; i++){
		str[i] = '0';
	}
}

void
set_key_length(char *key, int size)
{
	if(strlen((char *)key) < size)
		add_padding(key, BlockSize);
	else
		key[BlockSize - 1] = '\0';
}

void
get_key(char *key_file, char *key)
{
	int key_fd;
	ssize_t n_bytes_rode;

	//open file
	key_fd = open(key_file, O_RDONLY);
	if(key_fd == -1)
		errx(EXIT_FAILURE, "%s\n", "open file failed");

	//¿qUE MANERA MEJOR HAY DE LEER LA CLAVE PARA NO DEPENDER DE UNA SOLA LECTURA?
	n_bytes_rode = read(key_fd, key, BlockSize);

	if(n_bytes_rode < 0)
		errx(EXIT_FAILURE, "%s\n", "File reading failed");

	close(key_fd); //close file

	//if key length is smaller than, BlockSize, add padding until BlockSize
	if(n_bytes_rode < BlockSize){
		add_padding(key, (int)n_bytes_rode);
	}
	// ******* HASTA AQUI ESTA BIEN! *******
	//Ya tengo la clave como debe estar, a longitud 64, o bien acortada o con padding
}

void
get_ipad_opad(char *ipad, char *opad)
{
	for(int i = 0; i < BlockSize; i++){
		ipad[i] = IPadByte;
		opad[i] = OPadByte;
	}
}

void
concatenate(unsigned char *str1, unsigned char *str2, int size1,
								int size2, unsigned char *dest)
{
	int i;
	for(i = 0; i < size1; i++){
		dest[i] = str1[i];
	}
	for(i = 0; i < size2; i++){
		dest[size1 + i] = str2[i];
	}
}

void
get_hmac(char *key, char *opad, unsigned char *hash_first, unsigned char *hmac)
{
	int hash_arg_size = BlockSize + SHA_DIGEST_LENGTH - 1;
	unsigned char xor[BlockSize], hash_arg[hash_arg_size];
	SHA_CTX c;

	make_xor(key, opad, BlockSize, xor);
	concatenate(xor, hash_first, BlockSize, SHA_DIGEST_LENGTH, hash_arg);

	if(! SHA1_Init(&c)){
		errx(EXIT_FAILURE, "%s\n", "Hash failed");
	}
	for(int i = 0; i < hash_arg_size; i++)
		SHA1_Update(&c, &hash_arg[i], 1);

	SHA1_Final(hmac, &c);
}

void
print_hmacsha1(char *data_file, char *key_file)
{
	/*
	 *Print hmacsha1 of data file given key
	 */
	unsigned char sha1_hash_first[SHA_DIGEST_LENGTH], hmac[SHA_DIGEST_LENGTH];
	char key[BlockSize], ipad[BlockSize], opad[BlockSize];
	//unsigned char ipad[BlockSize];

	//1º Get key from key_file
	get_key(key_file, key);

	//2º Get ipad and opad
	get_ipad_opad(ipad, opad);

	get_first_sha1(data_file, key, ipad, sha1_hash_first);
	get_hmac(key, opad, sha1_hash_first, hmac);

	print_hexa(hmac, SHA_DIGEST_LENGTH);
}

int
main(int argc, char *argv[])
{
	if(! args_ok(argc, argv))
		errx(EXIT_FAILURE, "%s\n", "[Usage Error] invalid arguments");

	print_hmacsha1(argv[NArgs - 2], argv[NArgs - 1]);

	exit(EXIT_SUCCESS);
}
