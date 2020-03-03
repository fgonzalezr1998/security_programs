#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

enum{

	NArgs = 3,
	BlockSize = 64,
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
make_xor(unsigned char *op1, unsigned char * op2, int size, unsigned char *dest)
{
	for(int i = 0; i < size; i++){
		dest[i] = op1[i] ^ op2[i];
	}
}

void
get_first_sha1(char *data_file, unsigned char *key, unsigned char *ipad, unsigned char *sha1_hash)
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
	SHA1_Update(&c, xor, BlockSize);
	while(! eof){
		n_bytes_rode = read(data_fd, data_buf, BlockSize);

		if(n_bytes_rode < 0)
			errx(EXIT_FAILURE, "%s\n", "Error reading data file!");

		if(n_bytes_rode < BlockSize)
			eof = 1;
		for(int i = 0; i < n_bytes_rode; i++){
			printf("%c\n", data_buf[i]);
		}
		SHA1_Update(&c, data_buf, n_bytes_rode);
	}
	SHA1_Final(sha1_hash, &c);
	close(data_fd);
}

void
add_padding(unsigned char *str, int len)
{
	/*
	 * Add padding to 'src' until BlockSize
	 */
	int padding_len;

	padding_len = BlockSize - len;

	for(int i = len - 1; i < len + padding_len; i++){
		str[i] = '0';
	}
}

void
set_key_length(unsigned char *key, int size)
{
	if(strlen((char *)key) < size)
		add_padding(key, BlockSize);
	else
		key[BlockSize - 1] = '\0';
}

void
get_key(char *key_file, unsigned char *key)
{
	int key_fd;
	struct stat statbuf;
	ssize_t n_bytes_rode;
	SHA_CTX c;

	//open file
	key_fd = open(key_file, O_RDONLY);
	if(key_fd == -1)
		errx(EXIT_FAILURE, "%s\n", "open file failed");

	if(fstat(key_fd, &statbuf) < 0)
		errx(EXIT_FAILURE, "%s\n", "Fail getting file state!");
		
	n_bytes_rode = read(key_fd, key, statbuf.st_size);
	close(key_fd); //close file

	if(n_bytes_rode < 0)
		errx(EXIT_FAILURE, "%s\n", "File reading failed");

	if(n_bytes_rode < SHA_DIGEST_LENGTH)
		raise_warning_len();

	if(n_bytes_rode > BlockSize){

		if(! SHA1_Init(&c)){
			errx(EXIT_FAILURE, "%s\n", "Hash failed");
		}
		SHA1_Update(&c, key, n_bytes_rode);
		SHA1_Final(key, &c);
	}
	add_padding(key, (int)n_bytes_rode);
	// ******* HASTA AQUI ESTA BIEN! *******
	//Ya tengo la clave como debe estar, a longitud 64, o bien acortada o con padding
}

void
get_ipad_opad(unsigned char *ipad, unsigned char *opad)
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
get_hmac(unsigned char *key, unsigned char *opad, unsigned char *hash_first, unsigned char *hmac)
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
	unsigned char key[BlockSize], ipad[BlockSize], opad[BlockSize];
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
