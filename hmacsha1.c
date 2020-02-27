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
get_sha1(char *data_file, unsigned char *sha1_hash)
{
	/*
	 *get sha1 hash from 'data_file' file
	 */

	FILE *data_fd;
	int eof = 0;
	SHA_CTX c;

	data_fd = fopen(data_file, "r");
	if(data_fd == NULL)
		errx(EXIT_FAILURE, "%s\n", "open file failed");

	//read data
	char data_buf[BlockSize];

	if(! SHA1_Init(&c)){
		errx(EXIT_FAILURE, "%s\n", "Hash failed");
	}
	while(! eof){
		if(fgets(data_buf, BlockSize, data_fd) == NULL){
			eof = 1;
			continue;
		}else{
			SHA1_Update(&c, data_buf, strlen(data_buf));
		}
	}
	SHA1_Final(sha1_hash, &c);
	fclose(data_fd);
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
	for(int i = 0; i < BlockSize; i++){
		printf("%c", key[i]);
	}
	printf("\n");
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
print_hmacsha1(char *data_file, char *key_file)
{
	/*
	 *Print hmacsha1 of data file given key
	 */
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	char key[BlockSize], ipad[BlockSize], opad[BlockSize];
	//unsigned char ipad[BlockSize];

	//1º Get key from key_file
	get_key(key_file, key);

	//2º Get ipad and opad
	get_ipad_opad(ipad, opad);

	get_sha1(data_file, sha1_hash);
}

int
main(int argc, char *argv[])
{
	if(! args_ok(argc, argv))
		errx(EXIT_FAILURE, "%s\n", "[Usage Error] invalid arguments");

	print_hmacsha1(argv[NArgs - 2], argv[NArgs - 1]);

	exit(EXIT_SUCCESS);
}
