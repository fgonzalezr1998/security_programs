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

void print_hexa(unsigned char *str, int len)
{
	/*
	 *print 'str' using hexadecimal format
	 */
	for(int i = 0; i < len; i++)
		printf("%02x", str[i]);

	printf("\n");
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

	SHA1_Init(&c);
	while(! eof){
		if(fgets(data_buf, BlockSize, data_fd) == NULL){
			eof = 1;
			continue;
		}else{
			//update hash
			SHA1_Update(&c, data_buf, strlen(data_buf));
		}
	}
	SHA1_Final(sha1_hash, &c);
	fclose(data_fd);
}

void
get_key(char *key_file, char *key)
{
	FILE *key_fd;
	int eof = 0;
	char key_buf[BlockSize];

	//open file
	key_fd = fopen(key_file, "r");
	if(key_fd == NULL)
		errx(EXIT_FAILURE, "%s\n", "open file failed");

	key[0] = '\0'; //this is for strncat() knows 'key' is a empty string the first time
	while(! eof){
		if(fgets(key_buf, BlockSize, key_fd) == NULL){
			eof = 1;
			continue;
		}else{
			strncat(key, key_buf, strlen(key_buf));
		}
	}
	fclose(key_fd);
	//if key length is smaller than, BlockSize, add padding until BlockSize
	if(strlen(key) < BlockSize)
		add_padding(key, BlockSize);
}

void
print_hmacsha1(char *data_file, char *key_file)
{
	/*
	 *Print hmacsha1 of data file given key
	 */
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	char key[MaxKeyLen];

	//1º Get key from key_file
	get_key(key_file, key);
	printf("%s\n", key);

	get_sha1(data_file, sha1_hash);
	print_hexa(sha1_hash, SHA_DIGEST_LENGTH);
}

int
main(int argc, char *argv[])
{
	if(! args_ok(argc, argv)){
		errx(EXIT_FAILURE, "%s\n", "[Usage Error] invalid arguments");
	}

	print_hmacsha1(argv[NArgs - 2], argv[NArgs - 1]);

	exit(EXIT_SUCCESS);
}
