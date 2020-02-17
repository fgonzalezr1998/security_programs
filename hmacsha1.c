#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <string.h>

enum{

	NArgs = 3,
	MaxStr = 32,

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
	for(int i = 0; i < len; i++)
		printf("%02x", str[i]);

	printf("\n");
}

void
print_hmacsha1(char *data_file, char *key_file)
{
	/*
	 *Print hmacsha1 of data file given key
	 */
	FILE *data_fd;
	int eof = 0;
	SHA_CTX c;
	unsigned char md[SHA_DIGEST_LENGTH];

	data_fd = fopen(data_file, "r");
	if(data_fd == NULL)
		errx(EXIT_FAILURE, "%s\n", "open file failed");

	//read data
	char data_buf[MaxStr];
	SHA1_Init(&c);

	while(! eof){
		if(fgets(data_buf, MaxStr, data_fd) == NULL){
			eof = 1;
			continue;
		}else{
			//update hash
			SHA1_Update(&c, data_buf, strlen(data_buf));
		}
	}
	SHA1_Final(md, &c);

	print_hexa(md, SHA_DIGEST_LENGTH);

	fclose(data_fd);
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
