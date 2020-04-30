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

void
text2yellow()
{
	fprintf(stderr, "\033[1;33m");
}
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
raise_warning_len()
{
	text2yellow();
	fprintf(stderr, "[WARN] key is too short (should be longer than %d bytes)\n", SHA_DIGEST_LENGTH);
	reset();
}

void
raise_error(char *str)
{
	text2red();
	fprintf(stderr, "[ERROR] %s\n", str);
	reset();
	exit(EXIT_FAILURE);
}

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
			text2red();
			fprintf(stderr, "File [%s] has not required permissions\n", argv[i]);
			reset();
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
	int data_fd, eof, n_bytes;
	eof = 0;
	SHA_CTX c;
	unsigned char xor[BlockSize];
	unsigned char data_buf[BlockSize];

	make_xor(key, ipad, BlockSize, xor);

	data_fd = open(data_file, O_RDONLY);
	if(data_fd == -1)
		raise_error("open file failed");

	//Read data
	if(! SHA1_Init(&c)){
		raise_error("Hash Init failed!");
	}
	if(SHA1_Update(&c, xor, BlockSize) < 0)
		raise_error("SHA1 Update failed!");

	while(! eof){
		n_bytes = read(data_fd, data_buf, BlockSize);

		if(n_bytes < 0){
			close(data_fd);
			raise_error("Error reading data file!");
		}
		if(n_bytes < BlockSize)
			eof = 1;

		if(SHA1_Update(&c, data_buf, n_bytes) < 0){
			close(data_fd);
			raise_error("SHA1 Update failed!");
		}
	}
	close(data_fd);
	if(SHA1_Final(sha1_hash, &c) < 0)
		raise_error("SHA1 Final failed!");
}

void
add_padding(unsigned char *str, int len)
{
	/*
	 * Add padding to 'src' until BlockSize
	 */

	for(int i = len; i < BlockSize; i++){
		str[i] = (unsigned char)0x00;
	}
}

void
cut_key(unsigned char *key_aux, ssize_t n_bytes, int *key_len)
{
	SHA_CTX c;

	if(! SHA1_Init(&c)){
		raise_error("Hash Init failed!");
	}
	if(SHA1_Update(&c, key_aux, n_bytes) < 0)
		raise_error("SHA1 Update failed!");
	if(SHA1_Final(key_aux, &c) < 0)
		raise_error("SHA1 Final failed!");

	*key_len = SHA_DIGEST_LENGTH;
}

void
get_key(char *key_file, unsigned char *key)
{
	int key_fd, key_len;
	struct stat statbuf;
	ssize_t n_bytes;
	unsigned char *key_aux;

	//open file
	key_fd = open(key_file, O_RDONLY);
	if(key_fd == -1)
		raise_error("open file failed");

	if(fstat(key_fd, &statbuf) < 0){
		close(key_fd); //close file
		raise_error("Get file state failed!");
	}
	/*
	 *Use 'key_aux' because i don't now if 'statbuf.st_size' is greater than
	 *memory reserved to 'key' and it may cause an overflow.
	 */
	key_aux = (unsigned char *)malloc(statbuf.st_size);

	n_bytes = read(key_fd, key_aux, (int)statbuf.st_size);
	close(key_fd); //close file

	if(n_bytes < 0){
		raise_error("File reading failed");
		free(key_aux);
	}

	key_len = (int)n_bytes;

	if(n_bytes < SHA_DIGEST_LENGTH)
		raise_warning_len();

	if(n_bytes > BlockSize){

		cut_key(key_aux, n_bytes, &key_len);
	}
	memcpy(key, key_aux, key_len);
	free(key_aux);
	
	add_padding(key, key_len);
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
	int hash_arg_size = BlockSize + SHA_DIGEST_LENGTH;
	unsigned char xor[BlockSize], hash_arg[hash_arg_size];
	SHA_CTX c;

	make_xor(key, opad, BlockSize, xor);
	concatenate(xor, hash_first, BlockSize, SHA_DIGEST_LENGTH, hash_arg);

	if(! SHA1_Init(&c)){
		raise_error("Hash failed");
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

	//1º Get key from key_file
	get_key(key_file, key);

	//2º Get ipad and opad
	get_ipad_opad(ipad, opad);

	//3º Get first HSA1 -H(K XOR ipad, text)-
	get_first_sha1(data_file, key, ipad, sha1_hash_first);

	//4º Conclude with HMAC Compute -H(K XOR opad, sha1_hash_first)-
	get_hmac(key, opad, sha1_hash_first, hmac);

	//Print HMAC in Hexadecimal Format
	print_hexa(hmac, SHA_DIGEST_LENGTH);
}

int
main(int argc, char *argv[])
{
	if(! args_ok(argc, argv))
		raise_error("[Usage Error] invalid arguments");

	print_hmacsha1(argv[NArgs - 2], argv[NArgs - 1]);

	exit(EXIT_SUCCESS);
}
