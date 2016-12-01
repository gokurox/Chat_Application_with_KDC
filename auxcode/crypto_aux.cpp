#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/crypto_head.h"

using namespace std;

void handleErrors(void);
int ssl_encrypt_raw (const unsigned char *, int, const unsigned char *, const unsigned char *, unsigned char *);
int ssl_decrypt_raw (const unsigned char *, int, const unsigned char *, const unsigned char *, unsigned char *);
void ssl_bytes_to_key_raw (const char *, const char *, const unsigned char *, unsigned char *, unsigned char *);

/*****************************************************************************/

static std::map<char, int> HEXMAP = {
	{'0', 0},
	{'1', 1},
	{'2', 2},
	{'3', 3},
	{'4', 4},
	{'5', 5},
	{'6', 6},
	{'7', 7},
	{'8', 8},
	{'9', 9},
	{'a', 10},	{'A', 10},
	{'b', 11},	{'B', 11},
	{'c', 12},	{'C', 12},
	{'d', 13},	{'D', 13},
	{'e', 14},	{'E', 14},
	{'f', 15},	{'F', 15}
};

/*****************************************************************************/

void handleErrors(void)
{
	ERR_print_errors_fp (stderr);
	abort();
}

void ssl_setup ()
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
}

void ssl_cleanup ()
{
	EVP_cleanup();
	ERR_free_strings();
}

string_t uchar_to_hex (const unsigned char *input, const int inp_len) {
	string_t output;
	stringstream ss;

	for (int i = 0; i < inp_len; i++) {
		ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int) input[i];
	}
	output.clear ();
	output = ss.str();
	
	assert (output.size() % 2 == 0);
	return output;
}

int hex_to_uchar (string_t input, unsigned char output[]) {
	int in_len = input.size();
	int out_len = 0;

	for (int i = 0, j = 0; i < in_len; i += 2, j++, out_len++) {
		unsigned char c0, c1;
		c0 = input[i +1];
		c1 = input[i];

		int ucval = HEXMAP[c0] + (HEXMAP[c1] * 16);
		output[j] = (unsigned char) ucval;
	}

	assert (out_len == (int)(in_len/2));
	return (out_len);
}

int ssl_encrypt_raw (const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int ssl_decrypt_raw (const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void ssl_encrypt (const string_t plaintext, const string_t key, const string_t iv, string_t &ciphertext)
{
	const unsigned char *plaintext_cstr = (unsigned char *) plaintext.c_str();
	const int plaintext_size = plaintext.size();
	unsigned char key_cstr[32], iv_cstr[16];

	const int key_size = hex_to_uchar (key, key_cstr);
	const int iv_size = hex_to_uchar (iv, iv_cstr);

	assert (key_size == 32);
	assert (iv_size == 16);

	/* AES Block length = 128b = 16B
	 * Max ciphertext len_B = plaintext_len_B + 16B	
	 * Providing twice of that to be sure */
	const int ciphertext_possible_size = 2 * (plaintext_size + 16);
	unsigned char ciphertext_cstr [ciphertext_possible_size];
	
	bzero ((char *)ciphertext_cstr, ciphertext_possible_size);

	const int ciphertext_size = ssl_encrypt_raw (plaintext_cstr, plaintext_size, key_cstr, iv_cstr, ciphertext_cstr);

	string_t hex_cipher = uchar_to_hex (ciphertext_cstr, ciphertext_size);

	ciphertext.clear();
	ciphertext.reserve (ciphertext_possible_size);
	ciphertext.assign (hex_cipher);
	ciphertext.shrink_to_fit ();
}

void ssl_decrypt (const string_t ciphertext, const string_t key, const string_t iv, string_t &plaintext)
{
	unsigned char ciphertext_cstr [ciphertext.size()];
	unsigned char key_cstr[32], iv_cstr[16];

	bzero ((char *)ciphertext_cstr, ciphertext.size());
	bzero ((char *)key_cstr, 32);
	bzero ((char *)iv_cstr, 16);

	const int ciphertext_size = hex_to_uchar (ciphertext, ciphertext_cstr);
	const int key_size = hex_to_uchar (key, key_cstr);
	const int iv_size = hex_to_uchar (iv, iv_cstr);

	assert (key_size == 32);
	assert (iv_size == 16);

	/* AES Block length = 128b = 16B
	 * Max plaintext_len_B = ciphertext_len_B	
	 * Providing twice of that to be sure */
	const int plaintext_possible_size = 2 * ciphertext_size;
	unsigned char plaintext_cstr [plaintext_possible_size];

	bzero ((char *)plaintext_cstr, plaintext_possible_size);
	
	const int plaintext_size = ssl_decrypt_raw (ciphertext_cstr, ciphertext_size, key_cstr, iv_cstr, plaintext_cstr);

	char dec_plaintext [plaintext_size +1];
	bzero (dec_plaintext, plaintext_size +1);
	for (int i = 0; i < plaintext_size; i++) {
		dec_plaintext[i] = (char) plaintext_cstr[i];
	}

	plaintext.clear();
	plaintext.reserve (plaintext_possible_size);
	plaintext.assign (dec_plaintext);
	plaintext.shrink_to_fit ();
}

void ssl_bytes_to_key_raw (const char *cipher_name, const char *digest_name, const unsigned char *password, unsigned char key[], unsigned char iv[])
{
    const EVP_CIPHER *cipher = EVP_get_cipherbyname (cipher_name);
    if (!cipher) {
    	fprintf (stderr, "no such cipher\n");
    	handleErrors ();
    }

    const EVP_MD *digest = EVP_get_digestbyname (digest_name);
    if (!digest) {
    	fprintf (stderr, "no such digest\n");
    	handleErrors ();
    }

    /*if (strcmp (cipher_name, "aes-256-cbc") == 0) {
    	std::cout << sizeof (key) << ", " << sizeof (iv) << std::endl;
    	assert (sizeof (key) == 32);
    	assert (sizeof (iv) == 16);
    }*/

    const unsigned char *salt = NULL;

	// Assume ssl_setup has already been called

    // cipher = EVP_get_cipherbyname("aes-256-cbc");
    // dgst=EVP_get_digestbyname("md5");

    if (!EVP_BytesToKey (cipher, digest, salt, password, strlen ((char *) password), 1, key, iv)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        handleErrors ();
    }
}

void ssl_bytes_to_key (const string_t password, string_t &key, string_t &iv)
{
	const char *cipher_name = "aes-256-cbc";
	const char *digest_name = "md5";
	const unsigned char *password_cstr = (unsigned char *) password.c_str();
	unsigned char key_cstr[32], iv_cstr[16];

	bzero ((char *)key_cstr, 32);
	bzero ((char *)iv_cstr, 16);

	ssl_bytes_to_key_raw (cipher_name, digest_name, password_cstr, key_cstr, iv_cstr);

	string_t hex_key = uchar_to_hex (key_cstr, 32);
	string_t hex_iv = uchar_to_hex (iv_cstr, 16);

	key.clear();
	key.reserve (32);
	key.assign (hex_key);
	key.shrink_to_fit ();

	iv.clear();
	iv.reserve (16);
	iv.assign (hex_iv);
	iv.shrink_to_fit ();
}

void ssl_pass_to_key (const string_t password, string_t &key, string_t &iv, unsigned char *salt, int saltlen)
{
	const char *password_cstr = password.c_str();
	unsigned char key_cstr[32], iv_cstr[16];

	bzero ((char *)key_cstr, 32);
	bzero ((char *)iv_cstr, 16);

	int rc;
	rc = PKCS5_PBKDF2_HMAC_SHA1 (password_cstr, password.size(), salt, saltlen, 3000, 32, key_cstr);
	assert (rc == 1);
	rc = PKCS5_PBKDF2_HMAC_SHA1 (password_cstr, password.size(), salt, saltlen, 1500, 16, iv_cstr);
	assert (rc == 1);

	string_t hex_key = uchar_to_hex (key_cstr, 32);
	string_t hex_iv = uchar_to_hex (iv_cstr, 16);
	
	key.clear();
	key.reserve (32);
	key.assign (hex_key);
	key.shrink_to_fit ();

	iv.clear();
	iv.reserve (16);
	iv.assign (hex_iv);
	iv.shrink_to_fit ();
}

// int PKCS5_PBKDF2_HMAC_SHA1 (const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, int keylen, unsigned char *out);
void ssl_print_bio_dump (const string_t cipher)
{
	unsigned char cipher_cstr [cipher.size()];
	int cipher_size = hex_to_uchar (cipher, cipher_cstr); 
	
	BIO_dump_fp (stdout, (char *)cipher_cstr, cipher_size);

	fflush (stdout);
	cout.flush();
}