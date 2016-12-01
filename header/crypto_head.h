#ifndef CRYPTO_H
#define CRYPTO_H

struct user_crypt
{
	string_t key;
	string_t iv;
};

typedef std::map<string_t, user_crypt> map_string_crypt_t;

void ssl_setup ();
void ssl_cleanup ();

string_t uchar_to_hex (const unsigned char *, const int);
int hex_to_uchar (string_t, unsigned char []);

void ssl_encrypt (const string_t, const string_t, const string_t, string_t &);
void ssl_decrypt (const string_t, const string_t, const string_t, string_t &);

void ssl_bytes_to_key (const string_t, string_t &, string_t &);
void ssl_pass_to_key (const string_t, string_t &, string_t &, unsigned char *salt=NULL, int saltlen=0);

void ssl_print_bio_dump (const string_t);

#endif