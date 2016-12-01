#ifndef KDC_H
#define KDC_H

void generate_registered_user_crypts (map_string_string_t, map_string_crypt_t &);
void generate_user_crypt (const string_t, map_string_string_t, map_string_crypt_t &);

void kdc_keygen_handshake (fd_t &, map_string_string_t, map_string_fd_t, map_string_crypt_t, const vector_string_t);

#endif