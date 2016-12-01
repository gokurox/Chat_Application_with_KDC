#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/crypto_head.h"
#include "../header/kdc_head.h"

using namespace std;

void generate_registered_user_crypts (map_string_string_t registered_users, map_string_crypt_t &reg_users_crypt)
{
	map_string_string_t::iterator it = registered_users.begin();
	for (it; it != registered_users.end(); it++)
	{
		user_crypt crypt;
		
		crypt.key.clear();
		crypt.iv.clear();

		string_t uname = it -> first;
		string_t pword = it -> second;

		ssl_bytes_to_key (pword, crypt.key, crypt.iv);
		assert (crypt.key.empty() == false);
		assert (crypt.iv.empty() == false);

		reg_users_crypt [uname] = crypt;
	}
}

void generate_user_crypt (const string_t username, map_string_string_t registered_users, map_string_crypt_t &reg_users_crypt)
{
	user_crypt crypt;
	
	crypt.key.clear();
	crypt.iv.clear();

	string_t pword = registered_users [username];

	ssl_bytes_to_key (pword, crypt.key, crypt.iv);
	assert (crypt.key.empty() == false);
	assert (crypt.iv.empty() == false);

	reg_users_crypt [username] = crypt;
}

void kdc_keygen_handshake (fd_t &fd_A, map_string_string_t registered_users, map_string_fd_t logged_in_users, map_string_crypt_t reg_user_crypts, const vector_string_t client_request_ssk1)
{
	// recv SSK1

	string_t username_A = client_request_ssk1[3];
	string_t enc_payload_1 = client_request_ssk1[4];

	if (map_contains_key (registered_users, username_A) == false) {		// Is Alice registered
		send_negative_ACK (fd_A, "User is not registered.");
		close_fd (fd_A);		// Close kdc_fd
		return;
	}

	if (map_contains_key (reg_user_crypts, username_A) == false) {
		generate_user_crypt (username_A, registered_users, reg_user_crypts);	// Logically shouldn't be called
	}

	user_crypt crypt_A = reg_user_crypts [username_A];

	string_t dec_payload_1;
	ssl_decrypt (enc_payload_1, crypt_A.key, crypt_A.iv, dec_payload_1);
	vector_string_t payload_1_vector;
	split_length_appended_message (dec_payload_1, payload_1_vector);

	string_t username_B = payload_1_vector[1];

	if (map_contains_key (logged_in_users, username_B) == false) {
		send_negative_ACK (fd_A, "Other user is not online. Key exchange cannot proceed.");
		close_fd (fd_A);		// Close kdc_fd
		return;
	}

	fd_t fd_B = logged_in_users [username_B];
	user_crypt crypt_B = reg_user_crypts [username_B];

	string_t nonce_1 = payload_1_vector[2];
	
	long long timestamp_1 = string_to_integer (payload_1_vector[3]);
	if ((get_timestamp() - timestamp_1) > 600) {
		send_negative_ACK (fd_A, "Suspicion of REPLAY ATTACK. Dropping Handshake. (1)");
		close_fd (fd_A);		// Close kdc_fd
		return;
	}

	// send SSK2

	vector_string_t payload_2_vector;

	string_t nonce_1_op;
	operation_nonce_1 (nonce_1, nonce_1_op);

	unsigned char temp_buffer_16 [16];
	int rc = RAND_bytes (temp_buffer_16, 16);
	assert (rc == 1);

	string_t nonce_2 = uchar_to_hex (temp_buffer_16, 16);
	string_t nonce_2_op;
	operation_nonce_2 (nonce_2, nonce_2_op);

	payload_2_vector.push_back (nonce_1_op);
	payload_2_vector.push_back (nonce_2);
	payload_2_vector.push_back (integer_to_string (get_timestamp()));

	string_t dec_payload_2 = join_message_vector_with_lengths (payload_2_vector);
	string_t enc_payload_2;
	ssl_encrypt (dec_payload_2, crypt_A.key, crypt_A.iv, enc_payload_2);
	
	send_composed_message (fd_A, const_enums::KDC, const_enums::SSK2, enc_payload_2);

	// recv SSK3

	vector_string_t client_request_ssk3;
	recv_composed_message (fd_A, client_request_ssk3);
	if (is_negative_ACK (client_request_ssk3)) {
		cout << "Ack Type: NEGATIVE" << endl;
		cout << "Message : " << client_request_ssk3[3] << endl;
		close_fd (fd_A);		// Close kdc_fd
		return;
	}

	string_t enc_payload_3 = client_request_ssk3[3];

	string_t dec_payload_3;
	ssl_decrypt (enc_payload_3, crypt_A.key, crypt_A.iv, dec_payload_3);
	vector_string_t payload_3_vector;
	split_length_appended_message (dec_payload_3, payload_3_vector);

	string_t nonce_2_recv_op = payload_3_vector[1];
	if (compare_nonces (nonce_2_recv_op, nonce_2_op) == false) {
		send_negative_ACK (fd_A, "Nonce doesn't match expected value. Terminating Handshake.");
		close_fd (fd_A);		// Close kdc_fd
		return;
	}

	long long timestamp_3 = string_to_integer (payload_3_vector[2]);
	if ((get_timestamp() - timestamp_3) > 600) {
		send_negative_ACK (fd_A, "Suspicion of REPLAY ATTACK. Dropping Handshake. (2)");
		close_fd (fd_A);		// Close kdc_fd
		return;
	}

	// SSK4

	// Need to derive a random key and iv.
	// Deriving random key from user's password without any reason, using a random salt;
	user_crypt shared_crypt;
	string_t passphrase = registered_users[username_A] + registered_users[username_B];

	ssl_bytes_to_key (passphrase, shared_crypt.key, shared_crypt.iv);
	assert (shared_crypt.key.empty() == false);
	assert (shared_crypt.iv.empty() == false);

	vector_string_t payload_4_vector_A, payload_4_vector_B;
	payload_4_vector_A.push_back (username_B);			payload_4_vector_B.push_back (username_A);
	payload_4_vector_A.push_back (shared_crypt.key);	payload_4_vector_B.push_back (shared_crypt.key);
	payload_4_vector_A.push_back (shared_crypt.iv);		payload_4_vector_B.push_back (shared_crypt.iv);
	
	cout << "SHARED KEY:" << endl;
	ssl_print_bio_dump (shared_crypt.key);
	cout << "SHARED IV:" << endl;
	ssl_print_bio_dump (shared_crypt.iv);
	cout << endl;

	string_t timestamp_4 = integer_to_string (get_timestamp());
	payload_4_vector_A.push_back (timestamp_4);		payload_4_vector_B.push_back (timestamp_4);

	string_t dec_payload_4_A = join_message_vector_with_lengths (payload_4_vector_A);
	string_t dec_payload_4_B = join_message_vector_with_lengths (payload_4_vector_B);
	
	string_t enc_payload_4_A, enc_payload_4_B;
	ssl_encrypt (dec_payload_4_A, crypt_A.key, crypt_A.iv, enc_payload_4_A);
	ssl_encrypt (dec_payload_4_B, crypt_B.key, crypt_B.iv, enc_payload_4_B);

	send_composed_message (fd_A, const_enums::KDC, const_enums::SSK4, enc_payload_4_A);
	send_composed_message (fd_B, const_enums::KDC, const_enums::SSK4, enc_payload_4_B);

	close_fd (fd_A);		// Close kdc_fd
}