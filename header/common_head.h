#include "./sysheads.h"

#ifndef COMMON_H
#define COMMON_H

/*
 *	Type definitions used in the program
 */
typedef int fd_t;
typedef std::string string_t;
typedef std::vector<fd_t> vector_fd_t;
typedef std::vector<string_t> vector_string_t;
typedef std::map<string_t, fd_t> map_string_fd_t;
typedef std::map<string_t, string_t> map_string_string_t;

/*
 *	Custom structures used in the program
 */

/*
 *	Constants used in the program
 */
const string_t SERVER_IPv4_ADDR = "127.0.0.1";
const int SIGNUP_PORT_NUM = 9997;
const int SIGNIN_PORT_NUM = 9998;
const int KDC_PORT_NUM = 9999;
const int FILE_BUFFER_EXTRA_BYTES = 50;

const string_t CTRL_STR[] = {
	"\001",							// SOH (start of heading)
	"\003",							// ETX (end of text) [delimiter]
	"\004"							// EOT (end of transmission)
};
const string_t MSG_TYPE[] = {
	"CMD",
	"ACK",
	"KDC"
};
const string_t CMD_TYPE[] = {
	"REG",
	"LOG_IN",
	"LOG_OUT",
	"WHO",
	"MSG",
	"CREATE_GROUP",
	"JOIN_GROUP",
	"MSG_GROUP",
	"SEND_FILE",
	"RECV_FILE",
	"FILE"
};
const string_t ACK_TYPE[] = {
	"OK",
	"ERR"
};
const string_t KDC_TYPE[] = {
	"SSK1",
	"SSK2",
	"SSK3",
	"SSK4"
};

namespace const_enums
{
	enum ControlStrings {
		ControlStrings_start,
		SOH,
		ETX,
		EOT,
		ControlStrings_end
	};

	enum MessageType {
		MessageType_start,
		CMD,
		ACK,
		KDC,
		MessageType_end
	};

	enum CommandType {
		CommandType_start,
		REG,
		LOG_IN,
		LOG_OUT,
		WHO,
		MSG,
		CREATE_GROUP,
		JOIN_GROUP,
		MSG_GROUP,
		SEND_FILE,
		RECV_FILE,
		FILE,
		CommandType_end
	};

	enum AcknowledgementType {
		AcknowledgementType_start,
		OK,
		ERR,
		AcknowledgementType_end
	};

	enum KDCType {
		KDCType_start,
		SSK1,
		SSK2,
		SSK3,
		SSK4,
		KDCType_end
	};
}

namespace const_maps
{
	static std::map<string_t, const_enums::ControlStrings> CTRL_STR_MAP = {
		{CTRL_STR[0], const_enums::SOH},
		{CTRL_STR[1], const_enums::ETX},
		{CTRL_STR[2], const_enums::EOT}
	};

	static std::map<string_t, const_enums::MessageType> MSG_TYPE_MAP = {
		{MSG_TYPE[0], const_enums::CMD},
		{MSG_TYPE[1], const_enums::ACK},
		{MSG_TYPE[2], const_enums::KDC}
	};

	static std::map<string_t, const_enums::CommandType> CMD_TYPE_MAP = {
		{CMD_TYPE[0], const_enums::REG},
		{CMD_TYPE[1], const_enums::LOG_IN},
		{CMD_TYPE[2], const_enums::LOG_OUT},
		{CMD_TYPE[3], const_enums::WHO},
		{CMD_TYPE[4], const_enums::MSG},
		{CMD_TYPE[5], const_enums::CREATE_GROUP},
		{CMD_TYPE[6], const_enums::JOIN_GROUP},
		{CMD_TYPE[7], const_enums::MSG_GROUP},
		{CMD_TYPE[8], const_enums::SEND_FILE},
		{CMD_TYPE[9], const_enums::RECV_FILE},
		{CMD_TYPE[10], const_enums::FILE}
	};

	static std::map<string_t, const_enums::AcknowledgementType> ACK_TYPE_MAP = {
		{ACK_TYPE[0], const_enums::OK},
		{ACK_TYPE[1], const_enums::ERR}
	};

	static std::map<string_t, const_enums::KDCType> KDC_TYPE_MAP = {
		{KDC_TYPE[0], const_enums::SSK1},
		{KDC_TYPE[1], const_enums::SSK2},
		{KDC_TYPE[2], const_enums::SSK3},
		{KDC_TYPE[3], const_enums::SSK4}
	};
}

// Function Prototypes
// Defined in common_aux.cpp

void close_fd (fd_t &);
void close_fd (fd_t &, vector_fd_t &);
void close_fd (fd_t &, vector_fd_t &, map_string_fd_t &);

void single_split (const string_t, const string_t, int &, int &, string_t &);
void skip_read_by_length (const string_t, int &, int &, string_t &);
void split_message (const string_t, const string_t, vector_string_t &);
void split_length_appended_message (const string_t, vector_string_t &, const string_t delim=CTRL_STR[1]);
void split_to_composed_message (const string_t, vector_string_t &);

void polling_recv_from_fd (fd_t &, string_t &);
void send_to_fd (fd_t &, const string_t);

bool file_exists (const string_t);
void create_file (const string_t);
void read_file (const string_t, string_t &);
void overwrite_file (string_t, string_t);
void append_to_file (string_t, string_t, bool use_newline=false);

bool is_positive_ACK (const vector_string_t);
bool is_negative_ACK (const vector_string_t);

void send_composed_message (fd_t &, const_enums::MessageType, ...);
void send_positive_ACK (fd_t &, string_t);
void send_negative_ACK (fd_t &, string_t);

int recv_ACK (fd_t &);
void recv_composed_message (fd_t &, vector_string_t &);

string_t join_message_vector (const vector_string_t, const string_t delim=CTRL_STR[1]);
string_t join_message_vector_with_lengths (const vector_string_t, const bool use_ends=true, const string_t delim=CTRL_STR[1], const string_t soh=CTRL_STR[0], const string_t eot=CTRL_STR[2]);

long long string_to_integer (const string_t);
string_t integer_to_string (const long long);

long long get_timestamp ();
void LOGGER (const char *, const char *, const char *message=NULL);

void operation_nonce_1 (const string_t, string_t &);
void operation_nonce_2 (const string_t, string_t &);
bool compare_nonces (const string_t, const string_t);

// Generic methods need to be defined in header file or in the same file that they are used in, else they give linker error
template <typename K, typename V>
static bool map_contains_key (std::map<K, V> inp_map, K inp_key) {
	if (inp_map.find (inp_key) == inp_map.end())
		return false;
	return true;
}

template <typename K, typename V>
static bool map_contains_value (std::map<K, V> inp_map, V inp_value) {
	using namespace std;

	typename std::map<K, V>::iterator it;
	for (it = inp_map.begin(); it != inp_map.end(); it++) {
		if ((it -> second) == inp_value)
			return true;
	}

	return false;
}

template <typename K, typename V>
static K map_get_key_from_value (std::map<K, V> inp_map, V inp_value) {
	using namespace std;

	typename std::map<K, V>::iterator it;
	for (it = inp_map.begin(); it != inp_map.end(); it++) {
		if ((it -> second) == inp_value)
			return (it -> first);
	}

	return NULL;
}

#endif