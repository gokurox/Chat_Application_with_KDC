#include "./sysheads.h"
#include "./common_head.h"

#ifndef SERVER_H
#define SERVER_H

struct file_storage
{
	string_t filepath;
	string_t filename;
	string_t from;
	string_t to;
	struct stat file_info;
};

typedef std::vector<file_storage> vector_filestorage_t;

// Constants
const string_t DATABASE_DIR = "../database/private/";
const string_t GROUPS_DIR = "../database/groups/";
const string_t FILES_DIR = "../files/";
const string_t GROUPS_FILE = "groupnames.txt";
const string_t USERPASS_FILE = "userdata.txt";
const string_t USERPASS_SEPERATOR = " ";

const int MAX_LISTEN_LIMIT = 2048;

// Prototypes
void server_setup (fd_t &, fd_t &, fd_t &);
void add_to_conn_signup_fds (fd_t &, vector_fd_t &);
void add_to_conn_signin_fds (fd_t &, vector_fd_t &);
void add_to_conn_kdc_fds (fd_t &, vector_fd_t &);
void respond_to_signup_conn (fd_t &, vector_fd_t &, map_string_string_t &, map_string_crypt_t &);
void respond_to_signin_conn (fd_t &, vector_fd_t &, map_string_string_t, map_string_fd_t &, vector_filestorage_t &);
void respond_to_kdc_conn (fd_t &, vector_fd_t &, map_string_string_t, map_string_fd_t &, map_string_crypt_t);

void read_registered_users (map_string_string_t &);

#endif