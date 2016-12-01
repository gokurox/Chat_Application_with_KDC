#include "./sysheads.h"
#include "./common_head.h"

#ifndef CLIENT_H
#define CLIENT_H

// Constants
const int MAX_FILE_SIZE_MB = 2;
const int MAX_FILE_SIZE_KB = 3 * 1024;
const int MAX_FILE_SIZE_B = MAX_FILE_SIZE_KB * 1024;

static string_t CLIENT_USERNAME;
static string_t CLIENT_PASSWORD;
static string_t CLIENT_PASSPHRASE_KEY;
static string_t CLIENT_PASSPHRASE_IV;

const string_t CLIENT_INPUT_COMMAND[] = {
	"/register",
	"/login",
	"/logout",
	"/who",
	"/msg",
	"/create_grp",
	"/join_grp",
	"/msg_grp",
	"/send",
	"/recv",
	"/help",
	"/exit"
};

namespace client_const
{
	enum ClientInputCommand {
		ClientInputCommand_start,
		clnt_register,
		clnt_login,
		clnt_logout,
		clnt_who,
		clnt_msg,
		clnt_create_grp,
		clnt_join_grp,
		clnt_msg_grp,
		clnt_send,
		clnt_recv,
		clnt_help,
		clnt_exit,
		ClientInputCommand_end
	};

	static std::map<string_t, ClientInputCommand> CLIENT_INPUT_COMMAND_MAP = {
		{CLIENT_INPUT_COMMAND[0], clnt_register},
		{CLIENT_INPUT_COMMAND[1], clnt_login},
		{CLIENT_INPUT_COMMAND[2], clnt_logout},
		{CLIENT_INPUT_COMMAND[3], clnt_who},
		{CLIENT_INPUT_COMMAND[4], clnt_msg},
		{CLIENT_INPUT_COMMAND[5], clnt_create_grp},
		{CLIENT_INPUT_COMMAND[6], clnt_join_grp},
		{CLIENT_INPUT_COMMAND[7], clnt_msg_grp},
		{CLIENT_INPUT_COMMAND[8], clnt_send},
		{CLIENT_INPUT_COMMAND[9], clnt_recv},
		{CLIENT_INPUT_COMMAND[10], clnt_help},
		{CLIENT_INPUT_COMMAND[11], clnt_exit}
	};
}

// Prototypes
void connect_to_signup_server (fd_t &);
void connect_to_signin_server (fd_t &);
void connect_to_kdc_server (fd_t &);

void process_signup_request (fd_t &, const vector_string_t);
void process_signin_request (fd_t &, const vector_string_t);

void show_prompt (bool endl_before=false);
void help();

#endif