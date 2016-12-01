#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/crypto_head.h"
#include "../header/kdc_head.h"
#include "../header/server_head.h"

using namespace std;

/**
	All the local prototypes described here.
 */

void setup_server_for_signup (fd_t &);
void setup_server_for_signin (fd_t &);
void setup_server_for_kdc (fd_t &);

// Functions implementing specific commands
void register_user (fd_t &, map_string_string_t &, map_string_crypt_t &, const vector_string_t);
void log_in_user (fd_t &, map_string_string_t, map_string_fd_t &, const vector_string_t);
void log_out_user (fd_t &, vector_fd_t &, map_string_fd_t &);
void issue_who (fd_t &, map_string_fd_t);
void msg_user (fd_t &, map_string_fd_t, const vector_string_t);
void create_group (fd_t &, map_string_fd_t, const vector_string_t);
void join_group (fd_t &, map_string_fd_t, const vector_string_t);
void msg_group (fd_t &, map_string_fd_t, const vector_string_t);
void send_file (fd_t &, map_string_fd_t, vector_filestorage_t &, const vector_string_t);
void recv_file (fd_t &, map_string_fd_t, vector_filestorage_t &, const vector_string_t);

// Auxilliary functions
void read_group_users (const string_t, vector_string_t &);

/**
	All above described functions are defined here.
 */

// Server related functions

void server_setup (fd_t &signup_fd, fd_t &signin_fd, fd_t &kdc_fd) {
	setup_server_for_signup (signup_fd);
	setup_server_for_signin (signin_fd);
	setup_server_for_kdc (kdc_fd);
}

void setup_server_for_signup (fd_t &signup_fd)
{
	sockaddr_in signup_sock;
	int rc;

	// Create Registration Socket
	signup_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (signup_fd >= 0);

	// Initialize Socket
	bzero ((char *)(&signup_sock), sizeof (signup_sock));

	signup_sock.sin_family = AF_INET;
	signup_sock.sin_port = htons (SIGNUP_PORT_NUM);
	inet_pton (AF_INET , SERVER_IPv4_ADDR.c_str(), &(signup_sock.sin_addr));

	// Bind sockets to appropriate ports
	rc = bind (signup_fd, (sockaddr *)(&signup_sock), sizeof (signup_sock));
	assert (rc >= 0);

	// Listen on the ports for incoming connections
	rc = listen (signup_fd, MAX_LISTEN_LIMIT);
	assert (rc >= 0);

	cout << "INFO " << "@setup_server_for_signup: " << "Server listening for signup connection @port:" << SIGNUP_PORT_NUM << endl;
}

void setup_server_for_signin (fd_t &signin_fd)
{
	sockaddr_in signin_sock;
	int rc;

	// Create Registration Socket
	signin_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (signin_fd >= 0);

	// Initialize Socket
	bzero ((char *)(&signin_sock), sizeof (signin_sock));

	signin_sock.sin_family = AF_INET;
	signin_sock.sin_port = htons (SIGNIN_PORT_NUM);
	inet_pton (AF_INET , SERVER_IPv4_ADDR.c_str(), &(signin_sock.sin_addr));

	// Bind sockets to appropriate ports
	rc = bind (signin_fd, (sockaddr *)(&signin_sock), sizeof (signin_sock));
	assert (rc >= 0);

	// Listen on the ports for incoming connections
	rc = listen (signin_fd, MAX_LISTEN_LIMIT);
	assert (rc >= 0);

	cout << "INFO " << "@setup_server_for_signin: " << "Server listening for signin connection @port:" << SIGNIN_PORT_NUM << endl;
}

void setup_server_for_kdc (fd_t &kdc_fd)
{
	sockaddr_in kdc_sock;
	int rc;

	// Create Registration Socket
	kdc_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert (kdc_fd >= 0);

	// Initialize Socket
	bzero ((char *)(&kdc_sock), sizeof (kdc_sock));

	kdc_sock.sin_family = AF_INET;
	kdc_sock.sin_port = htons (KDC_PORT_NUM);
	inet_pton (AF_INET , SERVER_IPv4_ADDR.c_str(), &(kdc_sock.sin_addr));

	// Bind sockets to appropriate ports
	rc = bind (kdc_fd, (sockaddr *)(&kdc_sock), sizeof (kdc_sock));
	assert (rc >= 0);

	// Listen on the ports for incoming connections
	rc = listen (kdc_fd, MAX_LISTEN_LIMIT);
	assert (rc >= 0);

	cout << "INFO " << "@setup_server_for_kdc: " << "Server listening for KDC connection @port:" << KDC_PORT_NUM << endl;
}

void add_to_conn_signup_fds (fd_t &signup_fd, vector_fd_t &conn_signup_fds) {
	assert (signup_fd >= 0);
	conn_signup_fds.push_back (signup_fd);
	
	cout << "INFO @add_to_conn_signup_fds: Added FD[" << signup_fd << "]." << endl;
	cout << "INFO @add_to_conn_signup_fds: Sending positive ack" << endl;
	send_positive_ACK (signup_fd, "Connection Accepted. Client OK to Sign Up.");
}

void add_to_conn_signin_fds (fd_t &signin_fd, vector_fd_t &conn_signin_fds) {
	assert (signin_fd >= 0);
	conn_signin_fds.push_back (signin_fd);
	
	cout << "INFO @add_to_conn_signin_fds: Added FD[" << signin_fd << "]." << endl;
	cout << "INFO @add_to_conn_signin_fds: Sending positive ack" << endl;
	send_positive_ACK (signin_fd, "Connection Accepted. Client OK to Sign In.");
}

void add_to_conn_kdc_fds (fd_t &kdc_fd, vector_fd_t &conn_kdc_fds) {
	assert (kdc_fd >= 0);
	conn_kdc_fds.push_back (kdc_fd);
	
	cout << "INFO @add_to_conn_kdc_fds: Added FD[" << kdc_fd << "]." << endl;
	cout << "INFO @add_to_conn_kdc_fds: Sending positive ack" << endl;
	send_positive_ACK (kdc_fd, "Connection Accepted. Client OK to initiate Handshake.");
}

void respond_to_signup_conn (fd_t &fd, vector_fd_t &conn_signup_fds, map_string_string_t &registered_users, map_string_crypt_t &reg_user_crypts)
{
	vector_string_t request_vector;
	recv_composed_message (fd, request_vector);

	switch (const_maps::MSG_TYPE_MAP[request_vector[1]])
	{
		case const_enums::CMD:
		{	switch (const_maps::CMD_TYPE_MAP[request_vector[2]])
			{
				case const_enums::REG:
				{	
					register_user (fd, registered_users, reg_user_crypts, request_vector);
					break;
				}
				default:
				{
					send_negative_ACK (fd, "Invalid Command for signup socket.");
					break;
				}
			}
			break;
		}
		default:
		{
			send_negative_ACK (fd, "Invalid Message Type for signup socket.");
			break;
		}
	}

	close_fd (fd, conn_signup_fds);
}

void respond_to_signin_conn (fd_t &fd, vector_fd_t &conn_signin_fds, map_string_string_t registered_users, map_string_fd_t &logged_in_users, vector_filestorage_t &pending_file_operations)
{
	vector_string_t client_request;
	recv_composed_message (fd, client_request);

	switch (const_maps::MSG_TYPE_MAP[client_request[1]])
	{
		case const_enums::CMD:
			switch (const_maps::CMD_TYPE_MAP[client_request[2]])
			{
				case const_enums::LOG_IN:
					log_in_user (fd, registered_users, logged_in_users, client_request);
					break;
				case const_enums::LOG_OUT:
					log_out_user (fd, conn_signin_fds, logged_in_users);
					break;
				case const_enums::WHO:
					issue_who (fd, logged_in_users);
					break;
				case const_enums::MSG:
					msg_user (fd, logged_in_users, client_request);
					break;
				case const_enums::CREATE_GROUP:
					create_group (fd, logged_in_users, client_request);
					break;
				case const_enums::JOIN_GROUP:
					join_group (fd, logged_in_users, client_request);
					break;
				case const_enums::MSG_GROUP:
					msg_group (fd, logged_in_users, client_request);
					break;
				case const_enums::SEND_FILE:
					send_file (fd, logged_in_users, pending_file_operations, client_request);
					break;
				case const_enums::RECV_FILE:
					recv_file (fd, logged_in_users, pending_file_operations, client_request);
					break;
				default:
					cout << "WARNING " << "@respond_to_signin_conn:" << "Invalid Command." << endl;
					close_fd (fd, conn_signin_fds, logged_in_users);
					break;
			}
			break;
		case const_enums::ACK:
			break;
		case const_enums::KDC:
			break;
		default:
			break;
	}
}

void respond_to_kdc_conn (fd_t &fd, vector_fd_t &conn_kdc_fds, map_string_string_t registered_users, map_string_fd_t &logged_in_users, map_string_crypt_t reg_user_crypts)
{
	vector_string_t client_request;
	recv_composed_message (fd, client_request);

	for (string_t X: client_request)
		cout  << X << endl;

	switch (const_maps::MSG_TYPE_MAP[client_request[1]])
	{
		case const_enums::CMD:
			break;
		case const_enums::ACK:
			break;
		case const_enums::KDC:
		{
			switch (const_maps::KDC_TYPE_MAP[client_request[2]])
			{
				case const_enums::SSK1:
				{
					kdc_keygen_handshake (fd, registered_users, logged_in_users, reg_user_crypts, client_request);
					break;
				}
				default:
					break;
			}
			break;
		}
		default:
			break;
	}
}

// Functions implementing specific commands

void register_user (fd_t &fd, map_string_string_t &registered_users, map_string_crypt_t &reg_user_crypts, const vector_string_t request_vector)
{
	string_t username = request_vector[3];
	string_t password = request_vector[4];

	if (map_contains_key (registered_users, username))
	{
		send_negative_ACK (fd, "Requested username already exists.");
		return;
	}
	else 
	{
		string_t filepath = DATABASE_DIR + USERPASS_FILE;
		string_t to_append = username + USERPASS_SEPERATOR + password;
		append_to_file (filepath, to_append, true);

		// Add to map
		registered_users [username] = password;
		generate_user_crypt (username, registered_users, reg_user_crypts);

		send_positive_ACK (fd, "User registration successful.");
	}
}

void log_in_user (fd_t &fd, map_string_string_t registered_users, map_string_fd_t &logged_in_users, const vector_string_t client_request)
{
	string username = client_request[3];

	if (map_contains_key (registered_users, username) == false) {
		send_negative_ACK (fd, "User is not registered.");
		return;
	}

	if (map_contains_key (logged_in_users, username) || map_contains_value (logged_in_users, fd)) {
		send_negative_ACK (fd, "User is already logged in.");
		return;
	}

	string password = client_request[4];

	if (registered_users[username].compare (password) != 0) {
		send_negative_ACK (fd, "Credentials do not validate.");
		return;
	}

	logged_in_users [username] = fd;
	send_positive_ACK (fd, "User successfully logged in.");
}

void log_out_user (fd_t &fd, vector_fd_t &conn_signin_fds, map_string_fd_t &logged_in_users)
{
	if (map_contains_value (logged_in_users, fd) == false) {
		send_negative_ACK (fd, "User is not logged in.");
		return;
	}

	send_positive_ACK (fd, "User successfully logged out.");

	close_fd (fd, conn_signin_fds, logged_in_users);
	assert (fd == -1);
}

void issue_who (fd_t &fd, map_string_fd_t logged_in_users)
{
	if (map_contains_value (logged_in_users, fd) == false) {
		send_negative_ACK (fd, "User is not logged in.");
		return;
	}

	string_t online_users_string;
	vector_string_t online_users;

	map_string_fd_t::iterator it;
	for (it = logged_in_users.begin(); it != logged_in_users.end(); it++) {
		online_users.push_back (it -> first);
	}

	online_users_string = join_message_vector_with_lengths (online_users, true, "|", ">", "<");
	send_positive_ACK (fd, online_users_string);
}

// -------------> Checked

void msg_user (fd_t &from_fd, map_string_fd_t logged_in_users, vector_string_t client_request)
{
	// SOH,CMD,MSG,FROM,TO,MSG

	if (map_contains_value (logged_in_users, from_fd) == false) {
		send_negative_ACK (from_fd, "User is not logged in.");
		return;
	}

	string_t from_uname = client_request[3];
	string_t from_uname_ver = map_get_key_from_value (logged_in_users, from_fd);
	if (from_uname_ver.compare (from_uname) != 0) {
		send_negative_ACK (from_fd, "Given from_uname does not match the logged in user.");
		return;
	}

	string_t to_uname = client_request[4];

	if (map_contains_key (logged_in_users, to_uname) == false) {
		send_negative_ACK (from_fd, "Receiver is not Online.");
		return;
	}

	string_t user_message = client_request[5];

	fd_t to_fd = logged_in_users [to_uname];
	send_composed_message (to_fd, const_enums::CMD, const_enums::MSG, from_uname, to_uname, user_message);

	send_positive_ACK (from_fd, "Message delivered successfully.");
}

void create_group (fd_t &fd, map_string_fd_t logged_in_users, const vector_string_t client_request)
{
	if (map_contains_value (logged_in_users, fd) == false) {
		send_negative_ACK (fd, "User is not logged in.");
		return;
	}

	string groupname = client_request[3];
	string filepath = GROUPS_DIR + groupname;
	string groupdb_filepath = DATABASE_DIR + GROUPS_FILE;

	if (file_exists (filepath)) {
		send_negative_ACK (fd, "Group already exists.");
		return;
	}

	create_file (filepath);
	append_to_file (groupdb_filepath, groupname, true);

	send_positive_ACK (fd, "Group successfully created.");
}

void join_group (fd_t &fd, map_string_fd_t logged_in_users, const vector_string_t client_request)
{
	if (map_contains_value (logged_in_users, fd) == false) {
		send_negative_ACK (fd, "User is not logged in.");
		return;
	}

	string groupname = client_request[3];
	string filepath = GROUPS_DIR + groupname;

	if (!file_exists (filepath)) {
		send_negative_ACK (fd, "Group does not exist.");
		return;
	}

	string username = map_get_key_from_value (logged_in_users, fd);

	vector_string_t group_users;
	read_group_users (filepath, group_users);

	for (string_t grp_member: group_users) {
		if (grp_member.compare (username) == 0) {
			send_negative_ACK (fd, "User is already in the group.");
			return;
		}
	}

	append_to_file (filepath, username, true);
	send_positive_ACK (fd, "User successfully added to the group.");
}

void msg_group (fd_t &fd, map_string_fd_t logged_in_users, const vector_string_t client_request)
{
	if (map_contains_value (logged_in_users, fd) == false) {
		send_negative_ACK (fd, "User is not logged in.");
		return;
	}

	string_t groupname = client_request[3];
	string filepath = GROUPS_DIR + groupname;
	
	if (!file_exists (filepath)) {
		send_negative_ACK (fd, "Group does not exist.");
		return;
	}
	
	string_t from_uname = map_get_key_from_value (logged_in_users, fd);
	string_t user_message = client_request[4];
	
	vector_string_t group_users;
	read_group_users (filepath, group_users);

	bool is_member = false;
	for (string_t grp_member: group_users) {
		if (grp_member.compare (from_uname) == 0) {
			is_member = true;
			break;
		}
	}

	if (!is_member) {
		send_negative_ACK (fd, "User is not a member of the group.");
		return;
	}
	else {

		for (string_t to_uname: group_users) {
			if (to_uname.compare (from_uname) == 0) {
				continue;
			}

			if (map_contains_key (logged_in_users, to_uname)) {
				fd_t to_fd = logged_in_users [to_uname];
				send_composed_message (to_fd, const_enums::CMD, const_enums::MSG, from_uname, to_uname, user_message);
			}
		}
		
		send_positive_ACK (fd, "Message has been sent to all online members of the group.");
	}
}

void send_file (fd_t &fd, map_string_fd_t logged_in_users, vector_filestorage_t &pending_files, const vector_string_t client_request)
{
	if (map_contains_value (logged_in_users, fd) == false) {
		send_negative_ACK (fd, "User is not logged in.");
		return;
	}

	file_storage saved_file;

	saved_file.from = client_request[3];
	string_t from_ver = map_get_key_from_value (logged_in_users, fd);
	if (saved_file.from.compare (from_ver) != 0) {
		send_negative_ACK (fd, "Given from_uname does not match the logged in user.");
		return;
	}

	saved_file.to = client_request[4];
	saved_file.filepath = FILES_DIR + saved_file.from + "2" + saved_file.to;

	send_positive_ACK (fd, "User OK to send file");

	vector_string_t client_response;
	recv_composed_message (fd, client_response);
	
	if (is_negative_ACK (client_response)) {
		cout << "INFO @send_file: User declined to send file" << endl;
		return;
	}

	if (client_response[1].compare (MSG_TYPE[0]) == 0) {			// CMD
		if (client_response[2].compare (CMD_TYPE[10]) == 0) {		// FILE
			saved_file.filename = client_response[3];

			overwrite_file (saved_file.filepath, client_response[4]);
			stat (saved_file.filepath.c_str(), &(saved_file.file_info));
		}
		else {
			cout << "INFO @send_file: Invalid command. FILE expected." << endl;
			send_negative_ACK (fd, "Invalid command. FILE expected.");
			return;
		}
	}

	pending_files.push_back (saved_file);

	if (map_contains_key (logged_in_users, saved_file.to)) {
		fd_t to_fd = logged_in_users [saved_file.to];
		send_composed_message (to_fd, const_enums::CMD, const_enums::SEND_FILE, saved_file.from, saved_file.to);
		send_positive_ACK (fd, "FILE RECV request sent to receiver");
	}
	else {
		send_positive_ACK (fd, "FILE RECV request not sent to receiver. Receiver is offline. File saved at server.");
	}
}

void recv_file (fd_t &fd, map_string_fd_t logged_in_users, vector_filestorage_t &pending_files, const vector_string_t request)
{
	if (map_contains_value (logged_in_users, fd) == false) {
		send_negative_ACK (fd, "User is not logged in.");
		return;
	}

	file_storage saved_file;

	bool file_found = false;
	vector_filestorage_t::iterator curr_it = pending_files.begin();

	for (int i = 0; i < pending_files.size (); i++, curr_it++) {
		if (pending_files[i].from.compare (request[3]) == 0) {
			if (pending_files[i].to.compare (request[4]) == 0) {
				saved_file = pending_files[i];
				file_found = true;
				break;
			}
		}
	}

	if (!file_found) {
		send_negative_ACK (fd, "No pending file found at server.");
		return;
	}
	send_positive_ACK (fd, "User OK to RECV file");

	string file_to_send;
	read_file (saved_file.filepath, file_to_send);

	send_composed_message (fd, const_enums::CMD, const_enums::FILE, saved_file.filename, file_to_send);
	pending_files.erase (curr_it);
	int rc = remove (saved_file.filepath.c_str());
	assert (rc == 0);
}


// Auxilliary functions

void read_registered_users (map_string_string_t &registered_users)
{
	string filepath = DATABASE_DIR + USERPASS_FILE;

	if (!file_exists (filepath)) {
		create_file (filepath);
		return;
	}

	string file;
	read_file (filepath, file);
	istringstream sstream (file);

	string uname, pword;
	while (sstream >> uname >> pword) {
		registered_users[uname] = pword;
		uname.clear ();
		pword.clear ();
	}
}

void read_group_users (const string_t filepath, vector_string_t &group_users)
{
	group_users.clear();
	
	string_t file;
	read_file (filepath, file);

	istringstream sstream (file);
	string_t uname;

	while (sstream >> uname) {
		group_users.push_back (uname);
		uname.clear ();
	}
}
