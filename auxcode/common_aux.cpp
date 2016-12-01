#include "../header/sysheads.h"
#include "../header/common_head.h"

using namespace std;

// Functions related to file descriptors
void close_fd (fd_t &fd)
{
	int rc;
	rc = close (fd);
	assert (rc == 0);
	cout << "INFO " << "@close_fd: " << "Closed FD [" << fd << "]." << endl;
	fd = -1;
}

void close_fd (fd_t &fd, vector_fd_t &fd_list)
{
	int rc;
	
	rc = close (fd);
	vector_fd_t::iterator it;
	for (it = fd_list.begin(); it != fd_list.end(); it++) {
		if ((*it) == fd) {
			fd_list.erase (it);
			break;
		}
	}

	assert (rc == 0);
	cout << "INFO " << "@close_fd: " << "Closed FD [" << fd << "]." << endl;
	fd = -1;
}

void close_fd (fd_t &fd, vector_fd_t &fd_list, map_string_fd_t &fd_map)
{
	int rc;

	rc = close (fd);

	vector_fd_t::iterator it;
	for (it = fd_list.begin(); it != fd_list.end(); it++) {
		if ((*it) == fd) {
			fd_list.erase (it);
			break;
		}
	}

	map_string_fd_t::iterator it2;
	for (it2 = fd_map.begin(); it2 != fd_map.end(); it2++) {
		if ((it2 -> second) == fd) {
			fd_map.erase (it2);
			break;
		}
	}

	assert (rc == 0);
	cout << "INFO " << "@close_fd: " << "Closed FD [" << fd << "]." << endl;
	fd = -1;
}

// Functions related to Message interpretation

void split_message (const string_t str, const string_t delim, vector_string_t &out_buffer)
{
	assert (str.empty() == false);

	out_buffer.clear ();
	out_buffer.shrink_to_fit();
	string_t substring;
	int spos, epos;

	spos = 0;
	epos = str.find (delim);
	while (epos != string_t::npos) {
		substring.clear();
		substring.shrink_to_fit();
		substring.reserve (epos - spos);
		substring = str.substr (spos, epos - spos);

		if (!substring.empty()) {
			out_buffer.push_back (substring);
		}

		spos = epos +1;
		epos = str.find (delim, spos);
	}
	epos = str.size();
	substring.clear();
	substring.shrink_to_fit();
	substring.reserve (epos - spos);
	substring = str.substr (spos, epos - spos);
		
	if (!substring.empty()) {
		out_buffer.push_back (substring);
	}
}

void split_length_appended_message (const string_t inp_string, vector_string_t &out_message, const string_t delim)
{
	int spos, epos;
	string_t substring;

	out_message.clear();

	spos = 0;
	epos = 0;
	
	single_split (inp_string, delim, spos, epos, substring);
	if (substring.empty() == false)
			out_message.push_back (substring);

	while (epos != string_t::npos)
	{
		single_split (inp_string, delim, spos, epos, substring);

		if (epos != string_t::npos)
			skip_read_by_length (inp_string, spos, epos, substring);

		if (substring.empty() == false)
			out_message.push_back (substring);
	}

	assert (out_message.size() != 0);
}

void single_split (const string_t inp_message, const string_t delim, int &spos, int &epos, string_t &substring)
{
	epos = inp_message.find (delim, spos);

	substring.clear();
	substring.shrink_to_fit();
	if (epos != string_t::npos) {
		substring.reserve (epos - spos);
		substring = inp_message.substr (spos, epos - spos);
	}
	else {
		substring.reserve (inp_message.size() - spos);
		substring = inp_message.substr (spos, inp_message.size() - spos);
	}

	spos = epos +1;
}

void skip_read_by_length (const string_t inp_message, int &spos, int &epos, string_t &substring)
{
	assert (substring.empty() == false);
	assert (atoll (substring.c_str()) > 0);
	
	long long len = atoll (substring.c_str());
	
	substring.clear();
	substring.shrink_to_fit();
	substring.reserve (len);
	substring = inp_message.substr (spos, len);
	assert (substring.empty() == false);

	spos += len +1;
}


void split_to_composed_message (const string_t inp_message, vector_string_t &out_command)
{
	string_t delim = CTRL_STR[1];
	string_t substring;
	int spos, epos;

	out_command.clear();
	out_command.shrink_to_fit();

	// Get first three blocks manually :: SOH | MSG_TYPE | CMD/ACK/KDC TYPE
	spos = 0;
	epos = 0;

	single_split (inp_message, delim, spos, epos, substring);
	assert (epos != string_t::npos);
	if (substring.empty() == false)
		out_command.push_back (substring);

	single_split (inp_message, delim, spos, epos, substring);
	assert (epos != string_t::npos);
	if (substring.empty() == false)
		out_command.push_back (substring);

	single_split (inp_message, delim, spos, epos, substring);
	assert (epos != string_t::npos);
	if (substring.empty() == false)
		out_command.push_back (substring);		

	// Act according to message now!
	// Also check validity
	assert (out_command[0].compare (CTRL_STR[0]) == 0);		// out_command[0] == SOH

	assert (map_contains_key (const_maps::MSG_TYPE_MAP, out_command[1]) == true);

	switch (const_maps::MSG_TYPE_MAP[out_command[1]])
	{
		case const_enums::CMD:
		{
			assert (map_contains_key (const_maps::CMD_TYPE_MAP, out_command[2]) == true);

			switch (const_maps::CMD_TYPE_MAP[out_command[2]])
			{
				case const_enums::REG:
				{
					single_split (inp_message, delim, spos, epos, substring);	// uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// pword_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// pword
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::LOG_IN:
				{
					single_split (inp_message, delim, spos, epos, substring);	// uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// pword_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// pword
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::LOG_OUT:
				{
					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::WHO:
				{
					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::MSG:
				{
					single_split (inp_message, delim, spos, epos, substring);	// from_uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// from_uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// to_uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// to_uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// msg_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// msg
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::CREATE_GROUP:
				{
					single_split (inp_message, delim, spos, epos, substring);	// groupname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// groupname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::JOIN_GROUP:
				{
					single_split (inp_message, delim, spos, epos, substring);	// groupname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// groupname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::MSG_GROUP:
				{
					single_split (inp_message, delim, spos, epos, substring);	// groupname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// groupname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// msg_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// msg
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::SEND_FILE:
				{
					single_split (inp_message, delim, spos, epos, substring);	// from_uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// from_uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// to_uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// to_uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::RECV_FILE:
				{
					single_split (inp_message, delim, spos, epos, substring);	// from_uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// from_uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// to_uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// to_uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::FILE:
				{
					single_split (inp_message, delim, spos, epos, substring);	// filename_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// filename
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// file_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// file
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				default:
					return;
			}
			break;
		}
		case const_enums::ACK:
		{
			assert (map_contains_key (const_maps::ACK_TYPE_MAP, out_command[2]) == true);

			switch (const_maps::ACK_TYPE_MAP[out_command[2]])
			{
				case const_enums::OK:
				{
					single_split (inp_message, delim, spos, epos, substring);	// msg_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// msg
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::ERR:
				{
					single_split (inp_message, delim, spos, epos, substring);	// msg_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// msg
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				default:
					return;
			}
			break;
		}
		case const_enums::KDC:
		{
			assert (map_contains_key (const_maps::KDC_TYPE_MAP, out_command[2]) == true);

			switch (const_maps::KDC_TYPE_MAP[out_command[2]])
			{
				case const_enums::SSK1:
				{
					single_split (inp_message, delim, spos, epos, substring);	// from_uname_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// from_uname
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// payload_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// payload
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::SSK2:
				{
					single_split (inp_message, delim, spos, epos, substring);	// payload_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// payload
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);
					
					break;
				}
				case const_enums::SSK3:
				{
					single_split (inp_message, delim, spos, epos, substring);	// payload_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// payload
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				case const_enums::SSK4:
				{
					single_split (inp_message, delim, spos, epos, substring);	// payload_len
					assert (epos != string_t::npos);
					skip_read_by_length (inp_message, spos, epos, substring);	// payload
					out_command.push_back (substring);

					single_split (inp_message, delim, spos, epos, substring);	// EOT
					assert (epos == string_t::npos);
					if (substring.empty() == false)
						out_command.push_back (substring);

					break;
				}
				default:
					return;
			}
			break;
		}
		default:
			return;
	}

	assert (out_command[out_command.size() -1].compare (CTRL_STR[2]) == 0);

	cout << "INFO " << "@split_to_composed_message: " << "Received Command:" << endl;

	vector_string_t::const_iterator sub_beg = out_command.begin() +1;
	vector_string_t::const_iterator sub_end = out_command.end() -1;
	vector_string_t sub_out_command (sub_beg, sub_end);
	string_t out_command_printable = out_command[0] + " | " + join_message_vector_with_lengths (sub_out_command, false, " | ") + " | " + out_command[out_command.size() -1];
	
	cout << out_command_printable << endl;
	cout.flush();
}

// Functions related to Socket file descriptors

void polling_recv_from_fd (fd_t &fd, string_t &out_buffer)
{
	int buffer_size = 4100;
	char read_buffer [buffer_size];
	struct pollfd ufds[1];
	bool read_at_least_once = false;
	int rv, rpc, rc;

	ufds[0].fd = fd;
	ufds[0].events = POLLIN;		// check if data available to recv

	out_buffer.clear();

	rv = poll (ufds, 1, -1);
	bool poll_error = (ufds[0].revents & POLLERR) || (ufds[0].revents & POLLHUP) || (ufds[0].revents & POLLNVAL);
	assert (poll_error == false);
	assert (rv >= 0);

	bzero (read_buffer, buffer_size);
	while ((rpc = recv (fd, read_buffer, buffer_size, MSG_PEEK | MSG_DONTWAIT)) > 0) {
		rc = recv (fd, read_buffer, buffer_size, MSG_DONTWAIT);
		read_at_least_once = true;
		out_buffer += read_buffer;
		bzero (read_buffer, buffer_size);
	}

	if (!read_at_least_once) {
		cout << "ERROR " << "@polling_recv_from_fd: " << "Loop broken without reading even once. Closing FD[" << fd << "]." << endl;
		close_fd (fd);
	}
}

void send_to_fd (fd_t &fd, const string_t data_to_send)
{
	int rv, rc;

	rc = send (fd, (void *) data_to_send.c_str(), data_to_send.size(), 0);
	assert (rc >= 0);
}

// Functions related to file manipulation

bool file_exists (const string_t filepath)
{
	struct stat file_info;
	int rc = stat (filepath.c_str(), &file_info);
	return (rc == 0);
}

void create_file (const string_t filepath)
{
	if (file_exists (filepath))
		return;

	fstream fs;
	fs.open(filepath.c_str(), ios::out);
	fs.close();

	assert (file_exists (filepath) == true);
}

void read_file (const string_t filepath, string_t &op_buffer)
{
	op_buffer.clear ();
	op_buffer.shrink_to_fit ();

	assert (file_exists (filepath) == true);

	struct stat file_info;
	stat (filepath.c_str(), &file_info);
	op_buffer.reserve (file_info.st_size + FILE_BUFFER_EXTRA_BYTES);

	fd_t fd = open (filepath.c_str(), O_RDONLY);
	assert (fd >= 0);

	int rc;
	int buf_size = 1024;
	char read_buf[buf_size];

	bzero (read_buf, buf_size);
	while ((rc = read (fd, read_buf, buf_size -1)) > 0) {
		read_buf[strlen (read_buf)] = '\0';
		op_buffer = op_buffer + string (read_buf);
		bzero (read_buf, buf_size);
	}
	close (fd);
}

void overwrite_file (string_t filepath, string_t data)
{
	if (!file_exists (filepath)) {
		create_file (filepath);
	}

	fstream fs;
	fs.open (filepath, ios::out);
	fs << data;
	fs.close ();
}

void append_to_file (string_t filepath, string_t data, bool use_newline)
{
	if (!file_exists (filepath)) {
		create_file (filepath);
	}

	fstream fs;
	fs.open (filepath, ios::out|ios::app);
	
	if (use_newline)
		fs << data << endl;
	else
		fs << data;

	fs.close ();
}

void send_composed_message (fd_t &fd, const_enums::MessageType message_type, ...)
{
	va_list vararg_list;
	vector_string_t out_command;

	out_command.clear ();
	out_command.push_back (CTRL_STR[0]);		// SOH
	
	assert (map_contains_value (const_maps::MSG_TYPE_MAP, message_type) == true);
	out_command.push_back
			(map_get_key_from_value (const_maps::MSG_TYPE_MAP, message_type));

	va_start (vararg_list, message_type);		// Initialize vararg_list

	int expected_args;
	string_t arg;

	switch (message_type)
	{
		case const_enums::CMD:
		{
			const_enums::CommandType command_type = (const_enums::CommandType) va_arg (vararg_list, int);
			assert (map_contains_value (const_maps::CMD_TYPE_MAP, command_type) == true);
			out_command.push_back
					(map_get_key_from_value (const_maps::CMD_TYPE_MAP, command_type));

			switch (command_type)
			{
				case const_enums::REG:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::LOG_IN:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::LOG_OUT:
				{
					expected_args = 0;
					break;
				}
				case const_enums::WHO:
				{
					expected_args = 0;
					break;
				}
				case const_enums::MSG:
				{
					expected_args = 3;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::CREATE_GROUP:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::JOIN_GROUP:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::MSG_GROUP:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::SEND_FILE:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::RECV_FILE:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::FILE:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				default:
					return;
			}
			break;
		}
		case const_enums::ACK:
		{
			const_enums::AcknowledgementType ack_type = (const_enums::AcknowledgementType) va_arg (vararg_list, int);
			assert (map_contains_value (const_maps::ACK_TYPE_MAP, ack_type) == true);
			out_command.push_back
					(map_get_key_from_value (const_maps::ACK_TYPE_MAP, ack_type));

			switch (ack_type)
			{
				case const_enums::OK:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				case const_enums::ERR:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}
					break;
				}
				default:
					return;
			}
			break;
		}
		case const_enums::KDC:
		{
			const_enums::KDCType kdc_type = (const_enums::KDCType) va_arg (vararg_list, int);
			assert (map_contains_value (const_maps::KDC_TYPE_MAP, kdc_type) == true);
			out_command.push_back
					(map_get_key_from_value (const_maps::KDC_TYPE_MAP, kdc_type));

			switch (kdc_type)
			{
				case const_enums::SSK1:
				{
					expected_args = 2;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}

					break;
				}
				case const_enums::SSK2:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}

					break;
				}
				case const_enums::SSK3:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}

					break;
				}
				case const_enums::SSK4:
				{
					expected_args = 1;
					for (int i = 0; i < expected_args; i++)
					{
						arg.clear ();
						arg = string_t (va_arg (vararg_list, string_t));
						arg.shrink_to_fit();

						out_command.push_back (integer_to_string (arg.size()));
						out_command.push_back (arg);
					}

					break;
				}
				default:
					return;
			}
			break;
		}
		default:
			return;
	}

	va_end (vararg_list);					// Cleanup list

	out_command.push_back (CTRL_STR[2]);	// EOT
	
	string_t out_command_string = join_message_vector (out_command);	
	string_t out_command_printable = join_message_vector (out_command, " | ");
	cout << "INFO " << "@send_composed_message: " << "Sending command to fd [" << fd << "]:" << endl;
	cout << out_command_printable << endl;

	send_to_fd (fd, out_command_string);
}

void send_positive_ACK (fd_t &fd, string_t description) {
	string_t desc_length = integer_to_string (description.size());
	
	vector_string_t out_ack;
	out_ack.push_back (CTRL_STR[0]);			// SOH
	out_ack.push_back (MSG_TYPE[1]);			// ACK
	out_ack.push_back (ACK_TYPE[0]);			// OK
	out_ack.push_back (desc_length);			// description length
	out_ack.push_back (description);			// description
	out_ack.push_back (CTRL_STR[2]);			// EOT
	string_t out_ack_string = join_message_vector (out_ack);

	send_to_fd (fd, out_ack_string);
}

void send_negative_ACK (fd_t &fd, string_t description) {
	string_t desc_length = integer_to_string (description.size());
	
	vector_string_t out_ack;
	out_ack.push_back (CTRL_STR[0]);			// SOH
	out_ack.push_back (MSG_TYPE[1]);			// ACK
	out_ack.push_back (ACK_TYPE[1]);			// ERR
	out_ack.push_back (desc_length);			// description length
	out_ack.push_back (description);			// description
	out_ack.push_back (CTRL_STR[2]);			// EOT
	string_t out_ack_string = join_message_vector (out_ack);

	send_to_fd (fd, out_ack_string);
}

int recv_ACK (fd_t &fd)
{
	string_t read_response;
	polling_recv_from_fd (fd, read_response);
	assert (read_response.empty() == false);

	vector_string_t response_vector;
	split_to_composed_message (read_response, response_vector);
	assert (response_vector.empty() == false);

	if (is_positive_ACK (response_vector))
	{
		cout << "Ack Type: POSITIVE" << endl;
		cout << "Message : " << response_vector[3] << endl;
		return 1;
	}
	else
	if (is_negative_ACK (response_vector))
	{
		cout << "Ack Type: NEGATIVE" << endl;
		cout << "Message : " << response_vector[3] << endl;
		return 2;
	}

	return 0;
}

void recv_composed_message (fd_t &fd, vector_string_t &response_vector)
{
	string_t read_response;
	polling_recv_from_fd (fd, read_response);
	assert (read_response.empty() == false);

	split_to_composed_message (read_response, response_vector);
	assert (response_vector.empty() == false);
}

bool is_positive_ACK (const vector_string_t message) {
	if (message[0] == CTRL_STR[0])
		if (message[1] == MSG_TYPE[1])
			if (message[2] == ACK_TYPE[0])
				return true;
			else
				return false;
		else
			return false;

	return false;
}

bool is_negative_ACK (const vector_string_t message) {
	if (message[0] == CTRL_STR[0])
		if (message[1] == MSG_TYPE[1])
			if (message[2] == ACK_TYPE[1])
				return true;
			else
				return false;
		else
			return false;

	return false;
}

// Auxilliary Functions

string_t join_message_vector (const vector_string_t inp_vector, const string_t delim) {
	size_t reserve_size = 0;
	int inp_vector_size = inp_vector.size();
	string_t message;

	for (int i = 0; i < inp_vector_size; i++) {
		reserve_size += inp_vector[i].size();
	}

	message.reserve (reserve_size + inp_vector_size);

	for (int i = 0; i < inp_vector_size; i++) {
		message += inp_vector[i];
		if (i != inp_vector_size -1)
			message += delim;					// ETX
	}

	message.shrink_to_fit ();
	return message;
}

string_t join_message_vector_with_lengths (const vector_string_t inp_vector, const bool use_ends, const string_t delim, const string_t soh, const string_t eot) {
	size_t reserve_size = 0;
	int inp_vector_size = inp_vector.size();
	string_t message;
	bool append_length = true;

	for (int i = 0; i < inp_vector_size; i++) {
		reserve_size += inp_vector[i].size();
		if (append_length == true)
			reserve_size += (integer_to_string (inp_vector[i].size())).size();
	}

	message.reserve (reserve_size + (2 * delim.size() * (inp_vector_size + 2)) + soh.size() + eot.size());

	if (use_ends) {
		message += soh;
		message += delim;
	}

	for (int i = 0; i < inp_vector_size; i++) {
		if (append_length == true) {
			message += integer_to_string (inp_vector[i].size());
			message += delim;
		}

		message += inp_vector[i];

		if (i != inp_vector_size -1)
			message += delim;					// ETX
	}

	if (use_ends) {
		message += delim;
		message += eot;
	}

	message.shrink_to_fit ();
	return message;
}

long long string_to_integer (const string_t inp_string)
{
	std::stringstream sstream;
	long long out_integer;

	sstream << inp_string;
	sstream >> out_integer;
	return out_integer;
}

string_t integer_to_string (const long long inp_integer)
{
	std::stringstream sstream;
	string_t out_string;

	sstream << inp_integer;
	sstream >> out_string;
	return out_string;
}

long long get_timestamp () {
	return (long long) time (NULL);
}

void operation_nonce_1 (const string_t in_nonce, string_t &out_nonce)
{
	out_nonce = in_nonce;
}

void operation_nonce_2 (const string_t in_nonce, string_t &out_nonce)
{
	out_nonce = in_nonce;
}

bool compare_nonces (const string_t nonce_1, const string_t nonce_2)
{
	int size1 = nonce_1.size();
	int size2 = nonce_2.size();

	if (size1 != size2)
		return false;

	for (int i = 0; i < size1; i++)
	{
		unsigned char X, Y;
		X = (unsigned char) nonce_1[i];
		Y = (unsigned char) nonce_2[i];

		if ((X ^ Y) != 0)
			return false;
	}
	return true;
}