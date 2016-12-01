#include "../header/sysheads.h"
#include "../header/common_head.h"
#include "../header/crypto_head.h"
#include "../header/kdc_head.h"
#include "../header/server_head.h"

void run_server ();

int main() 
{
	ssl_setup();
	run_server ();
	ssl_cleanup();
	return 0;
}

void run_server ()
{
	using namespace std;

	// Variables required for Initializing server
	fd_t
		signup_sockfd,					// Registration Port Server File Descriptor
		signin_sockfd,					// Login Port File Server Descriptor
		kdc_sockfd;

	// Initialize server and setup to listen to the concerned ports
	server_setup (signup_sockfd, signin_sockfd, kdc_sockfd);
	assert ((signup_sockfd >= 0) && (signin_sockfd >= 0) && (kdc_sockfd >= 0));

	// Variables required for Server Functioning
	fd_t max_fd;
	fd_set sockfd_set;				// Set for open file descriptors
	
	vector_fd_t
		conn_signup_fds,			// All connected register socket fds
		conn_signin_fds,			// All connected login socket fds
		conn_kdc_fds;

	map_string_string_t registered_users;			// Registered users --> passwords
	map_string_crypt_t reg_user_crypts;

	read_registered_users (registered_users);
	generate_registered_user_crypts (registered_users, reg_user_crypts);

	map_string_fd_t logged_in_users;				// All logged in users (validated) with their fds

	vector_filestorage_t pending_file_operations;

	while (true) {
		// Clear the Socket Set
		FD_ZERO (&sockfd_set);

		// Add Registration and Login Sockets to set
		FD_SET (signup_sockfd, &sockfd_set);
		FD_SET (signin_sockfd, &sockfd_set);
		FD_SET (kdc_sockfd, &sockfd_set);

		max_fd = max (signup_sockfd, signin_sockfd);
		max_fd = max (kdc_sockfd, max_fd);

		// Add all registration sockets to sockfd_set
		for (fd_t fd: conn_signup_fds) {
			if (fd > 0) {
				FD_SET (fd, &sockfd_set);
				max_fd = max (fd, max_fd);
			}
			// else {
			// 	close_fd (fd, conn_signup_fds);
			// }
		}

		// Add all login sockets to sockfd_set
		for (fd_t fd: conn_signin_fds) {
			if (fd > 0) {
				FD_SET (fd, &sockfd_set);
				max_fd = max (fd, max_fd);
			}
			// else {
			// 	close_fd (fd, conn_signin_fds);
			// }
		}

		// Add all kdc sockets to sockfd_set
		for (fd_t fd: conn_kdc_fds) {
			if (fd > 0) {
				FD_SET (fd, &sockfd_set);
				max_fd = max (fd, max_fd);
			}
			// else {
			// 	close_fd (fd, conn_kdc_fds);
			// }
		}

		select (max_fd +1, &sockfd_set, NULL, NULL, NULL);

		if (FD_ISSET (signup_sockfd, &sockfd_set)) {
			fd_t fd = accept (signup_sockfd, NULL, NULL);
			cout << "INFO " << "@run_server: " << "Accepted a signup connection" << endl;
			add_to_conn_signup_fds (fd, conn_signup_fds);
		}

		if (FD_ISSET (signin_sockfd, &sockfd_set)) {
			fd_t fd = accept (signin_sockfd, NULL, NULL);
			cout << "INFO " << "@run_server: " << "Accepted a signin connection" << endl;
			add_to_conn_signin_fds (fd, conn_signin_fds);
		}

		if (FD_ISSET (kdc_sockfd, &sockfd_set)) {
			fd_t fd = accept (kdc_sockfd, NULL, NULL);
			cout << "INFO " << "@run_server: " << "Accepted a kdc connection" << endl;
			add_to_conn_kdc_fds (fd, conn_kdc_fds);
		}
		
		for (int i = 0; i < conn_signup_fds.size(); i++) {
			if (i >= conn_signup_fds.size())
				break;
			
			if (conn_signup_fds[i] < 0)
				continue;

			if (FD_ISSET (conn_signup_fds[i], &sockfd_set)) {
				respond_to_signup_conn (conn_signup_fds[i], conn_signup_fds, registered_users, reg_user_crypts);
			}
		}

		for (int j = 0; j < conn_signin_fds.size(); j++) {
			if (j >= conn_signin_fds.size())
				break;
			
			if (conn_signin_fds[j] < 0)
				continue;

			if (FD_ISSET (conn_signin_fds[j], &sockfd_set)) {
				respond_to_signin_conn (conn_signin_fds[j], conn_signin_fds, registered_users, logged_in_users, pending_file_operations);
			}
		}

		for (int k = 0; k < conn_kdc_fds.size(); k++) {
			if (k >= conn_kdc_fds.size())
				break;
			
			if (conn_kdc_fds[k] < 0)
				continue;

			if (FD_ISSET (conn_kdc_fds[k], &sockfd_set)) {
				respond_to_kdc_conn (conn_kdc_fds[k], conn_kdc_fds, registered_users, logged_in_users, reg_user_crypts);
			}
		}
	}
}