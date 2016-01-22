#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <sys/syslog.h>


#include "server_functions.h"
#include "cmtp_common.h"


int main()
{
	int server_socket = server_init();
	struct timeval select_timeout;
	select_timeout.tv_sec = 5;
	select_timeout.tv_usec = 0;

	fd_set connection_fdset;
	FD_ZERO (&connection_fdset);
	int connection[MAX_CONNECTIONS] = {0};
	int max_connection = 0;

	struct sockaddr_in client_address;
	client_address.sin_port = 0;
	client_address.sin_family = AF_INET;

	socklen_t addr_length;

	FD_SET (server_socket, &connection_fdset);

	if (max_connection < server_socket)
	{
		max_connection = server_socket;
	}

	while(1)
	{
		//Rebuild connection_fdset on each loop
		FD_ZERO(&connection_fdset);
		FD_SET(server_socket, &connection_fdset);
		for (int i = 1; i<MAX_CONNECTIONS; i++)
		{
			if (connection[i]!=0)
			{
				FD_SET(connection[i], &connection_fdset);
			}
		}

		//Simplify at some point


		//printf("Current fdset = %d\n",connection_fdset);
		//printf("Calling select()\n");
		if (select(max_connection + 1, &connection_fdset, NULL, NULL, &select_timeout)>0)
		{
			printf("Select has selected!\n");
			if (FD_ISSET(server_socket, &connection_fdset))
			{
				if (select_available_socket(connection, MAX_CONNECTIONS)>0)
				{
					int connection_index = select_available_socket(connection, MAX_CONNECTIONS);
					//printf("connection index = %d\n", connection_index);
					connection[connection_index] = accept(server_socket, (struct sockaddr *)&client_address, &addr_length);
					FD_SET(connection[connection_index], &connection_fdset);
					//printf("Current fdset = %x\n",connection_fdset);
					if (max_connection < connection[connection_index])
					{
						max_connection = connection[connection_index];
					}
				}
				else
				{
					printf("No file descriptors available for new incomming connection\n");
				}
			}

			for (int j=1;j<MAX_CONNECTIONS;j++)
			{
				//printf("Test FD_ISSET %d\n", FD_ISSET(connection[j], &connection_fdset));
				if (FD_ISSET(connection[j], &connection_fdset))
				{
					//Create thread
					pthread_t connection_thread;
					//printf("FD %d confirmed as set. Passing connection to connection_manager\n", j);
					//printf("Address of connection[%d] = %p. Address of j = %p\n",j, &connection[j], &j);
					//Thread_arg is freed within connection_manager as one of the first operations.
					int * thread_arg = calloc(1, sizeof(int));
					*thread_arg = connection[j];
					connection[j] = 0;
					if (pthread_create(&connection_thread, NULL, connection_manager, (void *)thread_arg)==0)
					{
						print_to_log("Thread error! We're all doomed!", LOG_EMERG);
						perror("pthread");
					}

					//connection_manager((void *)thread_arg);
					//free(thread_arg);
					//thread_arg = NULL;
					#ifdef DEBUG
		      printf("Returned from connection manager.\n");
					//printf("Address of j = %p\n", &j);
					//printf("connection[j] = , j = %d, thread_arg = \n", j);
		      #endif /*DEBUG*/
				}
				#ifdef DEBUG
	      printf("Post connection manager. In FD_SET loop. j = %d\n", j);
	      #endif /*DEBUG*/
			}
			#ifdef DEBUG
			printf("Post connection cycle\n");
			#endif /*DEBUG*/
		}
	}
}
