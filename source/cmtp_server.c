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
	sem_t thread_count;
	struct init_params running_params;
	uint32_t server_socket = server_init(&running_params);
	sem_init(&thread_count, 0, running_params.max_available_connections);
	int32_t temp_connection = 0;
	struct sockaddr temp_connection_sockaddr;
	socklen_t temp_addr_length = sizeof(temp_connection_sockaddr);

	// struct sockaddr_in client_address;
	// client_address.sin_port = 0;
	// client_address.sin_family = AF_INET;

	while(1)
	{
		if ((temp_connection=accept(server_socket, (struct sockaddr *)&temp_connection_sockaddr, &temp_addr_length))>-1)
		{
			//Create thread
			pthread_t connection_thread;
			//printf("FD %d confirmed as set. Passing connection to connection_manager\n", j);
			//printf("Address of connection[%d] = %p. Address of j = %p\n",j, &connection[j], &j);
			//Thread_arg is freed within connection_manager as one of the first operations.
			int * thread_arg = calloc(1, sizeof(int));
			*thread_arg = temp_connection;
			temp_connection = -1;
			if (pthread_create(&connection_thread, NULL, connection_manager, (void *)thread_arg)!=0)
			{
					print_to_log("Thread error! We're all doomed!", LOG_EMERG);
					perror("pthread");
			}
			#ifdef DEBUG
		  printf("Returned from connection manager.\n");
		  #endif /*DEBUG*/
		}
	}
}
