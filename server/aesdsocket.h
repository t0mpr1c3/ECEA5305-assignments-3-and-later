#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>


#define PORT "9000" 
#define BACKLOG 10
#define PACKET_BUFFER_SIZE 1000
#define TIMESTAMP_BUFFER_SIZE 100
#define DIRNAME "/var/tmp/"
#define FILENAME "/var/tmp/aesdsocketdata"
#define CHARDEV "/dev/aesdchar"
#define SHM_HANDLE "/SHM_AESD"
#define THREAD_PENDING -1
#define THREAD_SUCCESS 0
#define THREAD_FAILURE 1


typedef struct thread_args_s thread_args_t;
struct thread_args_s {
	int sockfd;
	struct sockaddr_storage *saddr;
	int retval;
};

typedef struct slist_data_s slist_data_t;
struct slist_data_s {
	pthread_t thread;
	thread_args_t *thread_args;
	SLIST_ENTRY(slist_data_s) link;
};


// declare function prototypes

static void ip2str (struct addrinfo *ai, char *buf);
static void signal_handler (int s);
static void goodbye (int retval);
static void* get_packet (void *arg);
static void* shm_init ();
static pthread_t spawn_thread (thread_args_t *thread_args);
static void block_signals (sigset_t *sigset);
/*
static size_t get_timestamp (const struct tm *now);
static struct timespec diff_timespec (const struct timespec *time1, const struct timespec *time0);
*/
