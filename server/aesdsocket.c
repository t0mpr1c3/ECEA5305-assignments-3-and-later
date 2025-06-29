#include "queue.h"
#include "aesdsocket.h"

// these variables are set by the server and needed by the servers
static int sig = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// these variables are set by the server and needed by helper functions
struct addrinfo *servinfo = NULL;
char timebuf[TIMESTAMP_BUFFER_SIZE];


// get IP address from addrinfo and convert to a string
void ip2str (struct addrinfo *ai, char *buf) {
	void *addr;
        //char *ipver;
        struct sockaddr_in *ipv4;
        struct sockaddr_in6 *ipv6;

        if (ai->ai_family == AF_INET) { // IPv4
            ipv4 = (struct sockaddr_in *) ai->ai_addr;
            addr = &(ipv4->sin_addr);
            //ipver = "IPv4";
        } 
	else { // IPv6
            ipv6 = (struct sockaddr_in6 *) ai->ai_addr;
            addr = &(ipv6->sin6_addr);
            //ipver = "IPv6";
        }

        inet_ntop(ai->ai_family, addr, buf, sizeof buf);
}


void signal_handler (int s) {
	sig = s;
}


void goodbye (int retval) {
	int status;

	// free addrinfo
	if (servinfo != NULL) {
		freeaddrinfo(servinfo);
	}

	// unlink file
	status = unlink(FILENAME);
        if (status < 0 && errno != ENOENT) {
		perror("unlink");
		syslog(LOG_ERR, "unlink: %s", strerror(errno));
		retval = -1;
	}
	syslog(LOG_DEBUG, "Unlinked output file %s\n in server process %d", FILENAME, getpid());
	
	// unlink shared memory
	status = shm_unlink(SHM_HANDLE);
        if (status < 0 && errno != ENOENT) {
		perror("shm_unlink");
		syslog(LOG_ERR, "shm_unlink: %s", strerror(errno));
		retval = -1;
	}
	syslog(LOG_DEBUG, "Unlinked shared memory in server process %d", getpid());

	exit(retval);
}


void* get_packet (void *arg) {
	int status, output_fd, mask;
	char *buf;
	char *p;
	ssize_t bytes, fo;
	size_t len;
	thread_args_t *thread_args = (thread_args_t *) arg;
	pthread_t thread = pthread_self();

	syslog(LOG_DEBUG, "Starting aesdsocket server thread %ld", pthread_self());

	// initialize packet data buffer
	buf = (char*) malloc(PACKET_BUFFER_SIZE + 1); // extra byte for terminal 0
	if (buf == NULL) {
		fprintf(stderr, "could not allocate buffer of size %u", PACKET_BUFFER_SIZE);
		thread_args->retval = THREAD_FAILURE;
		return NULL;
	}

	// lock mutex
	status = pthread_mutex_lock(&lock);
	if (status != 0) {
		perror("pthread_mutex_lock");
		syslog(LOG_ERR, "pthread_mutex_lock: %s", strerror(errno));
		thread_args->retval = THREAD_FAILURE;
		return NULL;
	}
	syslog(LOG_DEBUG, "Obtained mutex in thread %ld", thread);

	// open output file, creating it if necessary
	mask = umask(0);
	output_fd = open(FILENAME, O_RDWR|O_APPEND|O_CREAT, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH);
	umask(mask);
	if (output_fd < 0) {
		perror("open");
		syslog(LOG_ERR, "open: %s", strerror(errno));
		thread_args->retval = THREAD_FAILURE;
		return NULL;
	}
	syslog(LOG_DEBUG, "Opened file descriptor output_fd=%d in thread %ld", output_fd, thread);

	// receive data over connection
	// each packet of data is terminated by \n
	// data packets do not contain null characters
	while (true) {
		bytes = recv(thread_args->sockfd, (void*) buf, (size_t) PACKET_BUFFER_SIZE, 0);
		if (bytes < 0) {
			perror("recv");
			syslog(LOG_ERR, "recv: %s", strerror(errno));
			thread_args->retval = THREAD_FAILURE;
			return NULL;
		}
		buf[bytes] = 0;
		syslog(LOG_DEBUG, "Received packet containing %ld bytes in thread %ld: '%s'", bytes, thread, buf);
		
		// find newline
		p = strchr(buf, '\n');
		if (p == NULL) {
			len = PACKET_BUFFER_SIZE;
		}
		else {
			len = p - buf + 1;
			if (len < bytes) {
				fprintf(stderr, "packet format error");
				thread_args->retval = THREAD_FAILURE;
				return NULL;
			}
		}

		// write buffer to file
		mask = umask(0);
		bytes = write(output_fd, (void*) buf, len);
		umask(mask);
		if (bytes < 0) {
			perror("write");
			syslog(LOG_ERR, "write: %s", strerror(errno));
			thread_args->retval = THREAD_FAILURE;
			return NULL;
		}
		if (bytes < len) {
			fprintf(stderr, "write error");
			syslog(LOG_ERR, "write error");
			thread_args->retval = THREAD_FAILURE;
			return NULL;
		}
		syslog(LOG_DEBUG, "Wrote %ld bytes to file", bytes);

		if (len < PACKET_BUFFER_SIZE) {
			break;
		}
	}

	// clear buffer
	//memset(buf, 0, PACKET_BUFFER_SIZE + 1);

	// set initial files offset to 0
	fo = 0;

	// send entire contents of /var/tmp/aesdsocketdata back over connection
	while (true) {
		bytes = pread(output_fd, (void*) buf, (size_t) PACKET_BUFFER_SIZE, fo);
		if (bytes < 0) {
			perror("read");
			syslog(LOG_ERR, "read: %s", strerror(errno));
			thread_args->retval = THREAD_FAILURE;
			return NULL;
		}
		else if (bytes == 0) {
			// EOF
			break;
		}
		fo += bytes;
		syslog(LOG_DEBUG, "Read %ld bytes from file in thread %ld, offset is now %ld: '%s'", bytes, thread, fo, buf);
		buf[bytes] = 0;
		len = (size_t) bytes;
		bytes = send(thread_args->sockfd, (void*) buf, len, 0);
		if (bytes < 0) {
			perror("send");
			syslog(LOG_ERR, "send: %s", strerror(errno));
			thread_args->retval = THREAD_FAILURE;
			return NULL;
		}
		syslog(LOG_DEBUG, "Sent %ld bytes in thread %ld", bytes, thread);
	}
	
	// unlock mutex
	status = pthread_mutex_unlock(&lock);
	if (status != 0) {
		perror("pthread_mutex_unlock");
		syslog(LOG_ERR, "pthread_mutex_unlock: %s", strerror(errno));
		thread_args->retval = THREAD_FAILURE;
		return NULL;
	}
	syslog(LOG_DEBUG, "Released mutex in thread %ld", thread);

	// close connection
	status = close(thread_args->sockfd);
	if (status < 0) {
		perror("close");
		syslog(LOG_ERR, "close: %s", strerror(errno));
		thread_args->retval = THREAD_FAILURE;
		return NULL;
	}
	syslog(LOG_DEBUG, "Closed socket file descriptor thread_args->sockfd=%d in thread %ld", thread_args->sockfd, thread);

	// set return value
	thread_args->retval = THREAD_SUCCESS;

	syslog(LOG_DEBUG, "Exiting server thread %ld", pthread_self());
	return NULL;
}


void* shm_init()  { 
	// initialize shared memory
	int shm_fd = shm_open(SHM_HANDLE, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (shm_fd < 0) {
		perror("shm_open");
		syslog(LOG_ERR, "shm_open: %s", strerror(errno));
		goodbye(-1);
	}

	// set the size of the shared memory
	int status = ftruncate(shm_fd, sizeof(pid_t)); // we are going to save the pid of the server
	if (status < 0) {
		perror("ftruncate");
		syslog(LOG_ERR, "ftruncate: %s", strerror(errno));
		goodbye(-1);
	}

	// map the shared memory
	void *shm = mmap(NULL, sizeof(pid_t), PROT_READ|PROT_WRITE, MAP_SHARED, shm_fd, 0);
	if (shm == MAP_FAILED) {
		perror("mmap");
		syslog(LOG_ERR, "mmap: %s", strerror(errno));
		goodbye(-1);
	}

	return shm;
}


pthread_t spawn_thread (thread_args_t *thread_args) {
	pthread_t child_thread;

	// spawn new server thread
	int status = pthread_create(&child_thread, NULL, &get_packet, thread_args);
	if (status != 0) {
		perror("pthread_create");
		syslog(LOG_ERR, "pthread_create: %s", strerror(errno));
		goodbye(-1);
	}
	syslog(LOG_DEBUG, "Created new server thread %ld", child_thread);

	return child_thread;
}


void block_signals (sigset_t *sigset) {
	// create `sigset` as the union of SIGINT, SIGTERM, and SIGUSR1
	int status = sigemptyset(sigset);
	if (status < 0) {
		perror("sigemptyset");
		syslog(LOG_ERR, "sigemptyset: %s", strerror(errno));
		goodbye(-1);
	}
	status = sigaddset(sigset, SIGUSR1);
	if (status < 0) {
		perror("sigaddset");
		syslog(LOG_ERR, "sigaddset: %s", strerror(errno));
		goodbye(-1);
	}
	status = sigaddset(sigset, SIGINT);
	if (status < 0) {
		perror("sigaddset");
		syslog(LOG_ERR, "sigaddset: %s", strerror(errno));
		goodbye(-1);
	}
	status = sigaddset(sigset, SIGTERM);
	if (status < 0) {
		perror("sigaddset");
		syslog(LOG_ERR, "sigaddset: %s", strerror(errno));
		goodbye(-1);
	}

	// block signals in `sigset`
	status = pthread_sigmask(SIG_SETMASK, sigset, NULL);
	if (status < 0) {
		perror("pthread_sigmask");
		syslog(LOG_ERR, "pthread_sigmask: %s", strerror(errno));
		goodbye(-1);
	}
}


size_t get_timestamp (const struct tm *now) {
	// copy RFC 2822-compliant date format into buffer
	(void) strcpy(timebuf, "timestamp:");
	size_t len = strftime(timebuf + 10, TIMESTAMP_BUFFER_SIZE - 11, "%a, %d %b %Y %T %z", now);
	if (len == 0) {
		perror("strftime");
		syslog(LOG_ERR, "strftime: %s", strerror(errno));
		goodbye(-1);
	}
	*(timebuf + len + 10) = '\n';
	*(timebuf + len + 11) = 0;

	return len + 11;
}

// from https://stackoverflow.com/questions/68804469/subtract-two-timespec-objects-find-difference-in-time-or-duration
struct timespec diff_timespec (const struct timespec *time1, const struct timespec *time0) {
	assert(time1);
	assert(time0);
	struct timespec diff = {.tv_sec = time1->tv_sec - time0->tv_sec, .tv_nsec = time1->tv_nsec - time0->tv_nsec};
	if (diff.tv_nsec < 0) {
		diff.tv_nsec += 1000000000;
		diff.tv_sec--;
	}
	return diff;
}


int main (int argc, char *argv[]) {
	int status, server_pid, file_exists, mask;
	int *shm = NULL;
	struct stat sb;
	struct timespec now, deadline;
	bool daemon;
	pid_t process;

	if (argc == 1) {
		daemon = false;
	} else if (argc == 2 && strncmp(argv[1], "-d", 3) == 0) {
		daemon = true;
	} else {
		fprintf(stderr, "unrecognized arguments\n");
		exit(-1);
	}

	// fork if daemon
	if (daemon) {
		process = fork();
		if (process < 0) {
			perror("fork");
			syslog(LOG_ERR, "fork: %s", strerror(errno));
			exit(-1);
		}
		if (process != 0) {
			// parent:
			return 0;
		}
	}

	// record initial clock time
	clock_gettime(CLOCK_REALTIME, &now);
	deadline = (struct timespec) {.tv_sec = now.tv_sec + 10, .tv_nsec = now.tv_nsec};
	syslog(LOG_DEBUG, "Starting aesdsocket server in process %d", getpid());

	// check if output directory exists and is readable and writable
	// FIXME use another method to test whether the server is running
	status = stat(DIRNAME, &sb);
	if (status != 0 && errno != ENOENT) {
		perror("stat");
		syslog(LOG_ERR, "stat: %s", strerror(errno));
		goodbye(-1);
	}
	if (!(status == 0 && S_ISDIR(sb.st_mode) && ((sb.st_mode & 0555) == 0555))) {
		// output directory does not exist with the correct RWX permissions:
		// (re)create the directory with appropriate RWX permissions
		// NB this must be run as root user
		mask = umask(0);
		status = mkdir(DIRNAME, 0555);
		umask(mask);
		if (status < 0) {
			perror("mkdir");
			syslog(LOG_ERR, "mkdir: %s", strerror(errno));
			goodbye(-1);
		}
		syslog(LOG_DEBUG, "Created directory %s", DIRNAME);
	}

	// check if output file exists
	file_exists = stat(FILENAME, &sb);
	if (file_exists != 0 && errno != ENOENT) {
		perror("stat");
		syslog(LOG_ERR, "stat: %s", strerror(errno));
		goodbye(-1);
	}

	// is the output file already exists, send a signal to the process
	// corresponding to the server that is already running, and return.
	// (The signal will be ignored.)
	if (file_exists == 0) {
		// file exists:
		// get process id of server
		shm = (int*) shm_init();
		server_pid = *shm;

		// send SIGUSR1 to let the server know to spin up a new thread
		syslog(LOG_DEBUG, "Sending SIGUSR1 to server process %d", server_pid);
		status = kill(server_pid, SIGUSR1);
		if (status < 0) {
			perror("kill");
			syslog(LOG_ERR, "kill: %s", strerror(errno));
			goodbye(-1);
		}

		syslog(LOG_DEBUG, "Exiting server process %d", getpid());
		return 0;
	}

	// file does not exist:
	// initialize main server process
	int server_sockfd, thread_sockfd, output_fd, optval = 1;
	struct addrinfo hints;
	sigset_t sigset_blocked, sigset_pending;
	ssize_t bytes, len;
	struct tm now_tm;
	char ipstr[INET6_ADDRSTRLEN];
	slist_data_t *element = NULL, *next = NULL;
	thread_args_t *thread_args;
	struct sockaddr_storage saddr, *thread_saddr;
	socklen_t saddrlen;
	struct sigaction sa;

	// save process group to shared memory
	server_pid = getpid();
	shm = (int*) shm_init();
	*shm = server_pid;
	syslog(LOG_DEBUG, "Saved server_pid %d", server_pid);

	// unmap shared memory
	status = munmap(shm, sizeof(pid_t));
	if (status < 0) {
		perror("unmap");
		syslog(LOG_ERR, "unmap: %s", strerror(errno));
		goodbye(-1);
	}

	// open output file, creating it if necessary
	mask = umask(0);
	output_fd = open(FILENAME, O_RDWR|O_APPEND|O_CREAT, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH);
	umask(mask);
	if (output_fd < 0) {
		perror("open");
		syslog(LOG_ERR, "open: %s", strerror(errno));
		goodbye(-1);
	}
	syslog(LOG_DEBUG, "Opened output file with descriptor output_fd=%d", output_fd);

	// initialize hints
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	// listen for IP address
	status = getaddrinfo(NULL, PORT, &hints, &servinfo);
	if (status != 0) {
		fprintf(stderr, "getaddr: %s\n", gai_strerror(status));
		goodbye(-1);
	}
	ip2str(servinfo, ipstr);

	// create socket
	server_sockfd = socket(servinfo->ai_family, servinfo->ai_socktype|SOCK_NONBLOCK, servinfo->ai_protocol);
	if (server_sockfd < 0) {
		perror("socket");
		syslog(LOG_ERR, "socket: %s", strerror(errno));
		goodbye(-1);
	}
	syslog(LOG_DEBUG, "Opened server socket with file descriptor server_sockfd=%d", server_sockfd);

	// set socket option SO_REUSEPORT
	status = setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEPORT, (void*) &optval, sizeof(optval));
	if (status < 0) {
		perror("setsockopt");
		syslog(LOG_ERR, "setsockopt: %s", strerror(errno));
		goodbye(-1);
	}
	syslog(LOG_DEBUG, "Set option SO_REUSEPORT for socket with file descriptor server_sockfd=%d", server_sockfd);

	// bind socket to port
	status = bind(server_sockfd, servinfo->ai_addr, servinfo->ai_addrlen);
	if (status < 0) {
		perror("bind");
		syslog(LOG_ERR, "bind: %s", strerror(errno));
		syslog(LOG_ERR, "bind arguments: %d %p %u\n", server_sockfd, servinfo->ai_addr, servinfo->ai_addrlen);
		goodbye(-1);
	}

	// listen on port
	status = listen(server_sockfd, BACKLOG);
	if (status < 0) {
		perror("listen");
		syslog(LOG_ERR, "listen: %s", strerror(errno));
		goodbye(-1);
	}

	// set signal handlers
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = signal_handler;
	status = sigaction(SIGINT, &sa, NULL);
        if (status != 0) {
		perror("sigaction");
		syslog(LOG_ERR, "sigaction: %s", strerror(errno));
		goodbye(-1);
	}	
	status = sigaction(SIGTERM, &sa, NULL);
        if (status != 0) {
		perror("sigaction");
		syslog(LOG_ERR, "sigaction: %s", strerror(errno));
		goodbye(-1);
	}	

	// initialize the linked list that will hold information about the threads that the server will create
	SLIST_HEAD(slisthead, slist_data_s) thread_list;
	SLIST_INIT(&thread_list);

	// block SIGINT, SIGTERM, and SIGUSR1 signals
	block_signals(&sigset_blocked);
	syslog(LOG_DEBUG, "Awaiting signal in server process %d", getpid());

	// repeat until interrupted or killed
	do {
		// accept connection if there are any in the connection queue
		saddrlen = sizeof saddr;
		thread_sockfd = accept(server_sockfd, (struct sockaddr*) &saddr, &saddrlen);
		if (server_sockfd < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("accept");
			syslog(LOG_ERR, "accept: %s", strerror(errno));
			goodbye(-1);
		}
		if (thread_sockfd > 0) {
			// connection accepted:
			syslog(LOG_DEBUG, "Opened thread socket with file descriptor thread_sockfd=%d", thread_sockfd);
			syslog(LOG_DEBUG, "Accepted connection from %s", ipstr);
        	
			// create new thread and add to list
			thread_saddr = (struct sockaddr_storage*) malloc(sizeof(struct sockaddr_storage));
			*thread_saddr = saddr;
			thread_args = (thread_args_t*) malloc(sizeof(thread_args_t));
			thread_args->sockfd = thread_sockfd;
			thread_args->saddr = thread_saddr;
			thread_args->retval = THREAD_PENDING;
			element = (slist_data_t*) malloc(sizeof(slist_data_t));
			element->thread_args = thread_args;
			element->thread = spawn_thread(thread_args);
			SLIST_INSERT_HEAD(&thread_list, element, link);
        	
			// write contents of list to log
			syslog(LOG_DEBUG, "These are all the threads in the list:");
			SLIST_FOREACH(element, &thread_list, link) {
				syslog(LOG_DEBUG, "Thread: %ld", element->thread);
				syslog(LOG_DEBUG, "    thread_args: %p", element->thread_args);
				syslog(LOG_DEBUG, "    link: %p", element->link.sle_next);
				if (element->link.sle_next) {
					syslog(LOG_DEBUG, "    link -> thread: %ld", element->link.sle_next->thread);
				}
   		   	}
		}

		// iterate over threads in list checking if each has returned
		SLIST_FOREACH_SAFE(element, &thread_list, link, next) {
			if (element->thread_args->retval == THREAD_FAILURE) {
				syslog(LOG_ERR, "Thread %ld has failed", element->thread);
				goodbye(-1);
			}
			else if (element->thread_args->retval == THREAD_SUCCESS) {
				syslog(LOG_DEBUG, "Thread %ld has returned", element->thread);

				// join thread
				syslog(LOG_DEBUG, "Joining thread %ld", element->thread);
				status = pthread_join(element->thread, NULL);
				if (status < 0) {
					perror("pthread_join");
					syslog(LOG_ERR, "pthread_join: %s", strerror(errno));
					goodbye(-1);
				}
				syslog(LOG_DEBUG, "Joined thread %ld", element->thread);

				// remove element from list
				SLIST_REMOVE(&thread_list, element, slist_data_s, link);
				if (SLIST_EMPTY(&thread_list)) {
					syslog(LOG_DEBUG, "There are no threads in the list.");
				}
				else {
					syslog(LOG_DEBUG, "These are all the threads in the list:");
					SLIST_FOREACH(element, &thread_list, link) {
						syslog(LOG_DEBUG, "Thread: %ld", element->thread);
						syslog(LOG_DEBUG, "    thread_args: %p", element->thread_args);
						syslog(LOG_DEBUG, "    link: %p", element->link.sle_next);
						if (element->link.sle_next) {
							syslog(LOG_DEBUG, "    link -> thread: %ld", element->link.sle_next->thread);
						}
   		   	   	   	}
				}

				/*
				// I think we don't need to free these resources because they get trashed in SLIST_REMOVE
				free((void*) element->thread_args->saddr);
				free((void*) element->thread_args);
				free((void*) element);
				*/
			}
		}

		// write timestamp if 10 seconds have passed
		clock_gettime(CLOCK_REALTIME, &now);
		if (now.tv_sec > deadline.tv_sec || (now.tv_sec == deadline.tv_sec && now.tv_nsec > deadline.tv_nsec)) {
			// 10 seconds have passed:
			deadline.tv_sec += 10;
			now_tm = *gmtime(&now.tv_sec);
			len = get_timestamp(&now_tm);

			// lock mutex
			status = pthread_mutex_lock(&lock);
			if (status != 0) {
				perror("pthread_mutex_lock");
				syslog(LOG_ERR, "pthread_mutex_lock: %s", strerror(errno));
				goodbye(-1);
			}
			syslog(LOG_DEBUG, "Obtained mutex in server process %d", getpid());

			// write timestamp to output file
			mask = umask(0);
			bytes = write(output_fd, (void*) timebuf, len);
			umask(mask);
			if (bytes < 0) {
				perror("write");
				syslog(LOG_ERR, "write: %s", strerror(errno));
				goodbye(-1);
			}
			if (bytes < len) {
				fprintf(stderr, "write error");
				syslog(LOG_ERR, "write error");
				goodbye(-1);
			}
			syslog(LOG_DEBUG, "Wrote timestamp '%s' to file in server process %d", timebuf, getpid());

			// unlock mutex
			status = pthread_mutex_unlock(&lock);
			if (status != 0) {
				perror("pthread_mutex_unlock");
				syslog(LOG_ERR, "pthread_mutex_unlock: %s", strerror(errno));
				goodbye(-1);
			}
			syslog(LOG_DEBUG, "Released mutex in server process %d", getpid());
		}

		// check for any signals that have been sent
		status = sigpending(&sigset_pending);
		if (status < 0) {
			perror("sigpending");
			syslog(LOG_ERR, "sigpending: %s", strerror(errno));
			goodbye(-1);
		}
	}
	while(!sigismember(&sigset_pending, SIGINT) && !sigismember(&sigset_pending, SIGTERM));

	// unblock signals
	status = pthread_sigmask(SIG_UNBLOCK, &sigset_blocked, NULL);
	if (status < 0) {
		perror("pthread_sigmask");
		syslog(LOG_ERR, "pthread_sigmask: %s", strerror(errno));
		goodbye(-1);
	}

	// shut down socket
	status = shutdown(server_sockfd, SHUT_RDWR);
	if (status < 0) {
		perror("shutdown");
		syslog(LOG_ERR, "shutdown: %s", strerror(errno));
		goodbye(-1);
	}
	syslog(LOG_DEBUG, "Closed connection from %s", ipstr);
	syslog(LOG_DEBUG, "Shut down socket with file descriptor server_sockfd=%d\n in server process %d", server_sockfd, getpid());

	// close socket
	status = close(server_sockfd);
	if (status < 0) {
		perror("close");
		syslog(LOG_ERR, "close: %s", strerror(errno));
		goodbye(-1);
	}
	server_sockfd = 0;
	syslog(LOG_DEBUG, "Closed socket with file descriptor server_sockfd=%d\n in server process %d", server_sockfd, getpid());

	// close file
	status = close(output_fd);
	if (status < 0) {
		perror("close");
		syslog(LOG_ERR, "close: %s", strerror(errno));
	}
	syslog(LOG_DEBUG, "Closed file descriptor output_fd=%d\n", output_fd);

	syslog(LOG_DEBUG, "Exiting server process %d", getpid());
	goodbye(0);
}
