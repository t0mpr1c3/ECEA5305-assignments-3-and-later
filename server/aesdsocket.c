#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>


#define false 0
#define true 1
#define PORT "9000" 
#define BACKLOG 10
#define BUFFER_SIZE 1000
#define DIRNAME "/var/tmp/"
#define FILENAME "/var/tmp/aesdsocketdata"
#define SHM_HANDLE "/SHM_AESDSOCKET"


// these variables are set by the daemon and needed by the servers
static int sig = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int daemon_sockfd = 0;
static char ipstr[INET6_ADDRSTRLEN];


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
        } else { // IPv6
            ipv6 = (struct sockaddr_in6 *) ai->ai_addr;
            addr = &(ipv6->sin6_addr);
            //ipver = "IPv6";
        }

        inet_ntop(ai->ai_family, addr, buf, sizeof buf);
}


void signal_handler (int s) {
	sig = s;
}


void * serve(void *arg) {
	int status, server_sockfd, output_fd, mask;
	char *buf;
	struct sigaction sa;
	struct sockaddr_storage saddr;
	socklen_t saddrlen;
	char *p;
	ssize_t bytes, fo;
	size_t len;

	syslog(LOG_DEBUG, "Starting aesdsocket server in thread %ld", pthread_self());

	// initialize packet data buffer
	buf = (char*) malloc(BUFFER_SIZE + 1); // extra byte for terminal 0
	if (buf == NULL) {
		fprintf(stderr, "could not allocate buffer of size %u", BUFFER_SIZE);
		exit(-1);
	}

	// lock mutex
	status = pthread_mutex_lock(&lock);
	if (status != 0) {
		perror("pthread_mutex_lock");
		syslog(LOG_ERR, "pthread_mutex_lock: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Obtained mutex in thread %ld", pthread_self());

	// listen on port
	status = listen(daemon_sockfd, BACKLOG);
	if (status < 0) {
		perror("listen");
		syslog(LOG_ERR, "listen: %s", strerror(errno));
		(void) pthread_mutex_unlock(&lock);
		exit(-1);
	}

	// set signal handlers
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = signal_handler;
	status = sigaction(SIGINT, &sa, NULL);
        if (status != 0) {
		perror("sigaction");
		syslog(LOG_ERR, "sigaction: %s", strerror(errno));
		(void) pthread_mutex_unlock(&lock);
		exit(-1);
	}	
	status = sigaction(SIGTERM, &sa, NULL);
        if (status != 0) {
		perror("sigaction");
		syslog(LOG_ERR, "sigaction: %s", strerror(errno));
		(void) pthread_mutex_unlock(&lock);
		exit(-1);
	}	

	while (sig != SIGINT && sig != SIGTERM) {
		// accept connection
		saddrlen = sizeof saddr;
		server_sockfd = accept(daemon_sockfd, (struct sockaddr*) &saddr, &saddrlen);
		if (server_sockfd < 0) {
			perror("accept");
			syslog(LOG_ERR, "accept: %s", strerror(errno));
			(void) pthread_mutex_unlock(&lock);
			exit(-1);
		}
		syslog(LOG_DEBUG, "Opened socket with file descriptor server_sockfd=%d", server_sockfd);
		syslog(LOG_DEBUG, "Accepted connection from %s", ipstr);
	
		// open output file, creating it if necessary
		mask = umask(0);
		output_fd = open(FILENAME, O_RDWR|O_APPEND|O_CREAT, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH);
		umask(mask);
		if (output_fd < 0) {
			perror("open");
			syslog(LOG_ERR, "open: %s", strerror(errno));
			(void) pthread_mutex_unlock(&lock);
			exit(-1);
		}
		syslog(LOG_DEBUG, "Opened file descriptor output_fd=%d", output_fd);
	
		// receive data over connection
		// each packet of data is terminated by \n
		// data packets do not contain null characters
		while (true) {
			bytes = recv(server_sockfd, (void*) buf, (size_t) BUFFER_SIZE, 0);
			if (bytes < 0) {
				perror("recv");
				syslog(LOG_ERR, "recv: %s", strerror(errno));
				(void) pthread_mutex_unlock(&lock);
				exit(-1);
			}
			buf[bytes] = 0;
			syslog(LOG_DEBUG, "Received packet containing %ld bytes: '%sa'", bytes, buf);
			
			// find newline
			p = strchr(buf, '\n');
			if (p == NULL) {
				len = BUFFER_SIZE;
			} else {
				len = p - buf + 1;
				if (len < bytes) {
					fprintf(stderr, "packet format error");
					(void) pthread_mutex_unlock(&lock);
					exit(-1);
				}
			}
	
			// write buffer to file
			mask = umask(0);
			bytes = write(output_fd, (void*) buf, len);
			umask(mask);
			if (bytes < 0) {
				perror("write");
				syslog(LOG_ERR, "write: %s", strerror(errno));
				(void) pthread_mutex_unlock(&lock);
				exit(-1);
			}
			if (bytes < len) {
				fprintf(stderr, "write error");
				syslog(LOG_ERR, "write error");
				(void) pthread_mutex_unlock(&lock);
				exit(-1);
			}
			if (status < 0) {
				perror("close");
				syslog(LOG_ERR, "close: %s", strerror(errno));
				(void) pthread_mutex_unlock(&lock);
				exit(-1);
			}
			syslog(LOG_DEBUG, "Wrote %ld bytes to file", bytes);

			if (len < BUFFER_SIZE) {
				break;
			}
		}

		// clear buffer
		//memset(buf, 0, BUFFER_SIZE + 1);

		// set initial files offset to 0
		fo = 0;

		// send entire contents of /var/tmp/aedaemon_sockfdsocketdata back over connection
		while (true) {
			bytes = pread(output_fd, (void*) buf, (size_t) BUFFER_SIZE, fo);
			if (bytes < 0) {
				perror("read");
				syslog(LOG_ERR, "read: %s", strerror(errno));
				(void) pthread_mutex_unlock(&lock);
				exit(-1);
			} else if (bytes == 0) {
				// EOF
				break;
			}
			fo += bytes;
			syslog(LOG_DEBUG, "Read %ld bytes from file, offset is now %ld: '%s'\n", bytes, fo, buf);
			buf[bytes] = 0;
			len = (size_t) bytes;
			bytes = send(server_sockfd, (void*) buf, len, 0);
			if (bytes < 0) {
				perror("send");
				syslog(LOG_ERR, "send: %s", strerror(errno));
				(void) pthread_mutex_unlock(&lock);
				exit(-1);
			}
			syslog(LOG_DEBUG, "Sent %ld bytes\n", bytes);
		}
		
		// close connections
		status = close(output_fd);
		if (status < 0) {
			perror("close");
			syslog(LOG_ERR, "close: %s", strerror(errno));
			(void) pthread_mutex_unlock(&lock);
			exit(-1);
		}
		syslog(LOG_DEBUG, "Closed file descriptor output_fd=%d\n", output_fd);
		status = close(server_sockfd);
		if (status < 0) {
			perror("close");
			syslog(LOG_ERR, "close: %s", strerror(errno));
			(void) pthread_mutex_unlock(&lock);
			exit(-1);
		}
		syslog(LOG_DEBUG, "Closed socket file descriptor server_sockfd=%d\n", server_sockfd);
		syslog(LOG_DEBUG, "Closed connection from %s", ipstr);

		//syslog(LOG_DEBUG, "Start sleeping\n");
		usleep(500000);
		//syslog(LOG_DEBUG, "End sleeping\n");
	}

	// SIGINT or SIGTERM received:
	fprintf(stderr, "aesdsocket server interrupted");

	// unlock mutex
	status = pthread_mutex_unlock(&lock);
	if (status != 0) {
		perror("pthread_mutex_unlock");
		syslog(LOG_ERR, "pthread_mutex_unlock: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Released mutex in thread %ld", pthread_self());
	syslog(LOG_DEBUG, "Exiting server thread %ld", pthread_self());

	return NULL;
}


void* shm_init() { 
	// initialize shared memory
	int shm_fd = shm_open(SHM_HANDLE, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (shm_fd < 0) {
		perror("shm_open");
		syslog(LOG_ERR, "shm_open: %s", strerror(errno));
		exit(-1);
	}

	// set the size of the shared memory
	int status = ftruncate(shm_fd, sizeof(pid_t)); // we are going to save the pid of the daemon
	if (status < 0) {
		perror("ftruncate");
		syslog(LOG_ERR, "ftruncate: %s", strerror(errno));
		exit(-1);
	}

	// map the shared memory
	void *shm = mmap(NULL, sizeof(pid_t), PROT_READ|PROT_WRITE, MAP_SHARED, shm_fd, 0);
	if (shm == MAP_FAILED) {
		perror("mmap");
		syslog(LOG_ERR, "mmap: %s", strerror(errno));
		exit(-1);
	}

	return shm;
}


// FIXME do not detach child threads, instead store them in a linked list and join them
void spawn_thread() {
	pthread_t child_thread;

	// spawn new server thread
	int status = pthread_create(&child_thread, NULL, &serve, NULL);
	if (status != 0) {
		perror("pthread_create");
		syslog(LOG_ERR, "pthread_create: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Created new server thread %ld", child_thread);
	
	// detach child thread
	status = pthread_detach(child_thread);
	if (status != 0) {
		perror("pthread_detach");
		syslog(LOG_ERR, "pthread_detach: %s", strerror(errno));
		exit(-1);
	}
}


void block_signals(sigset_t *sigset) {
	// create `sigset` as the union of SIGINT, SIGTERM, and SIGUSR1
	int status = sigemptyset(sigset);
	if (status < 0) {
		perror("sigemptyset");
		syslog(LOG_ERR, "sigemptyset: %s", strerror(errno));
		close(daemon_sockfd);
		exit(-1);
	}
	status = sigaddset(sigset, SIGUSR1);
	if (status < 0) {
		perror("sigaddset");
		syslog(LOG_ERR, "sigaddset: %s", strerror(errno));
		close(daemon_sockfd);
		exit(-1);
	}
	status = sigaddset(sigset, SIGINT);
	if (status < 0) {
		perror("sigaddset");
		syslog(LOG_ERR, "sigaddset: %s", strerror(errno));
		close(daemon_sockfd);
		exit(-1);
	}
	status = sigaddset(sigset, SIGTERM);
	if (status < 0) {
		perror("sigaddset");
		syslog(LOG_ERR, "sigaddset: %s", strerror(errno));
		close(daemon_sockfd);
		exit(-1);
	}

	// block signals in `sigset`
	status = pthread_sigmask(SIG_SETMASK, sigset, NULL);
	if (status < 0) {
		perror("pthread_sigmask");
		syslog(LOG_ERR, "pthread_sigmask: %s", strerror(errno));
		close(daemon_sockfd);
		exit(-1);
	}
}


int main (int argc, char *argv[]) {
	int status, daemon_pid, file_exists, mask;
	int *shm = NULL;
	struct stat sb;

	syslog(LOG_DEBUG, "Starting aesdsocket daemon in process %d", getpid());

	/*
	int daemon;
	if (argc == 1) {
		daemon = false;
	} else if (argc == 2 && strncmp(argv[1], "-d", 3) == 0) {
		daemon = true;
	} else {
		fprintf(stderr, "unrecognized arguments\n");
		exit(-1);
	}

	// fork if daemon
	pid_t process;
	if (daemon) {
		process = fork();
		if (process < 0) {
			// error
			perror("fork");
			syslog(LOG_ERR, "fork: %s", strerror(errno));
			close(daemon_sockfd);
			exit(-1);
		}
		if (process != 0) {
			// parent
			close(daemon_sockfd);
			exit(0);
		}
	}
	*/

	// check if output directory exists and is readable and writable
	// FIXME use another method to test whether the daemon is running
	status = stat(DIRNAME, &sb);
	if (status != 0 && errno != ENOENT) {
		perror("stat");
		syslog(LOG_ERR, "stat: %s", strerror(errno));
		exit(-1);
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
			exit(-1);
		}
		syslog(LOG_DEBUG, "Created directory %s", DIRNAME);
	}

	// check if output file exists
	file_exists = stat(FILENAME, &sb);
	if (file_exists != 0 && errno != ENOENT) {
		perror("stat");
		syslog(LOG_ERR, "stat: %s", strerror(errno));
		exit(-1);
	}
	if (file_exists == 0) {
		// file exists:
		// get process id of daemon
		shm = (int*) shm_init();
		daemon_pid = *shm;

		// send SIGUSR1 to let the daemon know to spin up a new server thread
		syslog(LOG_DEBUG, "Sending SIGUSR1 to daemon process %d", daemon_pid);
		status = kill(daemon_pid, SIGUSR1);
		if (status < 0) {
			perror("kill");
			syslog(LOG_ERR, "kill: %s", strerror(errno));
			exit(-1);
		}

		syslog(LOG_DEBUG, "Exiting daemon process %d", getpid());
		return 0;
	}

	// file does not exist:
	// initialize daemon
	int output_fd, optval = 1;
	struct addrinfo hints, *servinfo;
	sigset_t sigset;


	// save process group of the daemon to shared memory
	daemon_pid = getpid();
	shm = (int*) shm_init();
	*shm = daemon_pid;
	syslog(LOG_DEBUG, "Saved daemon_pid %d", daemon_pid);

	// unmap shared memory
	status = munmap(shm, sizeof(pid_t));
	if (status < 0) {
		perror("unmap");
		syslog(LOG_ERR, "unmap: %s", strerror(errno));
		close(daemon_sockfd);
		exit(-1);
	}

	// open output file, creating it if necessary
	mask = umask(0);
	output_fd = open(FILENAME, O_RDWR|O_APPEND|O_CREAT, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH);
	umask(mask);
	if (output_fd < 0) {
		perror("open");
		syslog(LOG_ERR, "open: %s", strerror(errno));
		close(daemon_sockfd);
		exit(-1);
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
		exit(-1);
	}
	ip2str(servinfo, ipstr);

	// create socket
	daemon_sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (daemon_sockfd < 0) {
		perror("socket");
		syslog(LOG_ERR, "socket: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Opened socket with file descriptor daemon_sockfd=%d", daemon_sockfd);

	// set socket option SO_REUSEPORT
	status = setsockopt(daemon_sockfd, SOL_SOCKET, SO_REUSEPORT, (void*) &optval, sizeof(optval));
	if (status < 0) {
		perror("setsockopt");
		syslog(LOG_ERR, "setsockopt: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Set option SO_REUSEPORT for socket with file descriptor daemon_sockfd=%d", daemon_sockfd);

	// bind socket to port
	status = bind(daemon_sockfd, servinfo->ai_addr, servinfo->ai_addrlen);
	if (status < 0) {
		perror("bind");
		syslog(LOG_ERR, "bind: %s", strerror(errno));
		syslog(LOG_ERR, "bind arguments: %d %p %u\n", daemon_sockfd, servinfo->ai_addr, servinfo->ai_addrlen);
		close(daemon_sockfd);
		exit(-1);
	}

	// create first server thread
	spawn_thread();

	// block SIGINT, SIGTERM, and SIGUSR1 signals
	block_signals(&sigset);
	syslog(LOG_DEBUG, "Awaiting signal in daemon process %d", getpid());

	do {
		// FIXME instead of waiting for a signal, wait until there is a signal
		// or until 10 seconds has elapsed in which case append a timestamp to the output file

		// wait until a signal is received
		status = sigwait(&sigset, &sig);
		if (status < 0) {
			perror("sigwait");
			syslog(LOG_ERR, "sigwait: %s", strerror(errno));
			exit(-1);
		}
		syslog(LOG_DEBUG, "Caught signal %s in daemon process %d", strsignal(sig), getpid());
	
		if (sig == SIGUSR1) {
			// SIGUSR1 received:
			// reset sig
			sig = 0;

			// create new server thread
			spawn_thread();
		}
		usleep(100000);
	}
	while (sig != SIGINT && sig != SIGTERM);

	// unblock signals
	status = pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
	if (status < 0) {
		perror("pthread_sigmask");
		syslog(LOG_ERR, "pthread_sigmask: %s", strerror(errno));
		close(daemon_sockfd);
		exit(-1);
	}

	// shut down socket
	status = shutdown(daemon_sockfd, SHUT_RDWR);
	if (status < 0) {
		perror("shutdown");
		syslog(LOG_ERR, "shutdown: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Shut down socket with file descriptor daemon_sockfd=%d\n in daemon process %d", daemon_sockfd, getpid());

	// close socket
	status = close(daemon_sockfd);
	if (status < 0) {
		perror("close");
		syslog(LOG_ERR, "close: %s", strerror(errno));
		exit(-1);
	}
	daemon_sockfd = 0;
	syslog(LOG_DEBUG, "Closed socket with file descriptor daemon_sockfd=%d\n in daemon process %d", daemon_sockfd, getpid());

	// free addrinfo
	freeaddrinfo(servinfo);

	// unlink file
	status = unlink(FILENAME);
        if (status < 0) {
		perror("unlink");
		syslog(LOG_ERR, "unlink: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Unlinked output file %s\n in daemon process %d", FILENAME, getpid());
	
	// unlink shared memory
	status = shm_unlink(SHM_HANDLE);
	if (status < 0) {
		perror("shm_unlink");
		syslog(LOG_ERR, "shm_unlink: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Unlinked shared memory");

	syslog(LOG_DEBUG, "Exiting daemon process %d", getpid());

	return 0;
}
