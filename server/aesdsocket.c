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
#define IPC_HANDLE "/AF_UNIX_SOCKETPAIR"

static int sig = 0;

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

int main (int argc, char *argv[]) {
	syslog(LOG_DEBUG, "Starting aesdsocket\n");

	int status, sd, sd2, fd, mask, daemon;
	struct sigaction sa;
	struct addrinfo hints, *servinfo;
	struct sockaddr_storage saddr;
	socklen_t saddrlen;
	char ipstr[INET6_ADDRSTRLEN];
	struct stat sb;
	char *buf, *p;
	ssize_t bytes;
	size_t len;
	off_t file_offset;
	pid_t process;

	if (argc == 1) {
		daemon = false;
	} else if (argc == 2 && strncmp(argv[1], "-d", 3) == 0) {
		daemon = true;
	} else {
		fprintf(stderr, "unrecognized arguments\n");
		exit(-1);
	}

	// check if directory exists and is readable and writable
	status = stat(DIRNAME, &sb);
	if (status < 0 && errno != ENOENT) {
		perror("stat");
		syslog(LOG_ERR, "stat: %s", strerror(errno));
		exit(-1);
	}
	if (!(status == 0 && S_ISDIR(sb.st_mode) && ((sb.st_mode & 0555) == 0555))) {
		// otherwise create directory
		// requires root permissions
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

	// poll until FILENAME has been unlinked
	status = 0;
	while (!(status < 0 && errno == ENOENT)) {
		status = stat(FILENAME, &sb);
		if (status < 0 && errno != ENOENT) {
			perror("stat");
			syslog(LOG_ERR, "stat: %s", strerror(errno));
			exit(-1);
		}
		usleep(100000);
	}
	syslog(LOG_DEBUG, "%s is absent", FILENAME);

	// initialize hints
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	// initialize packet data buffer
	buf = (char*) malloc(BUFFER_SIZE + 1); // extra byte for terminal 0
	if (buf == NULL) {
		fprintf(stderr, "could not allocate buffer of size %u", BUFFER_SIZE);
		exit(-1);
	}

	// get IP address
	status = getaddrinfo(NULL, PORT, &hints, &servinfo);
	if (status != 0) {
		fprintf(stderr, "getaddr: %s\n", gai_strerror(status));
		exit(-1);
	}
	ip2str(servinfo, ipstr);

	// create socket
	sd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (sd < 0) {
		perror("socket");
		syslog(LOG_ERR, "socket: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Opened shared socket file descriptor sd=%d", sd);

	// set socket option SO_REUSEPORT
	int optval = 1;
	status = setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, (void*) &optval, sizeof(optval));
	if (status < 0) {
		perror("setsockopt");
		syslog(LOG_ERR, "setsockopt: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Set option SO_REUSEPORT for socket file descriptor sd=%d", sd);

	// bind socket to port
	status = bind(sd, servinfo->ai_addr, servinfo->ai_addrlen);
	if (status < 0) {
		perror("bind");
		syslog(LOG_ERR, "bind: %s", strerror(errno));
		syslog(LOG_ERR, "bind arguments: %d %p %u\n", sd, servinfo->ai_addr, servinfo->ai_addrlen);
		close(sd);
		exit(-1);
	}

	// fork if daemon
	if (daemon) {
		process = fork();
		if (process < 0) {
			perror("fork");
			syslog(LOG_ERR, "fork: %s", strerror(errno));
			close(sd);
			exit(-1);
		}
		if (process != 0) { // parent
			close(sd);
			exit(0);
		}
	}

	// listen on port
	status = listen(sd, BACKLOG);
	if (status < 0) {
		perror("listen");
		syslog(LOG_ERR, "listen: %s", strerror(errno));
		close(sd);
		exit(-1);
	}

	// set signal handlers
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = signal_handler;
	status = sigaction(SIGINT, &sa, NULL);
        if (status != 0) {
		perror("sigaction");
		syslog(LOG_ERR, "sigaction: %s", strerror(errno));
		close(sd);
		exit(-1);
	}	
	status = sigaction(SIGTERM, &sa, NULL);
        if (status != 0) {
		perror("sigaction");
		syslog(LOG_ERR, "sigaction: %s", strerror(errno));
		close(sd);
		exit(-1);
	}	
	sig = 0;

	while (sig == 0) {
		// accept connection
		saddrlen = sizeof saddr;
		sd2 = accept(sd, (struct sockaddr*) &saddr, &saddrlen);
		if (sd2 < 0) {
			perror("accept");
			syslog(LOG_ERR, "accept: %s", strerror(errno));
			close(sd);
			exit(-1);
		}
		syslog(LOG_DEBUG, "Opened socket file descriptor sd2=%d", sd2);
		syslog(LOG_DEBUG, "Accepted connection from %s", ipstr);
	
		// open output file, creating it if necessary
		mask = umask(0);
		fd = open(FILENAME, O_RDWR|O_APPEND|O_CREAT, S_IWUSR|S_IRUSR|S_IWGRP|S_IRGRP|S_IWOTH|S_IROTH);
		umask(mask);
		if (fd < 0) {
			perror("open");
			syslog(LOG_ERR, "open: %s", strerror(errno));
			close(sd);
			exit(-1);
		}
		syslog(LOG_DEBUG, "Opened file descriptor fd=%d", fd);
	
		// receive data over connection
		// each packet of data is terminated by \n
		// data packets do not contain null characters
		while (true) {
			bytes = recv(sd2, (void*) buf, (size_t) BUFFER_SIZE, 0);
			if (bytes < 0) {
				perror("recv");
				syslog(LOG_ERR, "recv: %s", strerror(errno));
				close(sd);
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
					close(sd);
					exit(-1);
				}
			}
	
			// write buffer to file
			mask = umask(0);
			bytes = write(fd, (void*) buf, len);
			umask(mask);
			if (bytes < 0) {
				perror("write");
				syslog(LOG_ERR, "write: %s", strerror(errno));
				close(sd);
				exit(-1);
			}
			if (bytes < len) {
				fprintf(stderr, "write error");
				syslog(LOG_ERR, "write error");
				close(sd);
				exit(-1);
			}
			if (status < 0) {
				perror("close");
				syslog(LOG_ERR, "close: %s", strerror(errno));
				close(sd);
				exit(-1);
			}
			syslog(LOG_DEBUG, "Wrote %ld bytes to file", bytes);

			if (len < BUFFER_SIZE) {
				break;
			}
		}

		// clear buffer
		//memset(buf, 0, BUFFER_SIZE + 1);

		// reset file offset to start of file
		file_offset = 1;
		while (file_offset > 0) {
			file_offset = lseek(fd, 0, SEEK_SET);
			if (file_offset < 0) {
				perror("lseek");
				syslog(LOG_ERR, "lseek: %s", strerror(errno));
				close(sd);
				exit(-1);
			}
		}

		// send entire contents of /var/tmp/aesdsocketdata back over connection
		while (true) {
			bytes = read(fd, (void*) buf, (size_t) BUFFER_SIZE);
			if (bytes < 0) {
				perror("read");
				syslog(LOG_ERR, "read: %s", strerror(errno));
				close(sd);
				exit(-1);
			} else if (bytes == 0) {
				break;
			}
			buf[bytes] = 0;
			syslog(LOG_DEBUG, "read %ld bytes from file: '%s'\n", bytes, buf);
			len = (size_t) bytes;
			bytes = send(sd2, (void*) buf, len, 0);
			if (bytes < 0) {
				perror("send");
				syslog(LOG_ERR, "send: %s", strerror(errno));
				close(sd);
				exit(-1);
			}
			syslog(LOG_DEBUG, "sent %ld bytes\n", bytes);
		}
		
		// close connections
		status = close(fd);
		if (status < 0) {
			perror("close");
			syslog(LOG_ERR, "close: %s", strerror(errno));
			close(sd);
			exit(-1);
		}
		syslog(LOG_DEBUG, "Closed file descriptor fd=%d\n", fd);
		status = close(sd2);
		if (status < 0) {
			perror("close");
			syslog(LOG_ERR, "close: %s", strerror(errno));
			close(sd);
			exit(-1);
		}
		syslog(LOG_DEBUG, "Closed socket file descriptor sd2=%d\n", sd2);
		syslog(LOG_DEBUG, "Closed connection from %s", ipstr);

		syslog(LOG_DEBUG, "Start sleeping\n");
		usleep(500000);
		syslog(LOG_DEBUG, "End sleeping\n");
	}

	// signal received
	if (sig == SIGINT) {
		fprintf(stderr, "aesdsocket interrupted");
	} else {
		fprintf(stderr, "aesdsocket terminated");
	}
	syslog(LOG_DEBUG, "Caught signal, exiting");

	status = shutdown(sd, SHUT_RDWR);
	if (status < 0) {
		perror("shutdown");
		syslog(LOG_ERR, "shutdown: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Shut down socket file descriptor sd=%d\n", sd);

	status = close(sd);
	if (status < 0) {
		perror("close");
		syslog(LOG_ERR, "close: %s", strerror(errno));
		exit(-1);
	}
	syslog(LOG_DEBUG, "Closed socket file descriptor sd=%d\n", sd);

	// free addrinfo
	freeaddrinfo(servinfo);

	// unlink file
	if (unlink(FILENAME) < 0) {
		perror("unlink");
		exit(-1);
	}
	syslog(LOG_DEBUG, "Unlinked file %s\n", FILENAME);

	exit(0);
}
