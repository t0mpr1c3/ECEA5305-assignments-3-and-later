#include <stdio.h>
#include <dirent.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
	if (argc < 3) {
		syslog(LOG_ERR, "Usage: writefile writestr");
		return 1;
	}

	FILE *WRITEFILE = fopen(argv[1], "w");
	if (WRITEFILE == NULL) {
		syslog(LOG_ERR, "File %s could not be created", argv[1]);
		return 1;
	}

	syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
	fprintf(WRITEFILE, "%s", argv[2]);
	if (fclose(WRITEFILE)) {
		syslog(LOG_ERR, "Error writing to %s", argv[1]);
		return 1;
	}
	return 0;
}
