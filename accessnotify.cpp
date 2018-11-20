/*Author:	Jacob Mills
 *Date:		11/20/2018
 *Description:	This utility provides runtime analysis of files accessed by using the fanotify system call along
 *		with other techniques for tracking and managing files accessed, access modes, and the invoking process.
 *		Super-User access is required due to the system calls utilized by the utility.
 *Citation: 	The basis of this code was derived from the fanotify manual page found after invoking `man fanotify`
 *		Additional formatting and details were implemented to provide robust runtime analysis of
 *		realtime file access
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <signal.h>
#include <unistd.h>
#include <string>
#include <map>
#include <vector>
#include <algorithm>

using namespace std;

/* Structs and classes */

struct proc_action
{
  int action;
  int occurences;
  string file_accessed;
};

/* Global Data */

map<string,vector<proc_action>> proc_map;

/* SIG_KILL handler */

void print_results() {
	
	for (auto &proc : proc_map) {
		printf("Process: %s\n",proc.first.c_str());
		for (auto &action : proc.second) {
			switch (action.action) {
				case FAN_ACCESS:
					printf("\t[%d] - FAN_ACCESS - %s\n",action.occurences, action.file_accessed.c_str());
					break;
				case FAN_OPEN:
					printf("\t[%d] - FAN_OPEN - %s\n",action.occurences, action.file_accessed.c_str());
					break;
				case FAN_MODIFY:
					printf("\t[%d] - FAN_MODIFY - %s\n",action.occurences, action.file_accessed.c_str());
					break;
				case FAN_CLOSE_WRITE:
					printf("\t[%d] - FAN_CLOSE_WRITE - %s\n",action.occurences, action.file_accessed.c_str());
					break;
				case FAN_CLOSE_NOWRITE:
					printf("\t[%d] - FAN_CLOSE_NOWRITE - %s\n",action.occurences, action.file_accessed.c_str());
					break;
				case FAN_ACCESS_PERM:
					printf("\t[%d] - FAN_ACCESS_PERM - %s\n",action.occurences, action.file_accessed.c_str());
					break;
				case FAN_OPEN_PERM:
					printf("\t[%d] - FAN_OPEN_PERM - %s\n",action.occurences, action.file_accessed.c_str());
					break;

			}
		}
	}
}

void sig_kill(int signo) {
	print_results();	
	exit(0);
}

/* Return the process name associated with a pid */

const char* get_process_name_by_pid(const int pid)
{
	char* name = (char*)calloc(1024,sizeof(char));
	if(name) {
		sprintf(name, "/proc/%d/cmdline",pid);
		FILE* f = fopen(name,"r");
		if(f) {
			size_t size;
			size = fread(name, sizeof(char), 1024, f);
			if(size>0) {
				if('\n'==name[size-1])
					name[size-1]='\0';
			}
			fclose(f);
		}
	}
	return name;
}

/* Read all available fanotify events from the file descriptor 'fd' */

static void handle_events(int fd)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[200];
	ssize_t len;
	char path[PATH_MAX];
	ssize_t path_len;
	char procfd_path[PATH_MAX];
	struct fanotify_response response;
	string s_procname, s_file;
	int s_action = 0;

	/* Loop while events can be read from fanotify file descriptor */

	for(;;) {

		/* Read some events */

		len = read(fd, (void *) &buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		/* Check if end of available data reached */

		if (len <= 0)
			break;

		/* Point to the first event in the buffer */

		metadata = buf;

		/* Loop over all events in the buffer */

		while (FAN_EVENT_OK(metadata, len)) {

			/* Check that run-time and compile-time structures match */

			if (metadata->vers != FANOTIFY_METADATA_VERSION) {
				fprintf(stderr,
				        "Mismatch of fanotify metadata version.\n");
				exit(EXIT_FAILURE);
			}

			/* metadata->fd contains either FAN_NOFD, indicating a
			   queue overflow, or a file descriptor (a nonnegative
			   integer). Here, we simply ignore queue overflow. */

			if (metadata->fd >= 0) {
				
				/* Determine triggering process */
				const char* procname = get_process_name_by_pid(metadata->pid);
				s_procname = string(procname);
				
				/* Handle open permission event */
				if (metadata->mask & FAN_OPEN_PERM) {
					s_action = FAN_OPEN_PERM;

					/* Allow file to be opened */
					response.fd = metadata->fd;
					response.response = FAN_ALLOW;
					write(fd, &response,
					      sizeof(struct fanotify_response));
						  
				} else if (metadata->mask & FAN_CLOSE_WRITE){
					s_action = FAN_CLOSE_WRITE;
				} else if (metadata->mask & FAN_CLOSE_NOWRITE){
					s_action = FAN_CLOSE_NOWRITE;
				} else if (metadata->mask & FAN_ACCESS){
					s_action = FAN_ACCESS;
				} else if (metadata->mask & FAN_OPEN){
					s_action = FAN_OPEN;
				} else if (metadata->mask & FAN_MODIFY){
					s_action = FAN_MODIFY;
				} else if (metadata->mask & FAN_ACCESS_PERM){
					s_action = FAN_ACCESS_PERM;
				} else if (metadata->mask & FAN_OPEN_PERM){
					s_action = FAN_OPEN_PERM;
				}

				/* Retrieve and print pathname of the accessed file */

				snprintf(procfd_path, sizeof(procfd_path),
				         "/proc/self/fd/%d", metadata->fd);
				path_len = readlink(procfd_path, path,
				                    sizeof(path) - 1);
				if (path_len == -1) {
					perror("readlink");
					exit(EXIT_FAILURE);
				}

				path[path_len] = '\0';
				s_file = string(path);

				/* Add proc entry to proc map */
				auto key = proc_map.find(s_procname);
				if (key != proc_map.end()) {
					bool found = false;
					for (auto &item : key->second) {
						if (item.action == s_action && item.file_accessed.compare(s_file) == 0) {
							item.occurences++;
							found = true;
						}
					}
					
					if (!found) {
						struct proc_action p_action;
						p_action.action = s_action;
						p_action.file_accessed = s_file;
						p_action.occurences = 1;
						key->second.push_back(p_action);
					}
				} else {
					vector<proc_action> p_vector;
					struct proc_action p_action;
					p_action.action = s_action;
					p_action.file_accessed = s_file;
					p_action.occurences = 1;
					p_vector.push_back(p_action);
					proc_map.insert(pair<string,vector<proc_action>>(s_procname,p_vector));
				}

				/* Close the file descriptor of the event */
				close(metadata->fd);
			}

			/* Advance to next event */
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sig_kill_action;
	char buf;
	int fd, poll_num;
	nfds_t nfds;
	struct pollfd fds[2];

	/* Check mount point is supplied */

	if (argc != 2) {
		fprintf(stderr, "Usage: %s MOUNT\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Configure signal handling */
	sig_kill_action.sa_handler = sig_kill;
	sigemptyset(&sig_kill_action.sa_mask);
	sig_kill_action.sa_flags = 0;
	sigaction(SIGINT, &sig_kill_action, NULL);

	printf("Press enter key to terminate (or send SIG_KILL).\n");

	/* Create the file descriptor for accessing the fanotify API */

	fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
	                   O_RDONLY | O_LARGEFILE);
	if (fd == -1) {
		perror("fanotify_init");
		exit(EXIT_FAILURE);
	}

	/* Mark the mount for:
	   - permission events before opening files
	   - notification events after closing a write-enabled
	     file descriptor */

	if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
	                  FAN_OPEN_PERM | FAN_CLOSE_WRITE, AT_FDCWD,
	                  argv[1]) == -1) {
		perror("fanotify_mark");
		exit(EXIT_FAILURE);
	}

	/* Prepare for polling */

	nfds = 2;

	/* Console input */

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;

	/* Fanotify input */

	fds[1].fd = fd;
	fds[1].events = POLLIN;

	/* This is the loop to wait for incoming events */

	printf("Listening for events.\n");

	while (1) {
		poll_num = poll(fds, nfds, -1);
		if (poll_num == -1) {
			if (errno == EINTR) /* Interrupted by a signal */
				continue;  /* Restart poll() */

			perror("poll");    /* Unexpected error */
			exit(EXIT_FAILURE);
		}

		if (poll_num > 0) {
			if (fds[0].revents & POLLIN) {

				/* Console input is available: empty stdin and quit */

				while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
					continue;
				break;
			}

			if (fds[1].revents & POLLIN) {

				/* Fanotify events are available */
				handle_events(fd);
			}
		}
	}
	
	print_results();
	exit(EXIT_SUCCESS);
}
