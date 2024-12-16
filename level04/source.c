#include <unistd.h>


int main(int argc, char **argv) {

	pid_t 		pid;
	int		status;
	unsigned int 	status;
	char		buffer[128];
	long		sys_call;

	pid = fork();
	memset(buffer, 0, 128);
	status = 0;
	if (pid == 0) {
		prctl(1, 1);
		ptrace("PTRACE_TRACEME", 0, 0, 0);
		puts("Give me somve shellcode, k");
		gets(buffer);
	}
	else {
		while (sys_call != 11) {
			wait(&status);
			// ((status & 127 == 0) || (((status & 127) + 1) >> 1) > 0)
			if (WIFEXITED(&status) == 0 || WIFSIGNALED(&status)) { 
				// if the child is terminated normally or by a signal
				puts("child is exiting...");
				return 0;
			}
			sys_call = ptrace(PTRACE_PEEKUSER, pid, 44, 0); // read the sys call of the child proces 
		}
		puts("no exec() for you");
		kill(pid); 
	}

	return 0;
}
