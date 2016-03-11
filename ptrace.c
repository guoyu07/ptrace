#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/debugreg.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>

int main(int argc, char **argv)
{
	pid_t pid;
	long addr, data;
	int rc;
	int status;
	struct user_regs_struct regs;

	/* $0 pid address */
	assert(argc == 3);

	pid = atoi(argv[1]);
	assert(pid > 1);

	rc = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (rc) {
		perror("attach");
		return -1;
	}

	/* 需要等待pid停止，这里不严谨 */
	waitpid(pid, NULL, 0);

	/* 设置一个断点, dr0,断点默认是disabled */
	addr = offsetof(struct user, u_debugreg);
	data = strtoul(argv[2], NULL, 16);
	rc = ptrace(PTRACE_POKEUSER, pid, (void*)addr, (void*)data);
	if (rc) {
		perror("set hwbp");
		goto out;
	}

	/* 激活4字节写断点, dr7 */
	addr = offsetof(struct user, u_debugreg) + 7 * sizeof(long);
	data = (0x1 /* enable dr0 */) | ((DR_RW_WRITE | DR_LEN_4) << DR_CONTROL_SHIFT);
	rc = ptrace(PTRACE_POKEUSER, pid, (void*)addr, (void*)data);
	if (rc) {
		perror("enable hwbp");
		goto out;
	}

	while (1) {
		rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
		if (rc) {
			perror("cont");
			goto out;
		}

		rc = waitpid(pid, &status, 0);
		if (rc == -1) {
			perror("waitpid");	
			goto out;
		}
		if (WIFEXITED(status)) {
			printf("exited\n");
			return -1;
		} else if (WIFSIGNALED(status)) {
			printf("killed by signal\n");
			return -1;
		} else if (WIFSTOPPED(status)) {
			printf("stopped\n");
		}

		rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (rc) {
			perror("getregs");
			goto out;
		}
		printf("rip 0x%llx\n", regs.rip);
	}

out:
	ptrace(PTRACE_DETACH, pid, NULL, NULL);

	return 0;
}

