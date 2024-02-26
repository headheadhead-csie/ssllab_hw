#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <unistd.h>

#define RET_IF_ERR(x) do { \
	int ret = (x); \
	if (ret < 0) \
		return ret; \
} while (0)

#define GOTO_IF_ERR(x, ret, label) do { \
	ret = (x); \
	if (ret < 0) \
		goto label; \
} while (0)

static bool is_end;

int parse_args(char **raw_cmd_ptr, char ***args_ptr)
{
	char *token, *arg;
	char *delimiter = "\n ";
	int args_len = 0;
	int args_size = 16;

	if (strlen(*raw_cmd_ptr) > _POSIX_ARG_MAX)
		return -EINVAL;

	*args_ptr = (char **)malloc(sizeof(char *)*args_size);
	token = strtok(*raw_cmd_ptr, delimiter);

	while (token) {
		if (args_len+1 > args_size) {
			args_size *= 2;
			*args_ptr = (char **)malloc(sizeof(char *)*args_size);
		}
		arg = malloc(strlen(token));
		if (!arg)
			return -1;

		strcpy(arg, token);
		(*args_ptr)[args_len++] = arg;
		token = strtok(NULL, delimiter);
	}
	(*args_ptr)[args_len] = NULL;

	return 0;
}

void free_args(char ***args_ptr)
{
	char **arg_ptr;

	if (!*args_ptr)
		return;

	for (arg_ptr = *args_ptr; *arg_ptr; arg_ptr++) {
		free(*arg_ptr);
		*arg_ptr = NULL;
	}
	free(args_ptr);
	*args_ptr = NULL;
}

void free_resources(char ***args_ptr, char **raw_cmd_ptr) {
	if (*raw_cmd_ptr) {
		free(*raw_cmd_ptr);
		*raw_cmd_ptr = NULL;
	}
	free_args(args_ptr);
}

void signal_handler(int signum)
{
	is_end = true;
	printf("signal is handled!\n");
}

int block_sigint(void)
{
	sigset_t set;

	RET_IF_ERR(sigemptyset(&set));
	RET_IF_ERR(sigaddset(&set, SIGINT));
	RET_IF_ERR(sigprocmask(SIG_BLOCK, &set, NULL));

	return 0;
}

int unblock_sigint(void)
{
	sigset_t set;

	RET_IF_ERR(sigemptyset(&set));
	RET_IF_ERR(sigaddset(&set, SIGINT));
	RET_IF_ERR(sigprocmask(SIG_UNBLOCK, &set, NULL));

	return 0;
}

int read_input(char **raw_cmd_ptr)
{
	char ch;
	int raw_cmd_len = 0;
	int raw_cmd_size = 1024;

	*raw_cmd_ptr = malloc(raw_cmd_size);
	RET_IF_ERR(unblock_sigint());
	while ((ch = getchar()) != EOF && !is_end) {
		RET_IF_ERR(ch);
		RET_IF_ERR(block_sigint());

		if (raw_cmd_len+1 > raw_cmd_size) {
			raw_cmd_size *= 2;
			*raw_cmd_ptr = realloc(*raw_cmd_ptr, raw_cmd_size);
		}
		if (!*raw_cmd_ptr)
			return -1;
		(*raw_cmd_ptr)[raw_cmd_len++] = ch;
		RET_IF_ERR(unblock_sigint());
		if (ch == '\n')
			break;
	}
	(*raw_cmd_ptr)[raw_cmd_len] = '\0';

	if (is_end)
		return -EINTR;
	RET_IF_ERR(block_sigint());
	is_end = (ch == EOF);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret, pid;
	char *raw_cmd = NULL;
	char **args = NULL;
	struct sigaction sigint_action;

	sigint_action.sa_handler = signal_handler;
	GOTO_IF_ERR(sigemptyset(&sigint_action.sa_mask), ret, err);
	GOTO_IF_ERR(sigaddset(&sigint_action.sa_mask, SIGINT), ret, err);
	sigint_action.sa_flags = 0;
	GOTO_IF_ERR(sigaction(SIGINT, &sigint_action, NULL), ret, err);

	while (!is_end) {
		pid = -1;
		GOTO_IF_ERR(printf("$"), ret, err);
		GOTO_IF_ERR(block_sigint(), ret, err);

		GOTO_IF_ERR(read_input(&raw_cmd), ret, err);
		if (strncmp(raw_cmd, "\n", 1) == 0) {
			free(raw_cmd);
			raw_cmd = NULL;
			continue;
		}
		GOTO_IF_ERR(parse_args(&raw_cmd, &args), ret, err);

		if (strncmp(args[0], "cd", 2) == 0)
			GOTO_IF_ERR(chdir(args[1]), ret, err);
		else if (strncmp(args[0], "exit", 4) == 0)
			break;
		else if (strncmp(args[0], "getcpu", 6) == 0)
			GOTO_IF_ERR(printf("%ld\n", syscall(436)), ret, err);
		else
			GOTO_IF_ERR(pid = fork(), ret, err);

		GOTO_IF_ERR(unblock_sigint(), ret, err);

		/* never return */
		if (!pid)
			GOTO_IF_ERR(execvp(args[0], args), ret, err);
		if (pid != -1)
			GOTO_IF_ERR(wait(NULL), ret, err);

		free_resources(&args, &raw_cmd);
		GOTO_IF_ERR(printf("\n"), ret, err);
	}

	exit(0);
err:
	free_resources(&args, &raw_cmd);
	fprintf(stderr, "error: %s\n", strerror(errno));
	exit(errno);
}
