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
static char *cmd_history[10];

int parse_args(char *raw_input, char ***args_ptr)
{
	char *token, *arg;
	char *delimiter = "\n ";
	int args_len = 0;
	int args_size = 16;

	*args_ptr = (char **)malloc(sizeof(char *)*args_size);
	token = strtok(raw_input, delimiter);

	while (token) {
		if (args_len+1 >= args_size) {
			args_size *= 2;
			if (args_size >= _POSIX_ARG_MAX)
				return -EINVAL;
			*args_ptr = (char **)realloc(*args_ptr, sizeof(char *) * args_size);
		}
		arg = malloc(strlen(token) + 1);
		if (!arg)
			return -errno;

		strcpy(arg, token);
		fprintf(stderr, "args[%d]: %s\n", args_len, arg);
		(*args_ptr)[args_len++] = arg;
		token = strtok(NULL, delimiter);
	}
	(*args_ptr)[args_len] = NULL;

	return 0;
}

int parse_cmds(char *raw_input, char ****args_arr_ptr)
{
	const char *pipe_deli = "|";
	char *cmd_token;
	int args_arr_len = 0, args_arr_size = 16;

	*args_arr_ptr = (char ***)malloc(sizeof(char **) * args_arr_size);
	while ((cmd_token = strsep(&raw_input, pipe_deli))) {
		fprintf(stderr, "args_arr[%d]: %s\n", args_arr_len, cmd_token);
		if (args_arr_len+1 >= args_arr_size) {
			args_arr_size *= 2;
			*args_arr_ptr = (char ***)realloc(*args_arr_ptr,
					sizeof(char **) * args_arr_size);
		}
		parse_args(cmd_token, (*args_arr_ptr) + args_arr_len++);
	}
	(*args_arr_ptr)[args_arr_len] = NULL;

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
	free(*args_ptr);
	*args_ptr = NULL;
}

void free_args_arr(char ****args_arr_ptr)
{
	char ***args_ptr;

	if (!*args_arr_ptr)
		return;

	for (args_ptr = *args_arr_ptr; *args_ptr; args_ptr++)
		free_args(args_ptr);
	free(*args_arr_ptr);
	*args_arr_ptr = NULL;
}

void free_resources(char ****args_arr_ptr, char **raw_input_ptr)
{
	if (*raw_input_ptr) {
		free(*raw_input_ptr);
		*raw_input_ptr = NULL;
	}
	free_args_arr(args_arr_ptr);
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

int read_input(char **raw_input_ptr)
{
	char ch;
	int raw_input_len = 0;
	int raw_input_size = 1024;

	*raw_input_ptr = malloc(raw_input_size);
	RET_IF_ERR(unblock_sigint());
	while ((ch = getchar()) != EOF && !is_end) {
		RET_IF_ERR(ch);
		RET_IF_ERR(block_sigint());

		if (raw_input_len+1 >= raw_input_size) {
			raw_input_size *= 2;
			*raw_input_ptr = realloc(*raw_input_ptr, raw_input_size);
		}
		if (!*raw_input_ptr)
			return -1;
		(*raw_input_ptr)[raw_input_len++] = ch;
		RET_IF_ERR(unblock_sigint());
		if (ch == '\n')
			break;
	}
	(*raw_input_ptr)[raw_input_len] = '\0';

	if (is_end)
		return -EINTR;
	RET_IF_ERR(block_sigint());
	is_end = (ch == EOF);
	return 0;
}

int print_history()
{
	return 0;
}

#define CMD_EXIT 1
#define CMD_FAIL 2
#define CMD_EXEC 3
int run_builtin_cmd(char **args) 
{
	int argc = 0;

	for (char **arg_ptr; *arg_ptr; arg_ptr++)
		argc++;
	if (strncmp(args[0], "cd", 2) == 0) {
		if (argc == 2)
			RET_IF_ERR(chdir(args[1]));
		else
			return CMD_FAIL;
	} else if (strncmp(args[0], "exit", 4) == 0) {
		if (argc == 1) {
			is_end = true;
			return CMD_EXIT;
		} else
			return CMD_FAIL;
	} else if (strncmp(args[0], "history", 6) == 0) {
		if (argc <= 2)
			return print_history();
		else
			return CMD_FAIL;
	} else {
		return CMD_EXEC;
	}

	return 0;
}

int run_cmds(char ***args_arr)
{
	int pid, ret;
	int pipe_fds[2][2] = {{-1, -1}, {-1, -1}};
	int *pipe_fd_prev = pipe_fds[0], *pipe_fd_next = pipe_fds[1], *tmp;
	char ***cmd_window = (char ***)malloc(sizeof(char**) * 2);

	RET_IF_ERR(pipe(pipe_fd_next));

	for (cmd_window = args_arr; cmd_window[0]; cmd_window++) {
		if (pipe_fd_prev[0] >= 0) {
			RET_IF_ERR(dup2(pipe_fd_prev[0], 0));
			RET_IF_ERR(close(pipe_fd_prev[0]));
			RET_IF_ERR(close(pipe_fd_prev[1]));
			pipe_fd_prev[1] = pipe_fd_prev[1] = -1;
		}
		if (pipe_fd_next[1] >= 0 && cmd_window[1])
			RET_IF_ERR(dup2(pipe_fd_next[1], 1));

		ret = run_builtin_cmd(cmd_window[0]);
		if (ret == CMD_EXIT) {
			break;
		} else if (ret == CMD_FAIL) {
			fprintf(stderr, "%s: arguments number incorrect\n", cmd_window[0][0]);
	printf("hi\n");
		} else if (ret == CMD_EXEC) {
			RET_IF_ERR(pid = fork());
			if (!pid) {
				RET_IF_ERR(close(pipe_fd_next[0]));
				RET_IF_ERR(close(pipe_fd_next[1]));
				RET_IF_ERR(execvp(cmd_window[0][0], cmd_window[0]));
			}
		}
		tmp = pipe_fd_prev;
		pipe_fd_prev = pipe_fd_next;
		pipe_fd_next = tmp;
		RET_IF_ERR(pipe(pipe_fd_next));
	}

	if (pipe_fd_prev[0] >= 0) {
		RET_IF_ERR(close(pipe_fd_prev[0]));
		RET_IF_ERR(close(pipe_fd_prev[1]));
	}
	if (pipe_fd_next[0] >= 0) {
		RET_IF_ERR(close(pipe_fd_next[0]));
		RET_IF_ERR(close(pipe_fd_next[1]));
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret, pid;
	char *raw_input = NULL;
	char ***args_arr = NULL;
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

		GOTO_IF_ERR(read_input(&raw_input), ret, err);
		if (strncmp(raw_input, "\n", 1) == 0) {
			free(raw_input);
			raw_input = NULL;
			continue;
		}
		GOTO_IF_ERR(parse_cmds(raw_input, &args_arr), ret, err);

		GOTO_IF_ERR(unblock_sigint(), ret, err);
		GOTO_IF_ERR(run_cmds(args_arr), ret, err);

		/* never return */
		if (!pid)
			GOTO_IF_ERR(execvp(args[0], args), ret, err);
		if (pid != -1)
			GOTO_IF_ERR(wait(NULL), ret, err);

		free_resources(&args_arr, &raw_input);
		GOTO_IF_ERR(printf("\n"), ret, err);
	}

	exit(0);
err:
	free_resources(&args_arr, &raw_input);
	fprintf(stderr, "error: %s\n", strerror(errno));
	exit(errno);
}
