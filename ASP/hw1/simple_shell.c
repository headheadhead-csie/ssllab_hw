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
static int cmd_cnt;
static int pipe_fds[2][2];

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

int close_all_pipes()
{
	if (pipe_fds[0][0] >= 0) {
		RET_IF_ERR(close(pipe_fds[0][0]));
		RET_IF_ERR(close(pipe_fds[0][1]));
	}
	if (pipe_fds[1][0] >= 0) {
		RET_IF_ERR(close(pipe_fds[1][0]));
		RET_IF_ERR(close(pipe_fds[1][1]));
	}
	return 0;
}

int free_resources(char ****args_arr_ptr, char **raw_input_ptr)
{
	close_all_pipes();
	if (*raw_input_ptr) {
		free(*raw_input_ptr);
		*raw_input_ptr = NULL;
	}
	free_args_arr(args_arr_ptr);

	return 0;
}

void signal_handler(int signum)
{
	is_end = true;
}

int read_input(char **raw_input_ptr)
{
	char ch;
	int raw_input_len = 0;
	int raw_input_size = 1024;

	*raw_input_ptr = malloc(raw_input_size);
	while ((ch = getchar()) != EOF && !is_end) {
		RET_IF_ERR(ch);

		if (raw_input_len+1 >= raw_input_size) {
			raw_input_size *= 2;
			*raw_input_ptr = realloc(*raw_input_ptr, raw_input_size);
		}
		if (!*raw_input_ptr)
			return -1;
		(*raw_input_ptr)[raw_input_len++] = ch;
		if (ch == '\n')
			break;
	}
	(*raw_input_ptr)[raw_input_len] = '\0';

	if (is_end)
		return 0;
	is_end = (ch == EOF);
	return 0;
}

void record_cmd(char *raw_input)
{
	if (cmd_cnt > 0 &&
	    cmd_history[(cmd_cnt-1) % 10] &&
	    strcmp(raw_input, cmd_history[(cmd_cnt-1) % 10]) == 0)
		return;
	if (cmd_history[cmd_cnt % 10])
		free(cmd_history[cmd_cnt % 10]);

	cmd_history[cmd_cnt++ % 10] = strdup(raw_input);
}

int do_history(char *args_1)
{
	int n = 10;

	if (args_1) {
		if (strcmp(args_1, "-c") == 0) {
			for (int i = 0; i < 10; i++) {
				if (cmd_history[i]) {
					free(cmd_history[i]);
					cmd_history[i] = NULL;
				}
			}
			cmd_cnt = 0;
			return 0;
		}
		for (char *ch_ptr = args_1; *ch_ptr; ch_ptr++) {
			if (!isdigit(*ch_ptr)) {
				fprintf(stderr, "error: history: invalid argument \"%s\"\n", args_1);
				return -EINVAL;
			}
		}
		n = atoi(args_1);
	}

	n = (n > 10)? 10: n;
	n = (n > cmd_cnt)? cmd_cnt: n;

	if (n <= 0) {
		fprintf(stderr, "error: history: invalid argument \"%s\"\n", args_1);
		return -EINVAL;
	}
	for (int i = cmd_cnt - n; i < cmd_cnt; i++)
		printf("%5d  %s", i+1, cmd_history[i % 10]);

	return 0;
}

#define CMD_EXIT 1
#define CMD_FAIL 2
#define CMD_EXEC 3
int run_builtin_cmd(char **args) 
{
	int argc = 0;

	for (char **arg_ptr = args; *arg_ptr; arg_ptr++)
		argc++;
	if (strcmp(args[0], "cd") == 0) {
		if (argc == 2)
			RET_IF_ERR(chdir(args[1]));
		else
			return CMD_FAIL;
	} else if (strcmp(args[0], "exit") == 0) {
		if (argc == 1) {
			is_end = true;
			return CMD_EXIT;
		} else
			return CMD_FAIL;
	} else if (strcmp(args[0], "history") == 0) {
		if (argc <= 2)
			return do_history(args[1]);
		else
			return CMD_FAIL;
	} else {
		return CMD_EXEC;
	}

	return 0;
}

int run_cmds(char ***args_arr)
{
	int pid, ret, proc_cnt = 0;
	int *pipe_fd_prev = pipe_fds[0], *pipe_fd_next = pipe_fds[1], *tmp;
	char ***cmd_window;

	memset(pipe_fds, -1, sizeof(pipe_fds[0][0]) * 4);
	RET_IF_ERR(pipe(pipe_fd_next));

	for (cmd_window = args_arr; cmd_window[0] && !is_end; cmd_window++) {
		ret = run_builtin_cmd(cmd_window[0]);
		if (ret == CMD_EXIT) {
			break;
		} else if (ret == CMD_FAIL) {
			fprintf(stderr, "error: %s: arguments number incorrect\n", cmd_window[0][0]);
		} else if (ret == CMD_EXEC) {
			RET_IF_ERR(pid = fork());
			if (!pid) {
				if (pipe_fd_prev[0] >= 0) {
					RET_IF_ERR(dup2(pipe_fd_prev[0], 0));
					RET_IF_ERR(close(pipe_fd_prev[0]));
					RET_IF_ERR(close(pipe_fd_prev[1]));
				}
				if (pipe_fd_next[1] >= 0 && cmd_window[1])
					RET_IF_ERR(dup2(pipe_fd_next[1], 1));
				RET_IF_ERR(close(pipe_fd_next[0]));
				RET_IF_ERR(close(pipe_fd_next[1]));
				RET_IF_ERR(execv(cmd_window[0][0], cmd_window[0]));
			} else if (pipe_fd_prev[0] >= 0) {
				RET_IF_ERR(close(pipe_fd_prev[0]));
				RET_IF_ERR(close(pipe_fd_prev[1]));
				pipe_fd_prev[1] = pipe_fd_prev[0] = -1;
			}
			proc_cnt++;
		}
		tmp = pipe_fd_prev;
		pipe_fd_prev = pipe_fd_next;
		pipe_fd_next = tmp;
		RET_IF_ERR(pipe(pipe_fd_next));
	}

	RET_IF_ERR(close_all_pipes());

	while (proc_cnt && !is_end) {
		wait(NULL);
		proc_cnt--;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	char *raw_input = NULL;
	char ***args_arr = NULL;
	struct sigaction sigint_action;

	sigint_action.sa_handler = signal_handler;
	GOTO_IF_ERR(sigemptyset(&sigint_action.sa_mask), ret, err);
	GOTO_IF_ERR(sigaddset(&sigint_action.sa_mask, SIGINT), ret, err);
	sigint_action.sa_flags = 0;
	GOTO_IF_ERR(sigaction(SIGINT, &sigint_action, NULL), ret, err);

	while (!is_end) {
		GOTO_IF_ERR(printf("$"), ret, err);

		GOTO_IF_ERR(read_input(&raw_input), ret, err);
		record_cmd(raw_input);
		if (strncmp(raw_input, "\n", 1) == 0 || is_end) {
			free(raw_input);
			raw_input = NULL;
			continue;
		}
		GOTO_IF_ERR(parse_cmds(raw_input, &args_arr), ret, err);

		GOTO_IF_ERR(run_cmds(args_arr), ret, err);

		free_resources(&args_arr, &raw_input);
	}

	exit(0);
err:
	free_resources(&args_arr, &raw_input);
	fprintf(stderr, "error: %s\n", strerror(errno));
	exit(errno);
}
