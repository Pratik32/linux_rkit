#include<string.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>

int main(int argc, char *argv[]) {
	if(argc < 1) {
		printf("too few arguments\n");
		return 0;
	}
	size_t len = strlen(argv[1]);
	printf("arg len : %lu\n", len);
	char *args = (char*)malloc(sizeof(char) * (len + 2));
	args[0] = '1';
	args[len + 1] = '\0';
	char *ptr = &args[1];
	strcpy(ptr, argv[1]);
	printf("command : %s\n", args);
	int fd = open("/dev/imp_dev", O_RDWR);
	if(fd < 0) {
		printf("Not able to open the device file\n");
		return 0;
	}
	write(fd, args, (len + 2));
	free(args);
	return 0;
}
