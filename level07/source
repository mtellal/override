void clear_stdin() {
	int var;

	var = getchar();
	while (var != -1) {
		if ((char)var == '\n')
			return 
		var = getchar(); 
	}
}

unsigned int get_unum() {
	unsigned int num;

	fflush(stdout);
	scanf("%u", &num);
	clear_stdin();
	return num;	
}

int	read(char *buffer) {

	unsigned int	index;

	print(" Index: ");
	index = get_unum();
	printf(" Number at data[%u] is %u\n", index, *(unsigned int *)(buffer + (index * 4)));
	return 0;
}

int	store_number(char *buffer) {

	unsigned int 	number;
	unsigned int 	index;
	int		err;

	printf(" Number: ");
	number = get_unum();
	printf(" Index: ");
	index = get_unum();
	if ((index % 3 === 0) || ((number >> 24) == 183)) {
		puts(" *** ERROR! ***");
		puts("   This index is reserved for wil!");
		puts(" *** ERROR! ***");
		err = 1;
	}
	else {
		*(unsigned int *)(buffer + (index * 4)) = number;
		err = 0;
	}
	return err;
}

int main(int argc, char **argv) {

	char 	buffer[100];
	char 	cmd_buff[20];
	int	ret;

	memset(buffer, 0, 100);
	memset(cmd_buff, 0, 20);
	puts("----------------------------------------------------\n  Welcome to wil\'s crappy number stora ge service!   \n----------------------------------------------------\n Commands:                                          \n    store - store a number into the data storage    \n    read  - read a number from the data storage     \n    quit  - exit the program                        \n----------------------------------------------------\n   wil has reserved some storage :>                 \n----------------------------------------------------\n");	
	while (true) {

		printf("Input command: ");
		ret = 1;
		fgets(buff_cmd, 20, stdin);

		if (!strncmp(buff_cmd, "store", 5))
			ret = store_number(buffer);
		else if (!strcmp(buff_cmd, "read", 4))
			ret = read_number(buffer);
		else if (!strncmp(buff_cmd, "quit", 4))
			return 0;

		if (ret == 0) 
			printf(" Completed %s command successfully\n", buff_cmd);
		else
			printf(" Failed to do %s command\n", buff_cmd);
		memset(buff_cmd, 0, 20);	
	}
}
