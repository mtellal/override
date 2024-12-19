int decrypt(int number) {

	int	res;
	char	buffer[17] = { 0 };
	int	len;

	memset(buffer, "Q}|u`sfg~sf{}|a3", 17);	
	i = 0;
	while (i < 17) {
		buffer[i] = buffer[i] ^ number;	
		i++;
	}
	if (!strcmp(buffer, "Congratulations!")) { 
		ret = system("/bin/sh");
	}
	else
		ret = puts("\nInvalid Password");
	return ret;
}

int test(int number)  {

	int res;

	res =  322424845 - number;
	switch (res) {
		case (1):
			decrypt(1);
			break;
		case (2):
			decrypt(2);
			break;
		case (3):
			decrypt(3);
			break;
		case (4):
			decrypt(4);
			break;
		case (5):
			decrypt(5);
			break;
		case (6):
			decrypt(6);
			break;
		case (7):
			decrypt(7);
			break;
		case (8):
			decrypt(8);
			break;
		case (9):
			decrypt(9);
			break;
		case (16):
			decrypt(16);
			break;
		case (17):
			decrypt(17);
			break;
		case (18):
			decrypt(18);
			break;
		case (19):
			decrypt(19);
			break;
		case (20):
			decrypt(20);
			break;
		case (21):
			decrypt(21);
			break;
		default:
			decrypt(rand());
			break;
	}
}

int main(int argc, char **argv) {

	unsigned int 	seed;
	int		number;

	seed = time(0);
	srand(seed);
	puts("***********************************");
	puts("*\t\tlevel03\t\t**");
	puts("***********************************");
	printf("Password:");
	scanf("%d", &number);
	test(number);
	return 0;

