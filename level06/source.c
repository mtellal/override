int	auth(char login_buff[32], unsigned int number) {

	int		ret;
	unsigned int	enc_value;

	int nl = strcspn(login_buff, "\n");
	login_buff[nl] = '\0';	
	int len = strnlen(login_buff, 32);
	if (len < 6)
		ret = 1;
	else {
		if (ptrace(PTRACE_TRACEME) == -1) {
			puts("\x1b[32m.---------------------------.");
			puts("\x1b[31m| !! TAMPERING DETECTED !!  |");
			puts("\x1b[32m\'---------------------------\'");
			ret = 1;
		}
		else {
			enc_value = ((int)login_buff[3] ^ 0x1337) + 0x5eeded;
			for (int i = 0; i < len; i++) {
				if (login_buff[i] < ' ')
					return 1;
				enc_value = enc_value + ((int)login_buff[i] ^ enc_value) % 0x539;
			}
			if (number == enc_value)
				ret = 0;
			else
				ret = 1;
		}
	}
	return ret;
}

int main(int argc, char **argv) {

	unsigned int 	number;
	int		valid;
	char		login_buff[32];

	puts("***********************************");
	puts("*\t\tlevel06\t\t  *");
	puts("***********************************");
	printf("-> Enter Login: ");

	fgets(login_buff, 32, stdin);

	puts("***********************************");
	puts("***** NEW ACCOUNT DETECTED ********");
	puts("***********************************");
	printf("-> Enter Serial: ");

	scanf("%u", &number);
	valid = auth(login_buff, number);
	if (valid == 0) {
		puts("Authenticated!");
		system("/bin/sh");
	}
	return valid != 0;
}
