int main(int argc, char **argv) {

	FILE *file;
	char buff_flag[48];
	char username[100];
	char password[112];

	int line_ret;

	file_pass = fopen("/home/users/level03/.pass", "r");
	if (!file_pass) {
		fwrite("ERROR: failed to open password file\n", 1, 36, stderr);
		exit(1);
	}

	int n_read = fread(buff_flag, 1, 41, file_pass);
	if (n_read != 41) {
		fwrite("ERROR: failed to read password file\n", 1, 36, stderr);
		exit(1);
	}
	line_ret = strcspn(buff_flag, "\n");
	buff_flag[line_ret] = '\0';
	fclose(file_pass);

	puts("===== [ Secure Access System v1.0 ] =====");
	puts("/***************************************\\");
	puts("| You must login to access this system. |");
	puts("\\**************************************/");

	printf("--[ Username: ");
	fgets(username, 100, stdin);
	line_ret = strcspn(username, "\n");
	username[line_ret] = '\0';

	printf("--[ Password: ");
	fgets(password, 100, stdin);
	line_ret = strcspn(password, "\n");
	password[line_ret] = '\0';

	puts("*****************************************");

	if (strncmp(buff_flag, password, 41) == 0) {
		printf("Greetings %s!\n", username);
		system("/bin/sh");
		return 0;
	}
	printf(username);
	puts(" does not have access!");
	exit(1);
}
