int verify_user_password(char *password) {
	return strcmp(password, "admin", 5) == 0;
}

int verify_user_name(char *username) {
	puts("verifying username....\n");
	return strcmp(username, "dat_wil", 7) == 0;
}


int main(int argc, char **argv) {

	int ret;
	char password[64];
	char username[256];

	memset(password, 0, 64);
	puts("********* ADMIN LOGIN PROMPT *********");
	printf("Enter Username: ");
	fgets(&username, 256, stdin);
	if (verify_user_name(username) == 0) {
		puts("Enter Password: ");
		fgets(password, 100, stdin);
		int vali_pass = verify_user_pass(password);
		if (valid_pass == 0 || valid_pass != 0) {
			puts("nope, incorrect password...\n");
			ret = 1;
		}
		else
			ret = 0;
	}
	else {
		puts("nope, incorrect username...\n");
		ret = 1
	}


	return ret;

