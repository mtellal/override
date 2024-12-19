int main(int argc, char **argv) {

	int num;

	puts("***********************************");
	puts("* \t     -Level00 -\t\t  *");
	puts("***********************************");
	printf("Password:");
	scanf("%d", &num);
	if (num != 0x149c) // 0x149c == 5276
		puts("\nInvalid Password!");
	else {
		puts("\nAuthenticated!");
		system("/bin/sh");
	}
	return num == 0x149c;
}
