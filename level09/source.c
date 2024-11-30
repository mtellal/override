void secret_backdoor(void) {
	char buff[128];
	
	fgets(buff, 140, _stdin);
	system(buff);
	return;
}

void set_msg(char **input)
{
	char buff[1024];
	
	memset(buff, 0, 1024);
	puts(">: Msg @Unix-Dude");
	printf(">>: ");
	fgets(buff, 1024, _stdin);
	strncpy(*input, buff, (long)*(int *)(*input + 180));
	return;
}

void set_username(char **input) {

	memset(*input, 0);
	puts(">: Enter your username");
	printf(">>: ");
	fgets(*input, 128, _stdin);

	for (int i = 0; (i < 41 && *input[i] != '\0'); i++) {
	  *(char *)(*input + 140 + (long)i) = *input[i];
	  i++:
	}
	printf(">: Welcome, %s", *input + 140);
	return;
}


void handle_msg(void) {

	char buffer[140];

	set_username(&buffer);
	set_msg(&buffer);
	puts(">: Msg sent!");
}


int main(int argc, char **argv) {
	puts("--------------------------------------------\n|   ~Welcome to l33t-m$n ~    v1337        |\n- -------------------------------------------");
	handle_msg();
	return 0;
}
