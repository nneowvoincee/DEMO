#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
//gcc chall.c -o chall -fstack-protector 
char * chunks[32] = {0};
char cookie[64] = "cookie";

void iflush() {
    int ch = 0;
    do {
        ch = getc(stdin);
    } while (ch != '\n');
}

int get_idx(){
	printf("Index: ");
	int idx;
	scanf("%d", &idx);
	if (idx < 0 || idx >=32){
		printf("Illegal idx\n");
		return -1;
	}
    return idx;
}

int get_size(){
	printf("size: ");
	int size;
	scanf("%d", &size);
	return size;
}

void flag(){
    FILE* f = fopen("flag.txt", "r");
    if (!f) {
        puts("no flag found D:\n");
        return;
    }
    fgets(cookie, 64, f);
}

void alloc_chunk(){
    int index;
	index = get_idx();
	if (index == -1){
		return;
	}
	int size = get_size();
	char* chunk = malloc(size);
    iflush();
    printf("data: ");

    fgets(chunk, size, stdin);
	chunks[index] = chunk;
}

void view_chunk(){
	int idx = get_idx();
	if (idx == -1 || !chunks[idx]){
		return;
	}

	puts(chunks[idx]);
}


void free_chunk(){
	int idx = get_idx();
	if (idx == -1){
		return;
	}

	free(chunks[idx]);

}

void change_byte(){
    int idx = get_idx();
	if (idx == -1){
		return;
	}
    iflush();
    printf("byte: ");
    long long int ptr = (long long int)chunks[idx];
    int value = fgetc(stdin);
    chunks[idx] = (char *)(((ptr >> 8) << 8) + value);
}


void  check_and_print_menu(){
        if (!strcmp(cookie, "cookie")) {
            printf("My cookie is on %p. :D\n", &cookie);
        }
        else if (!strcmp(cookie, "flag")) {
            flag();
        }
        else {
            printf("Where is my cookie. D:\n");
        }
		printf("1.Alloc\n");
		printf("2.Free\n");
		printf("3.View\n");
        printf("4.Change_byte\n");
}

void menu(){

	while(1){
		char key = fgetc(stdin);
		int option = key - 0x30;    
		if (key == '\n'){
			continue;
		}


		switch(option){
			case 1:
				alloc_chunk();
				break;
			case 2:
				free_chunk();
				break;
			case 3:
				view_chunk();
				break;
            case 4:
				change_byte();
				break;

		}

        check_and_print_menu();
	}


}

int main(){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);


    check_and_print_menu();
    menu();
}