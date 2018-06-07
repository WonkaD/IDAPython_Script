#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char * xorencryptFor(char * message, char * key) {
    size_t messagelen = strlen(message);
    size_t keylen = strlen(key);

    char * encrypted = malloc(messagelen+1);

    int i;
    for(i = 0; i < messagelen; i++) {
        encrypted[i] = message[i] ^ key[i % keylen];
    }
    encrypted[messagelen] = '\0';

    return encrypted;
}

char * xorencryptWhile(char * message, char * key) {
    size_t messagelen = strlen(message);
    size_t keylen = strlen(key);

    char * encrypted = malloc(messagelen+1);

    int i = 0;
    while(i < messagelen) {
        encrypted[i] = message[i] ^ key[i % keylen];
		i++;
    }
    encrypted[messagelen] = '\0';

    return encrypted;
}

char * xorencryptDoWhile(char * message, char * key) {
    size_t messagelen = strlen(message);
    size_t keylen = strlen(key);

    char * encrypted = malloc(messagelen+1);

    int i = 0;
	if (messagelen != 0){
		do {
			encrypted[i] = message[i] ^ key[i % keylen];
			i++;
		}
		while(i < messagelen);
	}

    encrypted[messagelen] = '\0';

    return encrypted;
}

char * xorencryptGoTo(char * message, char * key) {
    size_t messagelen = strlen(message);
    size_t keylen = strlen(key);

    char * encrypted = malloc(messagelen+1);

    int i = 0;
start:
	if (i >= messagelen) goto end;
	encrypted[i] = message[i] ^ key[i % keylen];
	i++;
	goto start;
end: 
	encrypted[messagelen] = '\0';
    return encrypted;
}

void helperXorencryptRecursive(char * message, char * key,char * encrypted, int i){
	size_t messagelen = strlen(message);
    size_t keylen = strlen(key);
	if (i < messagelen){
		encrypted[i] = message[i] ^ key[i % keylen];
		i++;		
		helperXorencryptRecursive(message, key, encrypted, i);
	}
	return;
}

char * xorencryptRecursive(char * message, char * key) {
	size_t messagelen = strlen(message);
	char * encrypted = malloc(messagelen+1);
    helperXorencryptRecursive(message, key, encrypted, 0);
    encrypted[messagelen] = '\0';
    return encrypted;
}
	
int main(int argc, char * argv[]) {
	char * message = "test message";
    char * key = "abc";
	char * encrypted = "";
    //---------------------- FOR ---------------------------
    encrypted = xorencryptFor(message, key);
    printf("FOR: %s\n", encrypted);
	//---------------------- WHILE ---------------------------
    encrypted = xorencryptWhile(message, key);
    printf("WHILE: %s\n", encrypted);
	
	//---------------------- DO WHILE ---------------------------
    encrypted = xorencryptDoWhile(message, key);
    printf("DO WHILE: %s\n", encrypted);
	
	//---------------------- GO TO ---------------------------
	encrypted = xorencryptGoTo(message, key);
    printf("GO TO: %s\n", encrypted);
	
	//---------------------- RECURSIVE ---------------------------
	encrypted = xorencryptRecursive(message, key);
    printf("RECURSIVE: %s\n", encrypted);
    
	free(encrypted);
	int a = 5;
again:
	while(a != 24){
		if (a==5) a = a + 24;
		while (a != 24){
			a = a - 1;
		}
		a = a * 3;
		if (a == 31) goto again;
		if (a == 0) break;
		a = a % 4;
		if (a == 2) continue;
		else a = a - 32;
	}
    return 0;
}







