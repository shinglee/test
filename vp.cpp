#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {

	FILE *inPtr, *outPtr, *tPtr;
	char outName[100];
	char input[20000];
	char targetIP[256];
	char vpIP[1024];
	char t[256], h[16];
	char *tmp, *tmp2;
	int count = 0;
	int hopCount;

	inPtr = fopen("./dataset/set_cover_IP_results", "r");
	//inPtr = fopen("./dataset/temp", "r");
	tPtr = fopen("./dataset/targetIP_list", "w+");
	if ( !inPtr ) {
		printf("ERROR in opening input file.\n");
		return 0;
	}else if(!tPtr ){
		printf("ERROR in opening output file.\n");
		return 0;
	}

	while ( fgets(input, 20000, inPtr) != NULL ) {

		if ( strlen(input) <= 10 ) break;
		count++;

		/* get the minum hop count */
		tmp2 = strstr(input, ";");
		strncpy(h, tmp2+1, 1);
		h[1] = '\0';
		hopCount = atoi(h);
		//printf("hop count = %s (%d)\n", h, hopCount);
		if ( hopCount > 4 )	continue;


		tmp = strtok(input, " ::;");
		strcpy(targetIP, tmp);
		memcpy(targetIP, tmp, strlen(tmp)+1);
		strcpy(t, targetIP);
		fprintf(tPtr, "%s\n", t);
		//printf("targetIP = %s\n", t);

		tmp = strtok(NULL, " ::;");
		//while ( tmp != NULL ){
		
			strcpy(vpIP, tmp);
			//printf("target IP = %s, VP = %s\n", t, vpIP);
			//if ( strlen(vpIP) <= 5 ) break;

			sprintf(outName, "./dataset/VP/%s", vpIP);
			outPtr = fopen(outName, "a+");
			fprintf(outPtr, "%s\n", t);
			fclose(outPtr);

		//	tmp = strtok(NULL, " ::;");
		//}

		printf("%d lines completed\n", count);
		//count++;
	}

	printf("program ends\n");
	fclose(inPtr);
	fclose(tPtr);

	return 0;
}
