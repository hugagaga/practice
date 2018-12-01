/* User space program */

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>

#define SCANNER __NR_tuxcall

char buffer[50];
char name[50];
char mode[10];

int main()
{
    char n[10] = "name";
    char f[10] = "file";
    char q[10] = "quit";
    char* line =NULL;
    size_t line_size =0;
    char choice[10];
    //prompt to ask whether user want to search malware process by name or a config file
    printf("Enter the mode: name / file\n");
    scanf("%s", mode);
    //name mode
    if (strcmp(mode, n) == 0) {
        printf("Enter the name of the malware");
        printf("(enter quit to quit)\n");
	//constantly ask for new name until "quit" is entered        
	scanf("%s", name);
	while (strcmp(name, q) != 0) {
            snprintf(buffer,sizeof(buffer), "%s", name);
	    //call new hijacked system call SCANNER
            int pid = syscall(SCANNER, buffer);
	    //if found, print the pid
            if (pid != 0) {
                printf("%s Found! pid:%d\n", name, pid);
		//prompt to ask user whether to kill the process or not
 		printf("Do you want to kill it? (y/n)");
	        scanf("%s", choice);
		if (strcmp(choice,"y") == 0) {
		   kill(-pid, SIGTERM);
		   sleep(2);
		   kill(-pid, SIGKILL);
		}
            } else {
                printf("%s Not Found!\n", name);
            }
	    printf("Enter the name of the malware");
            printf("(enter quit to quit)\n");
            scanf("%s", name);
	}
      //File mode
    } else if (strcmp(mode,f) == 0) {
	printf("Enter file name:\n");
        scanf("%s", name);
	FILE * file = fopen(name, "r");
	//Read the name line by line 
	while(getline(&line,&line_size,file)!=-1){
	    line[strlen(line) - 1] = '\0';
	    snprintf(buffer,sizeof(buffer), "%s", line);
            int pid = syscall(SCANNER, buffer);
            if (pid != 0) {
                printf("%s Found!\n", buffer);
            } else {
                printf("%s Not Found!\n", buffer);
            }
	}
	fclose(file);
    }
    return 0;
}

