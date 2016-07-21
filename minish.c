#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>

#define  _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500

void shell_listener();
int execute(char*, char*);

//variable to store the current working directory
char pwd[1000];

//global job id
int job_id = 1;

//background process group
int bg_pgrp = -1;

//current foreground process
int cur_fg_pid = -1;
//current foreground command
char* cur_fg_cmd;
//current foreground pid
int cur_bg_pid = -1;
//current background command
char* cur_bg_command;

//variable to indicate whether parent process can wait for the child to complete
int can_wait = 1;
//variable to indicate whether prompt needs to be shown
int prompt_disp = 0;
//global variable to indicate latest job_id
int latest_jobid = -1;

//process structure
typedef struct proc_info{
        pid_t pid;
        int jid;
        int status;
	char* command;
        struct proc_info *next;
}proc_info;

//process jobs list
typedef struct pjid_list{
        proc_info *head, *tail;
        int size;
}pjid_list;

//init proc_info
proc_info* init_proc_info(proc_info *node, pid_t pid, int jid, int status, char* command){
        node = (proc_info*)malloc(sizeof(proc_info));
        node->pid = pid;
        node->jid = jid;
        node->status = status;
	node->command = (char*)malloc(sizeof(char));
	strcpy(node->command, command);
        node->next = NULL;
        return node;
}

//init process list
pjid_list* init_pjid_list(pjid_list* l){
        l = (pjid_list*)malloc(sizeof(pjid_list));
        l->head = NULL;
        l->tail = NULL;
        l->size = 0;
        return l;
}

//insert information for a new process to the linked list
void insert(pjid_list *l, pid_t pid, int jid, int status, char* command){
        if(l->head == NULL){
                proc_info *new_node;
                new_node = init_proc_info(new_node, pid, jid, status, command);
                l->head = new_node;
                l->tail = new_node;
        }
        else{
                proc_info *temp = l->head;
                while(temp->next != NULL){
                        temp = temp->next;
                }
                proc_info *new_node;
                new_node = init_proc_info(new_node, pid, jid, status, command);
                temp->next = new_node;
                l->tail = new_node;
        }
        ++l->size;
}

//search whether process given by pid is present in the process list 
int search(pjid_list* l, int pid){
	if(l->head == NULL){
		return 0;
	}
	else{
		proc_info *temp = l->head;
		while(temp->next != NULL){
			if(temp->pid == pid){
				return 1;
			}
			temp = temp->next;
		}
		if(temp->pid == pid) return 1;
		return 0;
	}
}

//check whether the process list is empty
int is_empty(pjid_list* l){
	if(l->head == NULL) return 1;
	return 0;
}

//retrieve process command
char* get_command(pjid_list* l, int id){
	if(l->head == NULL){
		return NULL;
	}
	proc_info* temp = l->head;
	while(temp->next != NULL){
		if(temp->pid == id || temp->jid == id){
			return temp->command;
		}
		temp = temp->next;
	}
	if(temp->pid == id || temp->jid == id){
		return temp->command;
	}
	return NULL;
}

//delete information for a process from the process list 
void delete(pjid_list *l, pid_t pid){
        if(l->head == NULL){
                return;
        }
	else if(pid == -1) return;
	else if(search(l, pid) == 0){return;}
        else if(l->head == l->tail){
                if(l->head->pid == pid){
                        proc_info *temp = l->head;
                        l->head = NULL;
                        l->tail = NULL;
                        free(temp);
                }
                else return;
        }
        else if(l->head->pid == pid){
                proc_info *temp = l->head;
                l->head = l->head->next;
                temp->next = NULL;
                free(temp);
        }
        else{
                proc_info *temp = l->head;
                proc_info *prev = temp;
                while(temp->next != NULL && temp->pid != pid){
                        prev = temp;
                        temp = temp->next;
                }
                if(temp->pid == pid){
                        if(temp == l->tail){
                                prev->next = NULL;
                                l->tail = prev;
                                free(temp);
                        }
                        else{
                                prev->next = temp->next;
                                temp->next = NULL;
                                free(temp);
                        }
                }
                else return;
        }
        l->size--;
}

//update status for a process
void update(proc_info *cur, pid_t pid, int status){
        if(cur == NULL){
                return;
        }
        if(cur->pid == pid){
                cur->status = status;
                return;
        }
        update(cur->next, pid, status);
}

//retrieve reference to the process given by id (this can be either pid or jid)
proc_info* get_proc(pjid_list *l, int id){
	if(l->head == NULL){
		return NULL;
	}
	if(l->head->jid == id || l->head->pid == id){
		return l->head;
	}
	proc_info *temp = l->head;
	while(temp->next != NULL){
		if(temp->jid == id || temp->pid == id){
			return temp;
		}	
		temp = temp->next;
	}
	if(temp->jid == id || temp->pid == id){
		return temp;
	}
	return NULL;
}

//remove information for all processes from the process list
void clear(pjid_list *l){
        if(l->size == 0){
                return;
        }
        proc_info *temp = l->head;
        while(temp != l->tail){
                proc_info *del_node = temp;
                temp = temp->next;
                free(del_node);
        }
        free(temp);
	cur_fg_pid = -1;
	job_id = 0;
}

//global reference to the linked list
pjid_list *l;

//retrieve command line input
char *command_fetcher(void){
  char *line = NULL;
  size_t bufsize = 0;
  getline(&line, &bufsize, stdin);
  return line;
}

//extract job id from command
int get_job_id(char *line)
{
        char *line1 = (char*)malloc(sizeof(char));
        char *token;
        char **tokens = (char**)malloc(sizeof(char*));
        int job_id,i;
        strcpy(line1,line);
        token = strtok(line1,"%");
        i=0;
        while(token !=NULL && strlen(token) > 0)
        {
                tokens[i] = token;
                i = i+1;
                token = strtok(NULL,"%");
        }
        tokens[i] = NULL;
        job_id = atoi(tokens[1]);
        return job_id;

}

//check whether command is a background command using regex
int is_bg(char* line){
	
	if(line[strlen(line)-1] == '&') return -2;
	regex_t regex, regex1;
	int reti1, reti2;
	 /* Compile regular expression */
        reti1 = regcomp(&regex, "^[[:space:]]*bg[[:space:]]+%[[:space:]]*[[:digit:]]+[[:space:]]*$", REG_EXTENDED);
        reti2 = regcomp(&regex1, "[[:space:]]*^bg[[:space:]]*$", REG_EXTENDED);

        if (reti1){
                return -1;
        }
        if(reti2){
                 return -1;
        }

        reti1 = regexec(&regex,line, 0, NULL, 0);
        if (!reti1){
                int job_id = get_job_id(line);
                return job_id;
        }
        else if (reti1 == REG_NOMATCH){}
	else{
		return -1;
	}
	reti2 = regexec(&regex1,line, 0, NULL, 0);
        if (!reti2){
		return latest_jobid;
        }
        else if (reti2 == REG_NOMATCH){
                return -1;
        }
        else{
                return -1;
        }
}

//check whether command is a foreground command using regex
int is_fg(char* line){

	regex_t regex2;
        regex_t regex3;
        int reti3,reti4;
	/* Compile regular expression */
        reti3 = regcomp(&regex2, "^[[:space:]]*fg[[:space:]]+%[[:space:]]*[[:digit:]]+[[:space:]]*$", REG_EXTENDED);
        reti4 = regcomp(&regex3, "^[[:space:]]*fg[[:space:]]*$", REG_EXTENDED);

        if(reti3){
                return -1;
        }
        if(reti4){
                return -1;
        }
        reti3 = regexec(&regex2,line, 0, NULL, 0);
        if (!reti3){
                int job_id = get_job_id(line);
                return job_id;

        }
        else if (reti3 == REG_NOMATCH){}
        else{
                return -1;
        }
	reti4 = regexec(&regex3,line, 0, NULL, 0);
        if (!reti4){
		return latest_jobid;
        }
        else if (reti4 == REG_NOMATCH){
                return -1;
        }
        else{
                return -1;
        }
}

//handler for Ctrl-C (SIGINT signal)
void my_sigint_handler(int sig_number){
	can_wait = 0;
	if(cur_fg_pid != -1){
		kill(cur_fg_pid, SIGKILL);
	}
	else{
		delete(l, cur_fg_pid);
	}
	latest_jobid = -1;
	cur_fg_pid = -1;
	cur_fg_cmd = NULL;
	char* prompt_name = "\nminish:";
	char new_prompt_name[strlen(prompt_name) + strlen(pwd) + 2];
	strcpy(new_prompt_name, prompt_name);
	strcat(new_prompt_name, pwd);
	strcat(new_prompt_name, "> ");
	fwrite(new_prompt_name, sizeof(char), strlen(new_prompt_name)+1, stdout);
	prompt_disp = 1;
	fflush(stdout);
	return;
}

//handler for Ctrl-Z (SIGTSTP signal)
void my_sigtstp_handler(int signo){
	can_wait = 0;
	if(cur_fg_pid == -1){
		return;
	}
	//sending SIGSTP signal to the current foreground process
	int r = kill(cur_fg_pid, SIGTSTP);
	if(r == -1){
		perror("\nerror");
	}
	else{
		printf("\n[%d]+ \tStopped", job_id);
		if(search(l, cur_fg_pid) == 0){
			insert(l, cur_fg_pid, job_id, 3, cur_fg_cmd);
			latest_jobid = job_id;
			++job_id;
		}
		else{
			update(l->head, cur_fg_pid, 3);
			latest_jobid = get_proc(l, cur_fg_pid)->jid;
		}
		cur_fg_pid = -1;
		cur_fg_cmd = NULL;
	}
	//flushing standard output
	fflush(stdout);
	return;
}

//send process to foreground process group (either from suspended state of from background process group)
int send_to_foreground(int jid){
	proc_info *p = get_proc(l, jid);
	if(p == NULL){
		return -1;
	}	
	if(p->status == 3){
		p->status = 1;//changing the status of the process to foreground
		kill(p->pid, SIGCONT);
		cur_fg_pid = p->pid;
		cur_fg_cmd = p->command;
		setpgid(cur_fg_pid, getpgrp());
		int status;
		int k;
		while(can_wait == 1 && (k = kill(p->pid, 0)) == 0);
		if(errno == EPERM){perror("error");}
		if(p->status != 3 && can_wait == 1){
			kill(cur_fg_pid, SIGKILL);
			printf("\n[%d] done!\t%s\n", p->jid, p->command);
			delete(l, cur_fg_pid);
			latest_jobid = -1;
		}
		cur_fg_pid = -1;
		cur_fg_cmd = NULL;
		prompt_disp = 0;
		return 1;
	}
	else if(p->status == 2){
		p->status = 1;
		cur_fg_pid = p->pid;
		setpgid(cur_fg_pid, getpgrp());
		int status;
		int k;
		//need to wait on that process
		while(can_wait == 1 && (k = kill(p->pid, 0)) == 0);
		if(errno == EPERM){perror("error");}
                //if still foreground and can wait (this means that the process has completed execution and needs to be killed)
                if(can_wait == 1 && p->status == 1){
			kill(cur_fg_pid, SIGKILL);
			proc_info* p = get_proc(l, cur_fg_pid);
			printf("\n[%d] done!\t%s\n", p->jid, p->command);
                        delete(l, cur_fg_pid);
                }
		cur_bg_pid = -1;
		latest_jobid = -1;
		free(cur_bg_command);
		tcsetpgrp(STDIN_FILENO, getpid());
		return 1;
	}
	return -1;
}

//send process to background process group from suspended state
int send_to_background(int jid){
	proc_info* p = get_proc(l, jid);
	//if jobid invalid
	if(p == NULL){
		return -1;
	}
	//only a suspended can be continued in background
	if(p->status != 3){
		return -1;
	}
	//need to change the process group of the process to the background process group and then need to send a SIGCONT signal to the process. We return back to the prompt immediately and don't wait.
	setpgid(p->pid, bg_pgrp);
	cur_bg_pid = p->pid;
	int k = kill(p->pid, SIGCONT);	
	if(k == -1){
		perror("error");
		return -1;
	}
	update(p, p->pid, 2); 
	return 1;
}

//execute process in the background
int execute_bg(char* path, char* command){
	int child = fork();
	if(child < 0){
		return 0;
	}	
	if(child == 0){
		char* args[4];
		args[0] = path;
		args[1] = "-c";
		args[2] = command;
		args[3] = (char*)0;
		execvp(path, args);
	}
	else{
		//pid of background process will be one more than the child process
		int bg_pid = child+1;
		if(bg_pgrp == -1){
			setpgid(bg_pid, 0);
			bg_pgrp = bg_pid;
		}
		else{
			setpgid(bg_pid, bg_pgrp);
		}
		insert(l, bg_pid, job_id, 2, command);//background status = 2
		printf("[%d] %d\n", job_id, bg_pid);
		latest_jobid = job_id;
		cur_bg_pid = bg_pid;
		if(cur_bg_command == NULL){cur_bg_command = (char*)malloc(sizeof(char));}
		strcpy(cur_bg_command, command);
		++job_id;
	}
}

//executing any unrecognized command
int execute(char* path, char* command_line){
	//checking whether the command is of type 'cd'
	char* command_type = (char*)malloc(sizeof(char));
	int i = 0;
	//retrieving the type of the command
	for(i = 0; command_line[i] != ' ' && command_line[i] != '\0'; i++){
		command_type[i] = command_line[i];
	}
	if(strcmp(command_type,"cd") == 0){
		int is_just_cd = 0;
		if(strcmp(command_line, "cd") == 0 || strcmp(command_line, "cd ") == 0 || strcmp(command_line, "cd   ") == 0){
			is_just_cd = 1;
		}
		char* dir_path = strrchr(command_line, ' ') + 1;
		int r;
		if(is_just_cd == 1){
			r = chdir(getenv("HOME"));
		}
		else{
			r = chdir(dir_path);
		}
		if(r < 0){
			perror("error");
			return -1;
		}
		//updating the present working directory. Will use pwd to append to prompt
		strcpy(pwd, getcwd(pwd, 1000));
	}
	else{
		int child_pid = fork();
		if(child_pid < 0){
			perror("ERROR: could not fork process.\n");
		}
		if(child_pid == 0){
			char* args[4];
			args[0] = path;
			args[1] = "-c";
			args[2] = command_line;
			args[3] = (char*)0;
			
			//executing the command 
			int exec_return = execvp(path, args);
			if(exec_return == -1){
				perror("error: command execution failed!\n");
			}
			else{
				exit(exec_return);
			}
		}	
		else{
			//assigning cur_fg_pid to the child
			cur_fg_pid = child_pid+1;
			if(cur_fg_cmd == NULL){cur_fg_cmd = (char*)malloc(sizeof(char));}
			strcpy(cur_fg_cmd, command_line);
			int exit_status;
			while(can_wait == 1 && waitpid(child_pid, &exit_status, WUNTRACED) > 0){}
			cur_fg_pid = -1;
			cur_fg_cmd = NULL;
			if(can_wait == 1) latest_jobid = -1;
		}
	}
	return 1;
}

//dispatch the command to any one of functions for execution.
void executor(char *line)
{
	int fg_jobid = is_fg(line);
	int bg_jobid = is_bg(line);
	if(fg_jobid == -1)
	{
		if(bg_jobid == -1)
		{
			execute("/bin/sh",line);
			return;
		}
		else if(bg_jobid == -2){
			if(execute_bg("/bin/sh", line) == 0){
				perror("error");
			}
		}
		else
		{
			if(send_to_background(bg_jobid) == -1){
				printf("No such process!\n");
			}
			return;
		}
	}
	else
	{
		if(send_to_foreground(fg_jobid) == -1){
			printf("No such process!\n");
		}
		return;
	}
}

//constantly listen to command line input and send the input to executor for execution
void shell_listener(){
	char *line;
	int status = 1;
	char ***args;
	int i,j;
	do 
	{
		can_wait = 1;
		prompt_disp = 0;
		//updating the prompt display to show the current working directory
		
		if(prompt_disp == 0){
			char* prompt_name = "\nminish:";
			char new_prompt_name[strlen(prompt_name) + strlen(pwd) + 2];
			strcpy(new_prompt_name, prompt_name);
			strcat(new_prompt_name, pwd);
			strcat(new_prompt_name, "> ");
			printf("\n%s", new_prompt_name);
			prompt_disp = 1;
		}
		//fetching command
		line = command_fetcher();
		char temp[strlen(line)+1];
		strcpy(temp, line);
		temp[strlen(temp)-1] = '\0';
		line = temp;
		if(strcmp(line, "exit") == 0){
			status = 0;
			clear(l);
			exit(EXIT_SUCCESS);
		}
		executor(line);
	} while (status);
}

int main(){
	//initializing the pjid_list
	l = init_pjid_list(l);

	//clearing the screen
	execute("/bin/sh","clear");

	//specifying a signal handler
	signal(SIGINT, my_sigint_handler);
	signal(SIGTSTP, my_sigtstp_handler);

	//initializing present_working_directory
	strcpy(pwd, getcwd(pwd, 1000));
	shell_listener();
	return 0;
}

