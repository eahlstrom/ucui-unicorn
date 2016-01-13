#ifndef __ucui_readline_h
# define __ucui_readline_h

#define RL_PROMPT "cmd$ "

char *readline_command;
int ucui_readline_init(void);
void forward_to_readline(char c);

#endif
