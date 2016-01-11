#ifndef __commands_h
#define __commands_h

#define MAX_CMD 255

enum command_state {
  MORE_COMMANDS,
  DONE_PROCESSING,
};

char *last_command;
enum command_state runcmd(uc_engine *uc, uint64_t ip, char *command);

#endif
