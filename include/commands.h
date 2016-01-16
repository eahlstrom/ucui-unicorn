#ifndef __commands_h
#define __commands_h

#define MAX_CMD 255

typedef enum _command_state {
  MORE_COMMANDS,
  DONE_PROCESSING,
} command_state;

typedef command_state (*CmdHandler)(uc_engine *uc, uint64_t ip, char *args);

typedef struct _sCommand {
  char *name;
  CmdHandler handler;
  char *desc;
  struct _sCommand *next;
} Command;

Command *cmds;

command_state runcmd(uc_engine *uc, uint64_t ip, char *command);
Command *create_command(char *name, CmdHandler handler, char *desc);
void add_command(Command *root, Command *addcmd);
Command *init_commands(void);

// utilities
void hexdump_uint8(uint8_t *code, unsigned int len, uint64_t baseaddress);
void hexdump_uint16(uint8_t *code, unsigned int len, uint64_t baseaddress);
void hexdump_uint32(uint8_t *code, unsigned int len, uint64_t baseaddress);
void hexdump_uint64(uint8_t *code, unsigned int len, uint64_t baseaddress);

#endif
