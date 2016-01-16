#include "ucui.h"
// 
// kudoz to ulfalizer (https://github.com/ulfalizer/readline-and-ncurses.git)
//

// Input character for readline.
static unsigned char input;

// Used to signal "no more input" after feeding a character to readline.
static bool input_avail = false;

static int readline_getc(FILE *dummy) {
    input_avail = false;
    return input;
}

static void readline_redisplay(void) {
    size_t curs_pos = strlen(rl_display_prompt) + rl_point;

    werase(cmdw);
    mvwprintw(cmdw, 0, 0, "%s%s", rl_display_prompt, rl_line_buffer);
    wmove(cmdw, 0, curs_pos);
    wrefresh(cmdw);
}

static int readline_input_avail(void) {
    return input_avail;
}

static void run_prev_command(void)
{
    HIST_ENTRY *he = history_get(where_history());

    if (he == NULL) {
        strcpy(readline_command, "help");
    } else {
        strncpy(readline_command, he->line, MAX_CMD);
    }
}

void forward_to_readline(char c) {
    input = c;
    input_avail = true;
    if (c == '\n' && rl_point == 0) {
        run_prev_command();
        return;
    }
    rl_callback_read_char();
}

void command_entered(char *line) {
    HIST_ENTRY *he;

    if (line == NULL) {
        return;
    } else if (*line != '\0') {
        he = previous_history();
        if (he == NULL || strcmp(he->line, line) != 0) 
            add_history(line);
        strncpy(readline_command, line, MAX_CMD);
    }
}

int ucui_readline_init(void)
{
    cmds = init_commands();
    readline_command = xmalloc(MAX_CMD+1);
    
    using_history();

    // Disable completion. TODO: Is there a more robust way to do this?
    rl_bind_key('\t', rl_insert);

    // Let ncurses do all terminal and signal handling.
    rl_catch_signals = 0;
    rl_catch_sigwinch = 0;
    rl_deprep_term_function = NULL;
    rl_prep_term_function = NULL;

    // Prevent readline from setting the LINES and COLUMNS environment
    // variables, which override dynamic size adjustments in ncurses. When
    // using the alternate readline interface (as we do here), LINES and
    // COLUMNS are not updated if the terminal is resized between two calls to
    // rl_callback_read_char() (which is almost always the case).
    rl_change_environment = 0;

    // Handle input by manually feeding characters to readline.
    rl_getc_function = readline_getc;
    rl_input_available_hook = readline_input_avail;
    rl_redisplay_function = readline_redisplay;
    rl_callback_handler_install(RL_PROMPT, command_entered);

    return(0);
}
