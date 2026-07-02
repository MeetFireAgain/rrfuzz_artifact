/**
 * RR-Fuzz Strace Parser Module Header
 */

#ifndef RR_SYSCALLPARSER_H
#define RR_SYSCALLPARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>

/* Define MAP_ANONYMOUS if not defined */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

#define RR_STRACE_MAX_ARGS 8
#define RR_STRACE_MAX_STRING_LENGTH 256
#define RR_STRACE_MAX_SYSCALL_NAME 64
#define RR_STRACE_MAX_ERROR_MSG 64

typedef enum {
    RR_STRACE_ARG_TYPE_INT,
    RR_STRACE_ARG_TYPE_PTR,
    RR_STRACE_ARG_TYPE_STR
} rr_strace_arg_type_t;

typedef struct {
    long value;
    char str[RR_STRACE_MAX_STRING_LENGTH];
    rr_strace_arg_type_t type;
} rr_strace_arg_t;

typedef struct {
    int pid;
    char syscall_name[RR_STRACE_MAX_SYSCALL_NAME];
    rr_strace_arg_t args[RR_STRACE_MAX_ARGS];
    int arg_count;
    long ret_value;
    int error_code;
    char error_msg[RR_STRACE_MAX_ERROR_MSG];
    int has_error;
    unsigned long flags;
} rr_strace_record_t;

typedef struct {
    FILE *trace_file;
    rr_strace_record_t *records;
    size_t record_count;
    size_t current_index;
    int loaded;
    char *filename;
} rr_strace_parser_t;

/* API Function Declarations */
rr_strace_parser_t *rr_strace_parser_init(const char *filename);
int rr_strace_parser_load(rr_strace_parser_t *parser);
rr_strace_record_t *rr_strace_parser_get_next(rr_strace_parser_t *parser);
void rr_strace_parser_reset(rr_strace_parser_t *parser);
void rr_strace_parser_cleanup(rr_strace_parser_t *parser);
int rr_strace_get_syscall_number(const char *syscall_name);
int rr_strace_parse_line(char *line, rr_strace_record_t *record);
void rr_strace_print_record(const rr_strace_record_t *record);
void rr_strace_get_stats(rr_strace_parser_t *parser, size_t *total_records, size_t *current_index);

/* Helper Function Declarations */
long rr_strace_parse_number(const char *str);
rr_strace_arg_type_t rr_strace_identify_arg_type(const char *arg_str);
int rr_strace_parse_flags(const char *flag_str, const char *syscall_name, int arg_index);

#endif /* RR_SYSCALLPARSER_H */
