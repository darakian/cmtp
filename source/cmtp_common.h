// Copyright (c) 2015 by Jon Moroney. All Rights Reserved.
#ifndef _cmtp_common_h
#define _cmtp_common_h

static const char filesystem_safe_base64_string[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";

char* last_str_split(char* a_str, const char * a_delim);

int resolve_server(char * hostname, struct sockaddr_storage * result);

int write_to_file(char * buffer, int buffer_length, char * filename);

int create_verify_dir(char * path);

int initlog(char * log_name);

int generate_unique_string();

void print_to_log(char * message, int level);

int set_privilage(char * user);

int init_jail(char * jail_dir);

int enter_jail(char * jail_directory, char * new_user);

void print_buffer (const char * buffer, int count, char * desc, int max, int print_eol);

int32_t read_n_bytes(uint32_t socket, char * reception_buffer, uint64_t n);

int32_t read_until(uint32_t socket, char * reception_buffer, uint32_t reception_buffer_size, char terminator);


#endif /* _cmtp_common_h */
