#ifndef BASE64_ENCODE
#define BASE64_ENCODE
int base64_encode(char* input_buffer, int input_length, char* output_buffer, int output_buffer_length, char * lookup_string, int lookup_string_length);
int base64_default_encode(char* input_buffer, int input_length, char* output_buffer, int output_buffer_length);
#endif
