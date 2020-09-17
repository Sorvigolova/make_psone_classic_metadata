
#define _CRT_SECURE_NO_WARNINGS
#define MAX_PATH _MAX_PATH

#include <stdlib.h>
#include <string.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

// Auxiliary functions (endian swap, xor, prng and file name).
short se16(short i);
int se32(int i);
u64 se64(u64 i);
void xor(unsigned char *dest, unsigned char *src1, unsigned char *src2, int size);
void prng(unsigned char *dest, int size);
char* extract_file_name(const char* file_path, char real_file_name[MAX_PATH]);

// Hex string conversion auxiliary functions.
u64 hex_to_u64(const char* hex_str);
void hex_to_bytes(unsigned char *data, const char *hex_str, unsigned int str_length);
bool is_hex(const char* hex_str, unsigned int str_length);
bool isEmpty(unsigned char* buf, int buf_size);