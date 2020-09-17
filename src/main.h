
#define _CRT_SECURE_NO_WARNINGS

#include <direct.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"
#include "crypto.h"

extern "C" {
	#include "libkirk/sha1.h"
	#include "libkirk/kirk_engine.h"
}

// Multidisc ISO image signature.
char multi_iso_magic[0x10] = {
	0x50,  // P
	0x53,  // S
	0x54,  // T
	0x49,  // I
	0x54,  // T
	0x4C,  // L
	0x45,  // E
	0x49,  // I
	0x4D,  // M
	0x47,  // G
	0x30,  // 0
	0x30,  // 0
	0x30,  // 0
	0x30,  // 0
	0x30,  // 0
	0x30   // 0
};

// ISO image signature.
char iso_magic[0xC] = {
	0x50,  // P
	0x53,  // S
	0x49,  // I
	0x53,  // S
	0x4F,  // O
	0x49,  // I
	0x4D,  // M
	0x47,  // G
	0x30,  // 0
	0x30,  // 0
	0x30,  // 0
	0x30   // 0
};

char pbp_magic[0x4] = {
	0x00,  // .
	0x50,  // P
	0x42,  // B
	0x50   // P
};

char pgd_magic[0x4] = {
	0x00,  // .
	0x50,  // P
	0x47,  // G
	0x44   // D
};