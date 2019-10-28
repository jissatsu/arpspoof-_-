#ifndef __OUTPUT_H
#define __OUTPUT_H 1

#include <unistd.h>
#include <stdarg.h>
#include "error.h"
#include "color.h"

int tty;

void v_out( verr_t type, char *format, ... );

#endif