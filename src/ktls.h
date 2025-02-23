#ifndef _KTLS_H
#define _KTLS_H

#include <time.h>

// ktls functions
int ktls_global_init(int childfd, time_t poll_period_millis, int verbosity);
int ktls_serve();

#endif