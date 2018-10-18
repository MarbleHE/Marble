#pragma once
#ifndef MARBLE_TIMER_H
#define MARBLE_TIMER_H

#include <time.h>
#include <string>


double time_diff(timespec start, timespec end);

timespec gettime();


#endif //MARBLE_TIMER_H
