#include "timer.h"
#include <time.h>
#include <iostream>
#include <string>

using namespace std;


double timespec2ms(timespec time);
timespec timespec_diff(timespec start, timespec end);

double time_diff(timespec start, timespec end) {
    return timespec2ms(timespec_diff(start, end));
}

timespec timespec_diff(timespec start, timespec end)
{
    timespec temp;
    if ((end.tv_nsec-start.tv_nsec)<0) {
        temp.tv_sec = end.tv_sec-start.tv_sec-1;
        temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    } else {
        temp.tv_sec = end.tv_sec-start.tv_sec;
        temp.tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return temp;
}

double timespec2ms(timespec time) {
    return ( time.tv_sec * 1000 + (time.tv_nsec / (double)1E6));
}


timespec gettime() {
    timespec temp;
    clock_gettime(CLOCK_MONOTONIC , &temp);
    return temp;
}
