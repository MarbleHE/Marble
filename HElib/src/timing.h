/* Copyright (C) 2012-2017 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
/**
 * @file timing.h
 * @brief Utility functions for measuering time
 * 
 * This module contains some utility functions for measuring the time that
 * various methods take to execute. To use it, we insert the macro
 * FHE_TIMER_START at the beginning of the method(s) that we want to time and
 * FHE_TIMER_STOP at the end, then the main program needs to call the function
 * setTimersOn() to activate the timers and setTimersOff() to pause them. 
 * To obtain the value of a given timer (in seconds), the application can
 * use the function getTime4func(const char *fncName), and the function
 * printAllTimers() prints the values of all timers to an output stream.
 *
 * Using this method we can have at most one timer per method/function, and
 * the timer is called by the same name as the function itself (using the
 * built-in macro \_\_func\_\_). We can also use the "lower level" methods
 * startFHEtimer(name), stopFHEtimer(name), and resetFHEtimer(name) to add
 * timers with arbitrary names (not necessarily associated with functions).
 **/
#ifndef _TIMING_H_
#define _TIMING_H_


#include "NumbTh.h"
#include "multicore.h"


class FHEtimer;
void registerTimer(FHEtimer *timer);
unsigned long GetTimerClock();

//! A simple class to accumulate time
class FHEtimer {
public:
  const char *name;
  const char *loc;

  // THREADS: these need to be atomic
  FHE_atomic_ulong counter;
  FHE_atomic_long numCalls;

  FHEtimer(const char *_name, const char *_loc) :
    name(_name), loc(_loc), counter(0), numCalls(0) 
  { registerTimer(this); }

  void reset();
  double getTime() const;
  long getNumCalls() const;
};


// backward compatibility: timers are always on
inline void setTimersOn()  { }
inline void setTimersOff() { }
inline bool areTimersOn()  { return true; }

const FHEtimer *getTimerByName(const char *name);


void resetAllTimers();

//! Print the value of all timers to stream
void printAllTimers(std::ostream& str=std::cerr);

// return true if timer was found, false otherwise
bool printNamedTimer(ostream& str, const char* name);


//! \cond FALSE (make doxygen ignore these classes)
class auto_timer {
public:
  FHEtimer *timer;
  unsigned long amt;
  bool running;

  auto_timer(FHEtimer *_timer) : 
    timer(_timer), amt(GetTimerClock()), running(true) { }

  void stop() {
    amt = GetTimerClock() - amt; 
    timer->counter += amt;
    timer->numCalls++;
    running = false;
  }

  ~auto_timer() { if (running) stop(); }
};
//! \endcond


// NOTE: the STOP functions below are not really needed,
// but are provided for backward compatibility

#define FHE_STRINGIFY(x) #x
#define FHE_TOSTRING(x) FHE_STRINGIFY(x)
#define FHE_AT __FILE__ ":" FHE_TOSTRING(__LINE__)

#define FHE_stringify_aux(s) #s
#define FHE_stringify(s) FHE_stringify_aux(s)

#define FHE_TIMER_START \
  static FHEtimer _local_timer(__func__, FHE_AT); \
  auto_timer _local_auto_timer(&_local_timer)
  
#define FHE_TIMER_STOP  _local_auto_timer.stop()


#define FHE_NTIMER_START(n) \
  static FHEtimer _named_local_timer ## n(# n, FHE_AT ); \
  auto_timer _named_local_auto_timer ## n(&_named_local_timer ## n)

#define FHE_NTIMER_STOP(n)    _named_local_auto_timer ## n.stop();



#endif // _TIMING_H_
