/*
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

/*
 * @file   finetime.c
 * @brief  Fine timing management based on rdtsc.
 * @author Mejbah<mohammad.alam@utsa.edu>
 */

#include <time.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "finetime.h"

//double cpu_freq = 2000000; //KHz

// (dleoni) Get the CPU freq from make
// (Thanks to Daniel Castro)

#ifdef CPU_FREQ
  double cpu_freq = CPU_FREQ; //KHz
#else
  double cpu_freq = 2000000;  //KHz
#endif

/*
void get_tsc( struct timeinfo *ti )
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  ti->low  = lo;
  ti->high = hi;
}
*/

// (dleoni) Read the value of TSC before grabbing the lock, preventing memory reordering using the assembly instruction CPUID as a barrier
// Credits to Gabriele Paoloni
// https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf

void get_tsc (struct timeinfo *ti) {

  unsigned cycles_high, cycles_low;
  asm volatile (
    "CPUID\n\t"
    "RDTSC\n\t"
    "mov %%edx, %0\n\t"
    "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");
  ti -> low = cycles_low;
  ti -> high = cycles_high;
}

// (dleoni) Read the value of TSC after having grabbed the lock: use RDTSCPto ensure that the code that acquires the lock is completed.
// The call to CPUID provides a barrier which guarantees that no successive instruction is executed before RDTSCP
// RDTSCP also guarantees the measurement of the CPU cycles is synchronizedacross all the cores
// Credits to Gabriele Paoloni
// https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf

void get_tscp (struct timeinfo *ti) {

  unsigned cycles_high, cycles_low;
  asm volatile (
    "RDTSCP\n\t"
    "mov %%edx, %0\n\t"
    "mov %%eax, %1\n\t"
    "CPUID\n\t": "=r" (cycles_high), "=r" (cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
  ti -> low = cycles_low;
  ti -> high = cycles_high;
}


unsigned long get_elapsed_cycle( struct timeinfo *start, struct timeinfo *stop)
{
	
	unsigned long begin = ( (unsigned long )start->low)|( ((unsigned long )start->high)<<32 );
	unsigned long  end = ( (unsigned long )stop->low)|( ((unsigned long )stop->high)<<32 );
	if( stop->high < start->high)
	{
		return (TSC_MAX - begin)+end;
	}
	else {
		return end - begin;
	}
}

/**
 * TODO: not right way to count time, but works for fine for performance compare purpose
 */
double get_elapsed2ms( struct timeinfo *start, struct timeinfo *stop)
{
	if(stop==NULL){
		struct timeinfo end;
		// (dleoni) Use more accurate cycles measurement
		//get_tsc(&end);
		get_tscp(&end);
		return (double)get_elapsed_cycle(start,&end)/ cpu_freq;
	}
	else {
		// (dleoni) Use more accurate cycles measurement
		//get_tsc(&stop);
		get_tscp(&stop);
		return (double)get_elapsed_cycle(start,stop) / cpu_freq;
	}
}

void start(struct timeinfo *ti)
{
	/* Clear the start_ti and stop_ti */
	get_tsc(ti);
	return;
}

