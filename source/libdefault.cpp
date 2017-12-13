#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdarg.h>
#include "xrun.h"
#include "mutex_manager.h"
#include "recordentries.hh"
#include "report.h"

extern "C" {
  void initializer (void) __attribute__((constructor));
  void finalizer (void)   __attribute__((destructor));
  bool initialized = false;

	
  __thread thread_t * current = NULL;	
  bool _isMultithreading = false;

  RecordEntries<mutex_t>sync_vars;
	
  void *thread_sync_data;//TODO: for storing thread local mutex data
  
  void initializer (void) {
    // Using globals to provide allocation
    // before initialized.
    init_real_functions();
    xrun::getInstance().initialize();
    sync_vars.initialize(xdefines::MAX_SYNC_ENTRIES);
    thread_sync_data = MM::mmapAllocatePrivate(xdefines::MAX_SYNC_ENTRIES * xdefines::MAX_THREADS * sizeof(thread_mutex_t));	
		

    initialized = true;
  		//fprintf(stderr, "Now we have initialized successfully\n"); 
	
  }

  void finalizer (void) {
    initialized = false;
    xrun::getInstance().finalize();
    Report::getInstance().print(sync_vars);
  }



  // Intercept the pthread_create function.
  int pthread_create (pthread_t * tid, const pthread_attr_t * attr, void *(*start_routine) (void *), void * arg)
  {
    //printf("In my thread_create\n");
    return xthread::getInstance().thread_create(tid, attr, start_routine, arg);
  }

  // Intercept the pthread_join function. Thus, 
  // we are able to know that how many threads have exited.
  int pthread_join(pthread_t thread, void **retval) {
    return xthread::getInstance().thread_join(thread, retval);
	}


#ifndef ADVANCE_STACK_FRAME
# define ADVANCE_STACK_FRAME(next) ((struct layout *) (next))
#endif

struct layout
{
  void *next;
  void *return_address;
};

int backtrace (void **array, int size) {
    struct layout *current;
    void *top_frame;
    void *top_stack;
    int cnt = 0;
    top_frame = __builtin_frame_address (0);
    top_stack = ({ char __csf; &__csf; });
    current = ((struct layout *) top_frame);
    while (cnt < size) {
      if ((void *) current < top_stack || !((void *) current < __libc_stack_end)) break;
        array[cnt++] = current->return_address;
        current = ADVANCE_STACK_FRAME (current->next);
    }
    return cnt;
}
}; 
