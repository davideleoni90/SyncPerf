#ifndef _REPORT_H_
#define _REPORT_H_

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "xdefines.h"
#include "recordentries.hh"
#include "mutex_manager.h"
#include <map>
#include <vector>
#include <stdexcept>
#include <set>

// (dleoni) Include to use backtrace
#include <execinfo.h>

// (dleoni) Include to demangle C++ function names
#include <cxxabi.h>

#define MAXBUFSIZE 4096
#define COMBINED_REPORT 1

/*
 * @file   report.h
 * @brief  Reporting utilities for SyncPerf
 * @author Mejbah<mohammad.alam@utsa.edu>
 */



#ifdef REPORT_LINE_INFO
//Map for call stack and conflict rate
typedef std::map< std::string, std::vector<double> > Map;
#endif


typedef struct {
	char line_info[MAX_NUM_STACKS][MAX_CALL_STACK_DEPTH * 50];
	double conflict_rate;
	double frequency;
	int count; //number of line info
}sync_perf_t;

typedef struct {
	UINT32 access_count;
	UINT32 fail_count;
	char call_site[MAX_CALL_STACK_DEPTH * 50];
}call_site_info_t;


class Report {

private:
	char _curFilename[MAXBUFSIZE];
	Report(){}
 	

public:
	static Report& getInstance() {
		static Report instance;
        	return instance;		
	}	

	enum { THRESHOLD_CONFLICT = 5 };
	enum { THRESHOLD_FREQUENCY = 1 }; //per millisecond

	std::string exec (const char* cmd) {
		//std::cout << "exec CMD: " << cmd << std::endl; //TODO: remove this
    		FILE* pipe = popen(cmd, "r");
    		if (!pipe) {
			fprintf( stderr, "Could not pipe in exec function\n" );
			return "ERROR";
		}
    	
		char buffer[128];
    		std::string result = "";
    		while (!feof(pipe)) {
        	if (fgets(buffer, 128, pipe) != NULL){
			//printf("%s", buffer); //TODO: remove this
			result += buffer;
		}
    		}
    		pclose(pipe);
		return result;
	}

	void setFileName(){
		int count = readlink("/proc/self/exe", _curFilename, MAXBUFSIZE);
		if (count <= 0 || count >= MAXBUFSIZE)
		{
       			fprintf(stderr, "Failed to get current executable file name\n" );
			exit(1);
    		}
    		_curFilename[count] = '\0';
	
	}

  // (dleoni) For each frame in the call stack, extract a string:
  // function_name|offset
  // The c-string in input is as follows:
  // module_name(mangled_function_name+offset) [return_address]

  std::string parse_stack_frame(char* frame) {
    
    // Convert to std::string becaue it's easier to handle
    std::string frame_string = std::string(frame);

    // Get the mangled function name
    int first_parenthesis = frame_string.find("(");
    int plus_sign = frame_string.find("+");
    if ((first_parenthesis == std::string::npos) || (plus_sign == std::string::npos) || (!(plus_sign - first_parenthesis - 1)))
       return "---";
    std::string function = frame_string.substr(first_parenthesis+1, plus_sign - first_parenthesis - 1 );

    // Demangle the function name
    size_t funcnamesize = 256;
    char* funcname = (char*)malloc(funcnamesize);
    int status;
    char* demangled = abi::__cxa_demangle(function.c_str(), funcname, &funcnamesize, &status);
    if (!status) {
       function = std::string(demangled);
    }
     
    // Get the offset
    int second_parenthesis = frame_string.find(")");
    std::string offset = frame_string.substr(plus_sign + 1, second_parenthesis - plus_sign - 1);
    if ((second_parenthesis == std::string::npos) || (!(second_parenthesis - plus_sign - 1)))
       return "---"; 

    // return function_name|offset
    return function + "|" + offset;
    
  }

  //std::string get_call_stack_string( long *call_stack ){
  std::string get_call_stack_string( void **call_stack ){

    //char _curFilename[MAXBUFSIZE];
    //int count = readlink("/proc/self/exe", _curFilename, MAXBUFSIZE);
    //if (count <= 0 || count >= MAXBUFSIZE)
    //{
    //  fprintf(stderr, "Failed to get current executable file name\n" );
    //  exit(1);
    //}
    //_curFilename[count] = '\0';


		
    char buf[MAXBUFSIZE];
    std::string stack_str="";
    
    // (dleoni) Array of strings, each corresponding to a stack frame
    char **strings;
    int j=0;
    // (dleoni) Get the string representaion of the stack frame
    strings = backtrace_symbols(call_stack, MAX_CALL_STACK_DEPTH+1);
    // (dleoni) Parse each stack frame (skip the current function)
    for (j = 1; j < MAX_CALL_STACK_DEPTH+1; j++) {
        if(!std::string(strings[j]).compare("[(nil)]")) continue;
        std::string frame = parse_stack_frame(strings[j]);
	if (!frame.compare("---"))
		continue;
	stack_str += frame;
        stack_str += "\n";
    }
    free(strings);
    /*while(call_stack[j] != 0 ) {
      //printf("%#lx\n", m->stacks[i][j]);  
      sprintf(buf, "addr2line -e %s  -a 0x%lx  | tail -1", _curFilename, call_stack[j] );
      std::string source_line =  exec(buf);
      if(source_line[0] != '?') { // not found
        //get the file name only
        std::size_t found = source_line.find_last_of("/\\");
        source_line = source_line.substr(found+1);
        stack_str += source_line.erase(source_line.size()-1); // remove the newline at the end
        stack_str += " ";
      }
      j++;
    }*/
    return stack_str;
  }

#if 0
	void updateCallSiteInfo( std::map<size_t, call_site_info_t>& call_site_map, UINT32 access_count, UINT32 fail_count, size_t call_site, std::string context ){
		std::map<size_t, call_site_info_t>::iterator it = call_site_map.find(call_site);
		if(it != call_site_map.end()){
			it->second.access_count += access_count;
			it->second.fail_count += fail_count;
		}
		else{
			call_site_info_t new_context;
			new_context.access_count = access_count;
			new_context.fail_count = fail_count;
			strcpy(new_context.call_site, context.c_str());
			call_site_map[call_site] = new_context;
		}

	}
#endif

	
#ifdef REPORT_LINE_INFO
	void updateCallStackMap( Map& call_stack_map, std::string call_contexts, double conflict_rate){
		
		Map::iterator it = call_stack_map.find(call_contexts);
		if(it != call_stack_map.end()){
			it->second.push_back(conflict_rate);
		}
		else{
			std::vector<double>new_entry;
			new_entry.push_back(conflict_rate);
			call_stack_map.insert( Map::value_type(call_contexts,new_entry) );
		}

	}

	void findAsymmetricLock( Map& call_stack_map, std::vector<std::string>&results ){
		for(Map::iterator it = call_stack_map.begin(); it != call_stack_map.end(); it++){
			//std::cout << it->first << std::endl;
			//find  variance in it->second vector conflict rates
			if(it->second.size()>1){
				std::vector<double>::iterator iter = it->second.begin();
				float min,max;
				min  = max = *iter;
				for(; iter != it->second.end(); iter++){
					if(min > *iter){
						min = *iter;
					}
					if( max < *iter){
						max = *iter;
					}
				}
				if((max -min) > 10){ //Threshold for conflict rate difference, TODO: use variance algorithm
					results.push_back(it->first);
				}
			}
		}
	}

	void printCallStackMap( Map& call_stack_map ){
		for(Map::iterator it = call_stack_map.begin(); it != call_stack_map.end(); it++){
			std::cout << it->first << std::endl;
		}				
	}
#endif

	void print( RecordEntries<mutex_t>&sync_vars ){

#ifdef REPORT_LINE_INFO
		//set the file exe for lineinfo
		setFileName();
#endif

		std::cout<< "\n\nSyncPerf Msg: END OF PROGRAM";
		
		std::cout<< "\nSyncPerf Msg: Reporting in file: syncperf.report\nSyncPerf Msg: Thread reports in file: thread.csv " << std::endl;
#ifdef COMBINED_REPORT
		std::vector<sync_perf_t>high_conflict_low_freq;
		std::vector<sync_perf_t>high_conflict_high_freq;
		std::vector<sync_perf_t>low_conflict_high_freq;
#else

		std::fstream qhh_fs;
		std::fstream qhl_fs;
		std::fstream qlh_fs;
		qhh_fs.open("synperf_1.report", std::fstream::out);
		qhl_fs.open("synperf_2.report", std::fstream::out);
		qlh_fs.open("synperf_3.report", std::fstream::out);

		//high conflict, high frequency
		qhh_fs << "\n\n==============================" << std::endl;
		qhh_fs << "HIGH CONFLICT , HIGH FREQUENCY" << std::endl;
		qhh_fs << "==============================" << std::endl;

		//high conflict, low frequency
		qhl_fs << "\n\n==============================" << std::endl;
		qhl_fs << "HIGH CONFLICT , LOW FREQUENCY" << std::endl;
		qhl_fs << "==============================" << std::endl;	

		//low conflict, high frequency
		qlh_fs << "\n\n==============================" << std::endl;
                qlh_fs << "LOW CONFLICT , HIGH FREQUENCY" << std::endl;
		qlh_fs << "==============================" << std::endl;

		unsigned long qhh_count = 0;
		unsigned long qlh_count = 0;
		unsigned long qhl_count  = 0;
#endif
	  	int total_threads = xthread::getInstance().getMaxThreadIndex();
		unsigned long total_levels = xthread::getInstance().getTotalThreadLevels();

		WAIT_TIME_TYPE *thread_waits = malloc(sizeof(WAIT_TIME_TYPE)*total_threads);
		for(int idx=0; idx<total_threads; idx++) thread_waits[idx] = 0;	
#if 0	
		std::fstream thd_fs;
		thd_fs.open("thread_waits.csv", std::fstream::out);
		thd_fs << "tid, type, runtime, wait_time" << std::endl; 
		for(int idx=0; idx< total_threads; idx++){
			thread_t *thd = xthread::getInstance().getThreadInfoByIndex(idx);
			thd_fs << idx << ", " << std::hex <<(void*)( thd->startRoutine)<< ", " <<std::dec<< thd->actualRuntime << "," <<  thread_waits[idx]  << std::endl;
		}
#endif
		unsigned long total_thread_levels=xthread::getInstance().getTotalThreadLevels();

		threadLevelInfo *thd_level = xthread::getInstance().getThreadLevelByIndex(total_thread_levels);
#if 0
		thd_fs << "Elapsed time " << thd_level->elapse << std::endl;
#endif
		//double elapsed_time_for_freq = thd_level->elapse; //milliseconds
		double elapsed_time_for_freq = thd_level->elapse < 1000 ? 1000 : thd_level->elapse; //TODO: remove this, use the previous line instead
#if 0		
		thd_fs.close();	
#endif 

		//std::map<size_t, call_site_info_t>call_site_map;
		
#ifdef REPORT_LINE_INFO
		Map call_stack_map;
#endif
		int total_sync_vars = sync_vars.getEntriesNumb();

		int id = 0; //for debugging puporse, shoud match with total locks
		int total = 0;

		// A map with one key for each pthread_mutex_t* and multiple values corresponding to all the mutex_t that are
		// pointed by it (duplicates)
		std::multimap<pthread_mutex_t*, mutex_t*> sync_vars_unique;		

		// Find the duplicates
		for(int i=0; i < total_sync_vars; i++) {
			
			mutex_t *m = sync_vars.getEntry(i);
			sync_vars_unique.insert(std::pair<pthread_mutex_t*, mutex_t*>(m -> nominalmutex, m));
		}

		// Get the statistics for each pthread_mutex_t, for each mutex_t , for each thread
		for (std::multimap<pthread_mutex_t*, mutex_t*>::iterator it = sync_vars_unique.begin(); it != sync_vars_unique.end(); it = sync_vars_unique.upper_bound(it->first)) {

			// A key
			pthread_mutex_t* key = it -> first;

			std::cout << sync_vars_unique.count((*it).first) - 1 << " " << (*it).first << " DUPLICATES" << std::endl;
			
			// For debug only and for stats
			id++;
			total += sync_vars_unique.count((*it).first);
			
			// Statistics to be collected for each pthread_mutex_t (key)
			unsigned int total_access_count = 0;
			unsigned int total_fail_count = 0;
			unsigned int total_cond_wait = 0;
			unsigned int total_trylock_fails = 0;
			WAIT_TIME_TYPE total_wait_time = 0;
			WAIT_TIME_TYPE total_lock_wait = 0;			
			
			// The entry in the final report corresponding to the current pthread_mutex_t*	
			sync_perf_t sync_perf_entry;

			// The set of the call stacks ending with an acquisition of the current mutex
			std::set<std::string> call_stacks;

			// The counter for the number of stack traces that end with the acquisition of the current mutex
			sync_perf_entry.count = 0;
			
			// Get all the mutex_t (values) corresponding to the current pthred_mutex_t* (key)
			std::pair <std::multimap<pthread_mutex_t*, mutex_t*>::iterator, std::multimap<pthread_mutex_t*, mutex_t*>::iterator> values_iterator;
			// The first field points to the first value, second to the last value 
			values_iterator = sync_vars_unique.equal_range(key);
			
			// For each mutex_t (value) corresponding to the pthread_mutex_t (key), aggregate values over threads
			for (std::multimap<pthread_mutex_t*, mutex_t*>::iterator ite = values_iterator.first; ite != values_iterator.second; ++ite) {
				
				// A value
				mutex_t* value = ite -> second;
		
				// Sum all the thread local data
				for (int idx = 0; idx < total_threads; idx++ ) {
					//count
			  		thread_mutex_t *per_thd_data = get_thread_mutex_data( value->entry_index, idx);
					total_access_count += per_thd_data->access_count;
					total_fail_count += per_thd_data->fail_count;
					total_cond_wait += per_thd_data->cond_waits;
					total_trylock_fails += per_thd_data->trylock_fail_count;
					//times
					total_wait_time += per_thd_data->cond_futex_wait;
					total_lock_wait += per_thd_data->futex_wait;
					thread_waits[idx] += (per_thd_data->cond_futex_wait + per_thd_data->futex_wait);
				}

				// Add the call stacks for the current value to those corresponding to the current key
				for(int con=0; con < value -> stack_count; con++) {
#ifdef REPORT_LINE_INFO
					std::string call_contexts = get_call_stack_string(value -> stacks[con]);		
					
					//update call stack map
					//updateCallStackMap(call_stack_map, call_contexts,sync_perf_entry.conflict_rate);
#else
					int depth = 0;
			  		std::string call_contexts = "";
					while(value->stacks[con][depth]){	
							call_contexts += "0x";
							//call_contexts += std::to_string(m->stacks[con][depth]);
							std::stringstream ss;
							ss << std::hex << value->stacks[con][depth] << std::dec;
							call_contexts += ss.str();
							call_contexts += ",";
							depth++; 
					}									
#endif					
					
					// (dleoni) With C++ the name of a function may be very long
					assert(call_contexts.size() <= MAX_CALL_STACK_DEPTH * 200);
					//strcpy(sync_perf_entry.line_info[con], call_contexts.c_str());

					std::cout << "Key:" << key << " Value:" << value << std::endl;
					std::cout << "Stack count:" << value -> stack_count << std::endl;
					std::cout << call_contexts << std::endl;

					// Store the current call stack in the set of call stacks
					call_stacks.insert(call_contexts);
				}
			}
		
			// The access_count has to be positive
			if (!total_access_count) {
				std::cout << "Skipped mutex:" << key << "Duplicates:" << sync_vars_unique.count(key) - 1 << std::endl;
				continue;
			}
				
			// Set the aggregated statistics for the current mutex	
			sync_perf_entry.conflict_rate = (100*total_fail_count)/double(total_access_count);
			sync_perf_entry.frequency  = double(total_access_count)/elapsed_time_for_freq; //TODO: fix freqeuncey using max thd->actualRuntim

			// Set the call stacks for the current mutex
			int stack = 0;
			for (std::set<std::string>::iterator stack_it = call_stacks.begin(); stack_it != call_stacks.end(); ++stack_it) {
				strcpy(sync_perf_entry.line_info[stack], (*stack_it).c_str());
				stack++; 
			}

			// Update the counter of call stacks with the current mutex
			sync_perf_entry.count = stack;

			std::cout << "Key:" << key << " Stack count:" << stack << std::endl;

			// Now, depending on the conflict rate and frequency acquisition, check whether the mutex is to printed in one of
			// the reports

			if (sync_perf_entry.conflict_rate > THRESHOLD_CONFLICT) {

				if( sync_perf_entry.frequency > THRESHOLD_FREQUENCY ) {
#ifdef COMBINED_REPORT
					high_conflict_high_freq.push_back(sync_perf_entry);
#else
					qhh_count++;
					report_quadrant(qhh_fs, sync_perf_entry, qhh_count);
#endif
				}
				else {
#ifdef COMBINED_REPORT
					high_conflict_low_freq.push_back(sync_perf_entry);
#else
					qhl_count++;
					report_quadrant(qhl_fs, sync_perf_entry, qhl_count);
#endif
				}
				}
			else {
				if( sync_perf_entry.frequency > THRESHOLD_FREQUENCY ) {
					//print call stacks
#ifdef COMBINED_REPORT
					low_conflict_high_freq.push_back(sync_perf_entry);
#else
					qlh_count++;
					report_quadrant(qlh_fs, sync_perf_entry, qlh_count);	
#endif
				}
			}	
		}
/*
		for(int i=0; i<total_sync_vars; i++) {

			mutex_t *m = sync_vars.getEntry(i);
			assert(m->entry_index == i);
			
			unsigned int total_access_count = 0;
			unsigned int total_fail_count = 0;
			unsigned int total_cond_wait = 0;
			unsigned int total_trylock_fails = 0;
			WAIT_TIME_TYPE total_wait_time = 0;
			WAIT_TIME_TYPE total_lock_wait = 0;			

			// sum all thread local data
			for(int idx=0; idx<total_threads; idx++ ){
				//count
			  	thread_mutex_t *per_thd_data = get_thread_mutex_data( m->entry_index, idx);
				total_access_count += per_thd_data->access_count;
				total_fail_count += per_thd_data->fail_count;
				total_cond_wait += per_thd_data->cond_waits;
				total_trylock_fails += per_thd_data->trylock_fail_count;
				//times
				total_wait_time += per_thd_data->cond_futex_wait;
				total_lock_wait += per_thd_data->futex_wait;
			
				thread_waits[idx] += (per_thd_data->cond_futex_wait + per_thd_data->futex_wait);
			}

			sync_perf_t sync_perf_entry;
			sync_perf_entry.count = 0;
			if( total_access_count > 0 ) { //TODO: access_count = 0 is poosible as fix setSyncEntry ignores new mutex ,index already increased in recordentries
				printf("TOPEX:%p\n", m->nominalmutex);
                        	fflush(stdout);	
				id++; //for debug only and for stats

				sync_perf_entry.conflict_rate = (100*total_fail_count)/double(total_access_count);
				sync_perf_entry.frequency  = double(total_access_count)/elapsed_time_for_freq; //TODO: fix freqeuncey using max thd->actualRuntim

				//print call stacks
				for(int con=0; con<m->stack_count; con++){
#ifdef REPORT_LINE_INFO
					std::string call_contexts = get_call_stack_string(m->stacks[con]);		
					//update call stack map
					updateCallStackMap(call_stack_map, call_contexts,sync_perf_entry.conflict_rate);
#else
					int depth = 0;
			  		std::string call_contexts = "";
					while(m->stacks[con][depth]){	
							call_contexts += "0x";
							//call_contexts += std::to_string(m->stacks[con][depth]);
							std::stringstream ss;
							ss << std::hex << m->stacks[con][depth] << std::dec;
							call_contexts += ss.str();
							call_contexts += ",";
							depth++; 
					}									
#endif					
					//assert(call_contexts.size() <= MAX_CALL_STACK_DEPTH * 50);
					// (dleoni) With C++ the name of a function may be very long
					assert(call_contexts.size() <= MAX_CALL_STACK_DEPTH * 200);
					strcpy(sync_perf_entry.line_info[con], call_contexts.c_str());
					sync_perf_entry.count++;
				}
			
				
				if( sync_perf_entry.conflict_rate > THRESHOLD_CONFLICT ){

					if( sync_perf_entry.frequency > THRESHOLD_FREQUENCY ){
#ifdef COMBINED_REPORT
						high_conflict_high_freq.push_back(sync_perf_entry);
#else
						qhh_count++;
						report_quadrant(qhh_fs, sync_perf_entry, qhh_count);
#endif
					}
					else{
#ifdef COMBINED_REPORT
						high_conflict_low_freq.push_back(sync_perf_entry);
#else
						qhl_count++;
						report_quadrant(qhl_fs, sync_perf_entry, qhl_count);
#endif
					}
				}
				else{
					if( sync_perf_entry.frequency > THRESHOLD_FREQUENCY ){
						//print call stacks
#ifdef COMBINED_REPORT
						low_conflict_high_freq.push_back(sync_perf_entry);
#else
						qlh_count++;
						report_quadrant(qlh_fs, sync_perf_entry, qlh_count);	
#endif
					}
				}
			}
		}
*/
		std::fstream thd_fs;

		thd_fs.open("thread_waits.csv", std::fstream::out);
		thd_fs << "tid, type, runtime, wait_time" << std::endl; 

		for(int idx=0; idx< total_threads; idx++){
			thread_t *thd = xthread::getInstance().getThreadInfoByIndex(idx);
			thd_fs << idx << ", " << std::hex <<(void*)( thd->startRoutine)<< ", " <<std::dec<< thd->actualRuntime << ", " <<  thread_waits[idx]  << std::endl;
		}

		
		//thd_fs << "Elapsed time " << thd_level->elapse << std::endl;
		thd_fs.close();
	
#ifdef COMBINED_REPORT
		std::fstream fs;
		fs.open("syncperf.report", std::fstream::out);
		
		//high conflict, high frequency
		fs << "\n\n==============================" << std::endl;
		fs << "HIGH CONFLICT , HIGH FREQUENCY" << std::endl;
		fs << "==============================" << std::endl;
		write_report(fs, high_conflict_high_freq);

		//high conflict, low frequency
		fs << "\n\n==============================" << std::endl;
		fs << "HIGH CONFLICT , LOW FREQUENCY" << std::endl;
		fs << "==============================" << std::endl;
		write_report(fs, high_conflict_low_freq);

		//low conflict, high frequency
		fs << "\n\n==============================" << std::endl;
		fs << "LOW CONFLICT , HIGH FREQUENCY" << std::endl;
		fs << "==============================" << std::endl;
		write_report(fs, low_conflict_high_freq);


#ifdef REPORT_LINE_INFO
		//find asymmetric locks
		//printCallStackMap(call_stack_map);
		std::vector<std::string>asym_locks;
		findAsymmetricLock(call_stack_map,asym_locks);
		
		if(asym_locks.size()>0){
			fs << "\n\n======================"<< std::endl;
			fs << "Asymmetric Locks found :\t" << asym_locks.size() <<   std::endl;
			fs << "========================" << std::endl;
			for( std::vector<std::string>::iterator it = asym_locks.begin(); it != asym_locks.end(); it++){
				fs << *it << std::endl;
			}
		
		}
#endif
		fs.close();
#endif
#ifdef GET_STATISTICS
		std::cout<< "STATISTICS:\n";
		std::cout<< "\tTotal Threads: " << total_threads << std::endl;
		std::cout<< "\tTotal read mutex_t: " << total << std::endl;
                std::cout<< "\tTotal fake mutex_t: " << total_sync_vars << std::endl;
		std::cout<< "\tTotal Levels: " << total_levels << std::endl;
		std::cout<< "\tTotal Thread levels: " << total_thread_levels << std::endl;
		std::cout<< "\tTotal Distinct Locks: " << id << std::endl;
		std::cout<< "\tTotal Acquired Locks: " << totalLocks << std::endl;
		std::cout<< "\tTotal Conflicts: " << totalConflicts << std::endl;
		std::cout<< "\tTotal CondWaits: " << totalCondWaits << std::endl;
#endif
		
		//std::cout << total_threads << " threads, " << id <<  " mutexes\n";
		
		

	}

	void write_report( std::fstream& fs, std::vector<sync_perf_t>& results){
		fs << "Total found : " << results.size() << std::endl;
		std::vector<sync_perf_t>::iterator it;
		int id = 0;
		for( it=results.begin(); it != results.end(); it++ ){
			id++;
			fs << "No."<< id << std::endl;
			fs << "-------" << std::endl;
			fs << "Conflict Rate: " << it->conflict_rate << std::endl;
			fs << "Acquisition Frequency: " << it->frequency << std::endl;
			fs << "Line Numbers: " << it->count << std::endl;
			for( int i=0; i<it->count; i++ ){
				fs << it->line_info[i] << std::endl;
			}	
		}

	}

	void report_quadrant( std::fstream& fs, sync_perf_t sync_perf_entry,int count){
		fs << "# " << count << std::endl;
		fs << "-------" << std::endl;
		fs << "\t\tConflict Rate: " << sync_perf_entry.conflict_rate << std::endl;
		fs << "\t\tAcquisition Frequency: " << sync_perf_entry.frequency << std::endl;
		fs << "\t\tLine Numbers: " << sync_perf_entry.count << std::endl;
		for( int i=0; i<sync_perf_entry.count; i++ ){
			fs << "\t\t\t" << sync_perf_entry.line_info[i] << std::endl;
		}	
	}	

};

#endif
