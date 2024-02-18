#pragma once  

#include <stdexcept> 

using namespace std; 

class os_error : public runtime_error{ 
    public:
        os_error(const char * what) : runtime_error(what){};
}; 

string hex_number(unsigned char byte){
    stringstream stream; 
    stream << setfill('0') << setw(2) << hex << +((unsigned int)(byte)); 
    return stream.str();
}