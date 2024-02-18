#include <iostream> 
#include <thread> 
#include <chrono> 
#include <string.h> 
#include <signal.h>
#include "header_files/node.h"

using namespace std; 
/*
Tested functions: 
    * start_reader()  
    * make_outbound_connection() 
    * add_unestablished_peer() 
    * sha256() 
    * msg.to_byte_array()  
    * *send_message() 
    * read_from_socket()  
    * read_message 
    * parse_message()

*/ 

/* 
Testing:  
  
   
    
*/
int main(){  
    //signal(SIGPIPE, SIG_IGN); 

    node nd; 
    nd.start_node();
    //nd.make_outbound_connection("127.0.0.1", 10);

    while(1){
        this_thread::sleep_for(chrono::milliseconds(1000));
    }
}