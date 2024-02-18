#pragma once   

#include <iostream>
#include <string>


using namespace std; 

string main_line; 
int log_mode = 0;

void print_main_line(string line){ 
    main_line = line; 
    cout << "\33[2K\r" << "[[(())]]: " <<  main_line << flush; 
}; 

void print(string line){
    cout << "\33[2K\r" << line << "\n" << "[[(())]]: " << main_line << flush;  
}; 

