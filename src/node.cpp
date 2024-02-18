#include <iostream>  
#include <unistd.h> 
#include <string.h> 
#include <thread> 
#include <chrono> 
#include <fstream> 
#include <random> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <memory> 
#include <fcntl.h> 
#include <iomanip> 
#include <poll.h>

#include "header_files/node.h"   
#include "header_files/misc.h" 
#include "header_files/logger.h"
#include "crypto++_lib/sha.h"

using namespace std; 


node::node(){
    this->curr_peer_id = 0;  
    this->node_count = 1; 
} 

void node::start_node(){  
    //configure logger
    log_mode = 0;  

    this->start_reader();  
   
    try{
        this->listener_thread.reset( new thread([this](){ this->start_server();}));  
        print_main_line("LISTENER_THREAD Spun Up Sucsessfully!");
    }
    catch(system_error e){ 
        print_main_line("(X) Failed To Spin Up LISTENER THREAD");
        throw e; 
    }  

    print_main_line("CONNECTING TO SEED PEERS...");
    this->plant_network_seed();   

    log_mode = 1; 
    print_main_line("GROWING NETWORK, CONNECTING TO MORE PEERS...");
    this->grow_network();
    
    while(1){
        this_thread::sleep_for(chrono::milliseconds(1000));
    }
}

/*
    @brief starts reader thread, which runs read_messages()
*/
void node::start_reader(){ 
    print_main_line("Spinning Up READER_THREAD ...");
    try{
        this->reader_thread.reset( new thread([this](){
            read_messages();
        }));  
        print_main_line("READER_THREAD Spun Up Sucsessfully!");
    }
    catch(system_error e){ 
        print_main_line("(X) Failed To Spin Up READER_THREAD");
        throw e; 
    }
} 

/*
    @brief loops through the peers list and reads any data avaliable. If there's data, parses it and  
    starts the a handler thread to handle it
*/
int node::read_messages(){  
    print_main_line("READER_THREAD -> READER_THREAD RUNNING...");

    while(1){
        for(pair<const unsigned int, peer>& peer_entry : this->peers){  
            //read data from socker
            unsigned int peer_id = peer_entry.first;
            peer* p = &peer_entry.second;   
           
            vector<byte_t> data = this->read_from_socket(p->socket); 
            //cout << "READER_THREAD -> Reading From Peer-" + to_string(peer_id) + "..." << endl; 
            
            //if no data then go to next peer, else parse data and make handler thread to 
            //handler the data  
            if(data.size() > 0){  
                print("READER_THREAD -> " + to_string(data.size()) + " Bytes Read From Peer-" + to_string(peer_id)); 
                print("READER_THREAD -> Read From Peer-" + to_string(peer_id) + ": ");
                //print_msg_bytes(data); 

                vector<shared_ptr<message>> messages = this->parse_messages(data);  

                if(messages.size() != 0){ //if message was parsable 
                    print("Peer-" + to_string(peer_id) + " Parsed Messages:"); 
                    print("**********");
                    for(shared_ptr<message>& msg: messages){ 
                        if(msg->command != MESSAGE_TYPE_INV){ //FILTER OUT INV MESSAGES
                            msg->print_msg(); 
                        }
                    }   
                    print("**********");


                    shared_ptr<thread> handler_thread( new thread([this, peer_id, messages](){ 
                        print("READER_THREAD -> Spinning Up Handler Thread for Peer-" + to_string(peer_id)); 
                        handle_messages(messages, peer_id);  
                    }));  
                    print("READER_THREAD -> Spun Up Handler Thread For Peer-" + to_string(peer_id) + " Sucsesfully!");  

                    this->handler_threads.push_back(handler_thread);
                } 
            }

            this_thread::sleep_for(chrono::milliseconds(READ_SLEEP_TIME_MS)); 
        } 
    }
}

/*
    @brief reads all the data from a socket
*/
vector<byte_t> node::read_from_socket(socket_t socket){ 
    vector<byte_t> data;
    byte_t buffer[500]; 
    
    int retval = read(socket, buffer, 500);  
    while(retval > 0 ){  
        unsigned int size = data.size();
        data.resize(size + retval);
        memcpy(&data[size], buffer, retval);  

        retval = read(socket, buffer, 500); 
    }

    return data; 
}  

vector<shared_ptr<message>> node::parse_messages(vector<byte_t> message_bytes){
    vector<shared_ptr<message>> messages;
    int s = 0; 
    char command[12]; 
    
    while( s < message_bytes.size()){
        memcpy(command, &message_bytes[s + 4], 12);  

        /*** verack msg ***/
        if (strcmp(command, "verack") == 0){ 
            shared_ptr<verack_message> curr_message(new verack_message); 
            s += 24;  
            messages.push_back(curr_message);
        } 
        /*** version msg ***/
        else if(strcmp(command, "version") == 0){ 
            shared_ptr<version_message> curr_message(new version_message);
            
            //get payload_size
            memcpy(&curr_message->payload_size, &message_bytes[s + 16], 4);
            //get checksum
            memcpy(curr_message->checksum, &message_bytes[s+20], 4); 
            
            int p = s + 24; 
            //get version field 
            memcpy(&curr_message->version, &message_bytes[p], 4); 
            p += 4;
            //get services 
            memcpy(&curr_message->services, &message_bytes[p], 8); 
            p += 8;
            //get timestamp 
            memcpy(&curr_message->timestamp, &message_bytes[p], 8); 
            p += 8; 
            //get addr_recv_services 
            memcpy(&curr_message->addr_recv_services, &message_bytes[p], 8); 
            p += 8; 
            //get addr_recv_IP_address 
            memcpy(&curr_message->addr_recv_IP_address, &message_bytes[p], 16); 
            p += 16; 
            //get addr_recv_port
            memcpy(&curr_message->addr_recv_IP_address, &message_bytes[p], 2); 
            p += 2;  
            //get addr_trans_services 
            memcpy(&curr_message->addr_trans_services, &message_bytes[p], 8); 
            p += 8;  
            //get addr_trans_IP_address 
            memcpy(&curr_message->addr_trans_IP_address, &message_bytes[p], 16); 
            p += 16; 
            //get addr_trans_port
            memcpy(&curr_message->addr_trans_IP_address, &message_bytes[p], 2); 
            p += 2;   
            //get nonce 
            memcpy(&curr_message->nonce, &message_bytes[p], 8); 
            p += 8; 
            //get relay 
            p = s + 24 + curr_message->payload_size - 1; 
            memcpy(&curr_message->relay, &message_bytes[p], 1); 
            //get start_height
            p -= 4; 
            memcpy(&curr_message->start_height, &message_bytes[p], 4); 
            //get user_agent bytes ehh...  

            s += (24 + curr_message->payload_size);  
            messages.push_back(curr_message);  
        }  
        /*** addr msg ***/
        else if(strcmp(command, "addr") == 0){ 
            shared_ptr<addr_message> curr_message(new addr_message);
        
            //get payload_size
            memcpy(&curr_message->payload_size, &message_bytes[s + 16], 4);
            //get checksum
            memcpy(curr_message->checksum, &message_bytes[s+20], 4);  

            //parse payload
            s += 24;  

            //get mem size of ip_addy_count then get value  
            // mod 30 is used bbecause the message has a variable sized ip count 
            //field and each ip address is represented with 30 bytes  
            curr_message->ip_addy_count = curr_message->payload_size/30; 
            s += curr_message->payload_size % 30;   

            //get ip address entries via looping 
            for(unsigned int i = 0; i < curr_message->ip_addy_count; i++){
                addr_entry entry; 
                //get time 
                memcpy(&entry.time, &message_bytes[s], 4); 
                s += 4; 
                //get services 
                memcpy(&entry.services, &message_bytes[s], 8); 
                s += 8; 
                //get IP addy 
                memcpy(entry.ip_addy, &message_bytes[s], 16); 
                s += 16;  
                //get port  (store in little edian)
                byte_t * ptr = (byte_t *)&entry.port; 
                ptr[0] = message_bytes[s +1]; 
                ptr[1] = message_bytes[s]; 
                s += 2; 

                curr_message->ip_addys.push_back(entry);
            } 

            messages.push_back(curr_message); 

        }    
        /*** sendheaders msg ***/
        else if(strcmp(command, "sendheaders") == 0){
            shared_ptr<sendheaders_message> curr_message(new sendheaders_message); 
            s += 24;  
            messages.push_back(curr_message);
        } 
        /*** sendCmpct ***/ 
        else if(strcmp(command, "sendcmpct") == 0){
            shared_ptr<sendcmpct_message> curr_message(new sendcmpct_message); 

            //get payload_size
            memcpy(&curr_message->payload_size, &message_bytes[s + 16], 4);
            //get checksum
            memcpy(curr_message->checksum, &message_bytes[s+20], 4); 
            
            //parse payload
            s += 24;
            //get announce field 
            memcpy(&curr_message->announce, &message_bytes[s], 1); 
            s += 1;
            //get cmpct version  
            memcpy(&curr_message->version, &message_bytes[s], 8);  
            s += 8;  

            messages.push_back(curr_message);
        } 
        /*** ping ***/ 
        else if(strcmp(command, "ping") == 0){
            shared_ptr<ping_message> curr_message(new ping_message); 

            //get payload_size
            memcpy(&curr_message->payload_size, &message_bytes[s + 16], 4);
            //get checksum
            memcpy(curr_message->checksum, &message_bytes[s+20], 4); 
            
            //parse payload
            s += 24;
            //get nonce field 
            memcpy(&curr_message->nonce, &message_bytes[s], 8); 
            s += 8; 

            messages.push_back(curr_message);  
        } 
        /*** pong ***/ 
        else if(strcmp(command, "pong") == 0){
            shared_ptr<pong_message> curr_message(new pong_message); 

            //get payload_size
            memcpy(&curr_message->payload_size, &message_bytes[s + 16], 4);
            //get checksum
            memcpy(curr_message->checksum, &message_bytes[s+20], 4); 
            
            //parse payload
            s += 24;
            //get nonce field 
            memcpy(&curr_message->nonce, &message_bytes[s], 8); 
            s += 8; 

            messages.push_back(curr_message);  
        } 
        /*** getheaders ***/ 
        else if(strcmp(command, "getheaders") == 0){
            shared_ptr<getheaders_message> curr_message(new getheaders_message); 

            //get payload_size
            memcpy(&curr_message->payload_size, &message_bytes[s + 16], 4);
            //get checksum
            memcpy(curr_message->checksum, &message_bytes[s+20], 4);  

            //parse payload 
            s += 24; 
            //get version 
            memcpy(&curr_message->version, &message_bytes[s], 4); 
            s += 4; 
            //get hash count  (each hash is 32 bytes)
            unsigned int hash_count_bytes = (curr_message->payload_size - 4) % 32; 
            memcpy(&curr_message->hash_count, &message_bytes[s], hash_count_bytes); 
            s += hash_count_bytes;  
            //get block header hashes 
            for(unsigned int i = 0; i < curr_message->hash_count; i++){
                vector<byte_t> hash; 
                hash.resize(32); 
                memcpy(&hash[0], &message_bytes[s], 32); 
                curr_message->block_header_hashes.push_back(hash); 
                s += 32;
            } 
            //get stop hash 
            curr_message->stop_hash.resize(32); 
            memcpy(&curr_message->stop_hash[0], &message_bytes[s], 32); 
            s += 32;  

            messages.push_back(curr_message);
        } 
        /*** inv***/ 
        else if(strcmp(command, "inv") == 0){
            shared_ptr<inv_message> curr_message(new inv_message); 

            //get payload_size
            memcpy(&curr_message->payload_size, &message_bytes[s + 16], 4);
            //get checksum
            memcpy(curr_message->checksum, &message_bytes[s+20], 4);  

            //parse payload 
            s += 24;  
            s += curr_message->payload_size;

            messages.push_back(curr_message);
        }
        else{ //can't parse message  
            print("(X) ERROR PARSING MESSAGE");
            return vector<shared_ptr<message>>();
        }
       
        /*** TODO: add more message type parsing here ***/
    }  

    return messages;
} 

void node::handle_messages(vector<shared_ptr<message>> messages, unsigned int peer_id){
    for( shared_ptr<message> msg : messages){
        switch(msg->command){
            case MESSAGE_TYPE_VERACK:  
            { 
                print("HANDLER_THREAD-> Handleing VERACK Message From Peer-" + to_string(peer_id) + "...");
                this->peers[peer_id].verack_recvd = true; 
                if(this->peers[peer_id].version_recvd){
                    this->peers[peer_id].established = true; 
                    this->node_count++;  

                    if(log_mode == 0){
                        print_main_line( "CONNECTING TO SEED PEERS... NETWORK SIZE: " + to_string(this->node_count) + " peers!"); 
                    }
                    else if(log_mode == 1){
                        print_main_line( "GROWING NETWORK, CONNECTING TO MORE PEERS... NETWORK SIZE: "  + to_string(this->node_count) + " peers!");
                    }
                }  
 
                print("HANDLER_THREAD-> Sucsessfully Handled VERACK Message From Peer-" + to_string(peer_id) + "!");
                break; 
            } 
            case MESSAGE_TYPE_VERSION: 
            {   
                print("HANDLER_THREAD-> Handleing VERSION Message From Peer-" + to_string(peer_id) + "...");
                peer* curr_peer = &this->peers[peer_id];
                curr_peer->version_recvd = true; 
                if(curr_peer->verack_recvd){
                    curr_peer->established = true; 
                    this->node_count++;  
                    if(log_mode == 0){
                        print_main_line( "CONNECTING TO SEED PEERS... NETWORK SIZE: " + to_string(this->node_count) + " peers!"); 
                    }
                    else if(log_mode == 1){
                        print_main_line( "GROWING NETWORK, CONNECTING TO MORE PEERS... NETWORK SIZE: "  + to_string(this->node_count) + " peers!");
                    }
                }  
                //set peer data    
                shared_ptr<version_message> v_msg = dynamic_pointer_cast<version_message>(msg);
                curr_peer->version = v_msg->version; 
                curr_peer->services = v_msg->services; 
                memcpy(curr_peer->IP_address, v_msg->addr_trans_IP_address, 16); 
                curr_peer->port = v_msg->addr_trans_port; 
                curr_peer->start_height = v_msg->start_height; 
                curr_peer->relay = v_msg->relay;  

                //send verack message to acknowledge peer's version msg
                verack_message verack_msg;  
                print("HANDLER_THREAD-> Handeling VERSION Message From Peer-" + to_string(peer_id) + "--- Sending VERACK msg");  
                this->send_message(peer_id, verack_msg);   
                print("HANDLER_THREAD-> Sucsessfully Handled VERSION Message From Peer-" + to_string(peer_id) + "!");
                
                break; 
            } 
            case MESSAGE_TYPE_ADDR:  
            { 
                print("HANDLER_THREAD-> Handleing ADDR Message From Peer-" + to_string(peer_id) + "...");
                this->peers[peer_id].rx_queue.push_back(msg);  
                print("HANDLER_THREAD-> Sucsessfully Handled ADDR Message From Peer-" + to_string(peer_id) + "!");
                break; 
            }    
            case MESSAGE_TYPE_SENDHEADERS:
            {
                print("HANDLER_THREAD-> Handleing SENDHEADERS Message From Peer-" + to_string(peer_id) + "...");
                this->peers[peer_id].send_headers = true; 
                print("HANDLER_THREAD-> Sucsessfully Handled SENDHEADERS Message From Peer-" + to_string(peer_id) + "!");
                break; 
            } 
            case MESSAGE_TYPE_SENDCMPCT: 
            {
                print("HANDLER_THREAD-> Handleing SENDCMPCT Message From Peer-" + to_string(peer_id) + "...");
                shared_ptr<sendcmpct_message> sendcmpct_msg = dynamic_pointer_cast<sendcmpct_message>(msg);
                this->peers[peer_id].cmpct_announce = sendcmpct_msg->announce; 
                this->peers[peer_id].cmpct_version = sendcmpct_msg->version;  
                print("HANDLER_THREAD-> Sucsessfully Handled SENDCMPCT Message From Peer-" + to_string(peer_id) + "!");
                break; 
            } 
            case MESSAGE_TYPE_PING: 
            {
                print("HANDLER_THREAD-> Handleing PING Message From Peer-" + to_string(peer_id) + "...");
                shared_ptr<ping_message> ping_msg = dynamic_pointer_cast<ping_message>(msg);
                
                //send pong message 
                pong_message pong_msg; 
                pong_msg.nonce = ping_msg->nonce; 
                send_message(peer_id, pong_msg);

                print("HANDLER_THREAD-> Sucsessfully Handled PING Message From Peer-" + to_string(peer_id) + "!");
                break; 
            } 
            case MESSAGE_TYPE_PONG: 
            {
                print("HANDLER_THREAD-> Handleing PONG Message From Peer-" + to_string(peer_id) + "...");
                //nothing to do
                print("HANDLER_THREAD-> Sucsessfully Handled PONG Message From Peer-" + to_string(peer_id) + "!");
                break;
            } 
            case MESSAGE_TYPE_GETHEADERS:
            {
                print("HANDLER_THREAD-> Handleing GETHEADERS Message From Peer-" + to_string(peer_id) + "...");
                // TODO: for now send an empy headers message, as I have no blocks, but fix later 
                headers_message headers_msg; 
                send_message(peer_id, headers_msg);
                print("HANDLER_THREAD-> Sucsessfully Handled GETHEADERS Message From Peer-" + to_string(peer_id) + "!");
                break;
            } 
            case MESSAGE_TYPE_INV:
            {
                print("HANDLER_THREAD-> Handleing INV Message From Peer-" + to_string(peer_id) + "...");
                // TODO: fix later 
                print("HANDLER_THREAD-> Sucsessfully Handled INV Message From Peer-" + to_string(peer_id) + "!");
                break;
            }
            default:
            { 
                break; 
            }   
        }
    }
} 

void node::plant_network_seed(){ 
    ifstream seed_file(SEED_FILE);  
    if(!seed_file.is_open()){ 
        print_main_line("(X) Seed File Failed To Open");
        throw os_error("Seef File Failed To Open");
    } 

    string ip_addy;
    while(getline(seed_file, ip_addy)){ 
        //attempt to connect and make unestablished peer  
        socket_t sock;
        sock = this->make_outbound_connection(ip_addy, MAINNET_PORT); 
        if(sock == -1){
            continue; 
        } 

        this->establish_connection(sock, ip_addy, MAINNET_PORT);
    }   


    // wait for sometime for version/verack exchanges to establish connection 
    // which is handled by the reader thread, if not established by then, remove
    this_thread::sleep_for(chrono::milliseconds(ESTABLISH_PEER_WAIT_TIME_MS));    
    //this->clean_unestablished_peers();
            
    print_main_line("Planted Network Seed!!! Inital Network Size: " + to_string(this->node_count) + " Nodes!"); 
}   

version_message node::make_version_message(unsigned char * recv_ip_address, uint16_t recv_port){
    version_message version_msg; 

    version_msg.version = 70015; 
    version_msg.services = 0x01; 
    version_msg.timestamp = chrono::system_clock::to_time_t(chrono::system_clock::now()); 
    memcpy(version_msg.addr_recv_IP_address, recv_ip_address, 16); 
    version_msg.addr_recv_port = recv_port; 
    version_msg.addr_trans_services = 0x01;   
    //put current nodes ipv4 address in ipv6 format
    memset(version_msg.addr_trans_IP_address, 0, 16); 
    version_msg.addr_trans_IP_address[10] = (byte_t) 12;  
    version_msg.addr_trans_IP_address[11] = (byte_t) 12; 
    version_msg.addr_trans_IP_address[12] = (byte_t) 35;  
    version_msg.addr_trans_IP_address[13] = (byte_t) 212; 
    version_msg.addr_trans_IP_address[14] = (byte_t) 26;  
    version_msg.addr_trans_IP_address[15] = (byte_t) 178;  

    version_msg.addr_trans_port = MAINNET_PORT;  

    //get a random number between 1 and 10000 for nonce 
    random_device rd;
    uniform_int_distribution<> distro(1, 1000); 
    version_msg.nonce = (uint64_t) distro(rd);  

    version_msg.user_agent_bytes = 0; 

    //get block chain height from data/block_chain.txt 
    ifstream block_chain_file(BLOCK_CHAIN_FILE); 
    string line; 
    getline(block_chain_file, line); 
    try{
        version_msg.start_height = (uint32_t) stoi(line);
    }
    catch(invalid_argument e){
        print_main_line("(X) Block Chain File Malformated, Could Not Get Start Height");
        throw e; 
    }

    version_msg.relay = true;  
    version_msg.payload_size = 86;
    return version_msg;

} 

int node::send_message(unsigned int peer_id, message &msg){ 
    print("Sending Message To Peer-" + to_string(peer_id) + "..."); 
    print("**********");  
    msg.print_msg();
    print("**********");
   
    //get byte array of message and send via socked_fd 
    vector<byte_t> vector_msg = msg.to_byte_array();  
    byte_t msg_buffer[vector_msg.size()]; 
    memcpy(msg_buffer, &vector_msg[0], vector_msg.size());   

    int retval = send(this->peers[peer_id].socket, msg_buffer, vector_msg.size(), MSG_NOSIGNAL);  
      

    if(retval < 0){ 
        print("(X) Failed To Send Message");
        if(this->peers[peer_id].established){
            this->peers[peer_id].established = false;  
            this->node_count--; 
        } 
        close(this->peers[peer_id].socket);
        return retval;
    }   

    print("Sucsessfully Sent Message As " + to_string(retval) + "Bytes To Peer-" + to_string(peer_id));
    return retval;
}

int node::make_outbound_connection(string ip_addy, uint16_t port){ 
    //check for invalid IPs 
    if((ip_addy[0] == '0') || (ip_addy.substr(0,3).compare("127") == 0)){
        return -1;
    }

    print("Making Outbound Connection To " + ip_addy + "...");

    //make socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0); 
    if (server_sock == -1){  
        print("(X) Failed To Make OutBound Connection To " + ip_addy);
        return -1;
    } 

    //make address structure to ip_address, to connect socket to 
    struct sockaddr_in server_addy;  
    memset(&server_addy, 0, sizeof(sockaddr_in));
    server_addy.sin_family = AF_INET; 
    server_addy.sin_port = htons(port); 
    inet_pton(AF_INET, ip_addy.c_str(), &server_addy.sin_addr);  
    
    //try to connect untill timeout, then giveup
    fcntl(server_sock, F_SETFL, O_NONBLOCK); 
    connect(server_sock, (const sockaddr *)&server_addy, sizeof(server_addy));  
    pollfd pfd_struct; 
    pfd_struct.fd = server_sock; 
    pfd_struct.events = POLLOUT; 
    poll(&pfd_struct, 1, CONNECT_TIMEOUT);
    if( (pfd_struct.revents & POLLOUT) == 0 || (pfd_struct.revents & POLLERR) != 0 ){ 
        print("(X) Failed To Make OutBound Connection To " + ip_addy);
        return -1;
    }  
    
    print("Successfully Made OutBound Connection To " + ip_addy + "!");
    return server_sock; 
}  

unsigned int node::add_unestablished_peer(int peer_socket, string peer_ip_addy, unsigned int peer_port){ 
    //TODO: add ip address param 
    print("Adding Unestablished Peer [socket: " + to_string(peer_socket) + ", ip_address: " + peer_ip_addy + ", port: " + to_string(peer_port) +  "]...");
    //get new id for new peer
    unsigned int peer_id = this->curr_peer_id; 
    this->curr_peer_id++; 

    //make peer and init 
    peer curr_peer(peer_id, peer_socket, peer_ip_addy, peer_port, false);

    //add peer to peer map 
    this->peers[peer_id] = curr_peer;   
    print("Successfully Added Unestablished Peer [socket: " + to_string(peer_socket) + ", ip_address: " + peer_ip_addy + ", port: " + to_string(peer_port) +  "] As Peer-" + to_string(peer_id) );
    return peer_id; 
}  

void node::start_server(){    
    print_main_line("LISTENER THREAD -> Initalizing Server...");

    //make socket
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0); 
    if(sock < 0){ 
        print_main_line("LISTENER THREAD -> (X) Server Init Failed - Socket Creation");
        throw os_error("Server Socket Creation Failed");
    }
 
    //create addr struct and bind
    struct sockaddr_in server_addr; 
    memset(&server_addr, 0, sizeof(sockaddr_in)); 
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(MAINNET_PORT); 
    server_addr.sin_addr.s_addr = INADDR_ANY;   

    if( bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){ 
        print_main_line("(X) Server Init Failed - Socket Binding");
    } 

    listen(sock, 10); 
    this->server_sock = sock; 

    print_main_line( "LISTENER THREAD -> Successfully Initalized Server, Listening For Inbound Connections..."); 
    //listen for inbound connections
    while(1){ 
        struct sockaddr_in client_addr; 
        socklen_t client_addr_len = sizeof(sockaddr_in); 
        memset(&client_addr, 0, client_addr_len); 

        socket_t client_sock = accept(sock, (sockaddr*)&client_addr, &client_addr_len); 
        if(client_sock > 0){  

            //get string version of IP from 32bit int (sin_addr)
            string peer_ip_addy ="";  
            byte_t * ptr = (byte_t *)&client_addr.sin_addr;  
            for(unsigned int i = 0; i < 4; i++){
                peer_ip_addy.append(to_string(ptr[i]));  
                if(i != 3){
                    peer_ip_addy.append("."); 
                }
            }  

                //check for invalid IPs 
                if((peer_ip_addy[0] == '0') || (peer_ip_addy.substr(0,3).compare("127") == 0)){
                    continue;
                }
            print("LISTENER THREAD -> Attempting To Connect To Inbound Connection at " + peer_ip_addy);
            //try to establish connection 
            this->establish_connection(client_sock, peer_ip_addy, client_addr.sin_port); 
        }
    } 
} 

void node::clean_unestablished_peers(){
    vector<unsigned int> peers_to_remove;
    for(pair<const unsigned int, peer>& kvp : this->peers){ 
        peer& curr_peer = kvp.second; 
        if(!curr_peer.established){  
            unsigned int peer_id = kvp.first;
            peers_to_remove.push_back(peer_id);
        }
    }  
    for(unsigned int peer_id : peers_to_remove){
        this->peers.erase(peer_id); 
 //       cout << "(X) Removing Unestablish Connection Peer-" << to_string(peer_id) << endl;  
    }           
} 

void node::establish_connection(socket_t peer_sock, string peer_ip_addy, unsigned int peer_port){ 
    
    //add peer who we connected to but haven't established p2p level connection
    unsigned int peer_id = this->add_unestablished_peer(peer_sock, peer_ip_addy, peer_port);
    
    //convert ip_addy string into char array for version message
    unsigned char addr_recv_IP_address[16]; 
    ip_string_to_array(peer_ip_addy, addr_recv_IP_address); 

    //make version message and send it
    version_message v_msg = this->make_version_message(addr_recv_IP_address, MAINNET_PORT);  
    this->send_message(peer_id, v_msg);  
} 

void node::grow_network(){ 
    //make list of orignal peers as the list will change 
    vector<unsigned int> org_peer_ids; 
    for(pair<const unsigned int, peer>& peer_kvp: this->peers){ 
        if(peer_kvp.second.established){
            org_peer_ids.push_back(peer_kvp.first); 
        } 
    } 

    //make get_addr msg and send to every orginal peer 
    getaddr_message getaddr_msg;  
    for(unsigned int peer_id : org_peer_ids){ 
        if(!this->peers[peer_id].established) continue; 
        this->send_message(peer_id, getaddr_msg);
    } 
    //wait for network stuff to happen
    this_thread::sleep_for(chrono::milliseconds(60000)); 

    //check for addr msgs and connect to the provided ip addresses
    //for each orginal peer
    for(unsigned int peer_id : org_peer_ids){ 
        //skip unconnected nodes
        if(!this->peers[peer_id].established) continue; 

        vector<shared_ptr<message>> addr_msgs = this->peers[peer_id].get_rx_msgs(MESSAGE_TYPE_ADDR); 
        if(addr_msgs.size() == 0){
            continue; 
        } 
        //for each addr message from one peer
        for(shared_ptr<message>& msg : addr_msgs){
            shared_ptr<addr_message> addr_msg = dynamic_pointer_cast<addr_message>(msg); 
            //for each ip addy in from one addr message from one peer  
            for(addr_entry& addr_ent : addr_msg->ip_addys){ 
                if(this->peers.size() >= MAX_PEERS){
                    goto DONE_GROWING;
                }
                string ip = ip_array_to_string(addr_ent.ip_addy, 12); 
                unsigned int sock = this->make_outbound_connection(ip, addr_ent.port);  
                if(sock != -1){
                    this->establish_connection(sock, ip, addr_ent.port); 
                }  
            } 
        } 
    }   

    DONE_GROWING: /*LABEL*/
    //wait for network stuff to happen
    this_thread::sleep_for(chrono::milliseconds(60000));  

    //clean unestablish nodes
    //this->clean_unestablished_peers();  
    
    print_main_line("Network Established, Final Network Size: " + to_string(this->node_count) + " Nodes!");
}

peer::peer(unsigned int peer_id, socket_t peer_socket, string ip_addy, unsigned int peer_port, bool established){
    this->peer_id = peer_id;
    this->socket = peer_socket; 
    this->ip_addy = ip_addy;   
    ip_string_to_array(ip_addy, this->IP_address);  
    this->port = peer_port; 

    this->established = false; 
    this->verack_recvd = false; 
    this->version_recvd = false; 
    this->version = 0; 
    this->services = 0;  
    this->start_height = 0; 
    this->relay = false; 
} 

peer::peer(){ 
    this->send_headers = false;
};  

vector<shared_ptr<message>> peer::get_rx_msgs(MESSAGE_TYPE msg_type){
    //return subqueue of all rx msgs of type msg_type
    vector<shared_ptr<message>> msgs; 
    for(shared_ptr<message>& msg : this->rx_queue){
        if(msg->command == msg_type){
            shared_ptr<message> entry(msg.get()); 
            msgs.push_back(entry);  
        }
    } 
    return msgs;
}






message::message(){ 
    memcpy(this->start_string, START_STRING, 4);
    this->command = MESSAGE_TYPE_NONE;
    this->payload_size = 0; 
    checksum[0] = 0x5d; 
    checksum[1] = 0xf6; 
    checksum[2] = 0xe0; 
    checksum[3] = 0xe2;
}  

vector<byte_t> message::header_to_byte_array(){
    vector<byte_t> byte_array; 

    unsigned int org_size = 0; 

    //add start_string to array
    byte_array.resize(4); 
    memcpy(&byte_array[0], this->start_string, 4);
    //add command_name to array  
    org_size = byte_array.size(); 
    byte_array.resize(org_size + 12); 
    memcpy(&byte_array[org_size], this->command_name, 12); 
    //add payload_size to array 
    org_size = byte_array.size(); 
    byte_array.resize(org_size + 4); 
    memcpy(&byte_array[org_size], &this->payload_size, 4); 
    //add checksum to array 
    org_size = byte_array.size(); 
    byte_array.resize(org_size + 4); 
    memcpy(&byte_array[org_size], this->checksum, 4); 

    return byte_array;
} 

void message::print_header(){ 
    string temp = "start_string: ";
    for(unsigned int i = 0; i < 4; i++){ 
        temp += "0x" + hex_number((unsigned char) this->start_string[i]) + " ";
    } 
    print(temp);

    print( "command: " + string(this->command_name)); 

    print("payload_size: " + std::to_string(this->payload_size)); 

    temp = "checksum: ";
    for(unsigned int i = 0; i < 4; i++){
        temp += "0x" + hex_number((unsigned char) this->checksum[i]) +  " ";
    } 
    print(temp);      
}

verack_message::verack_message(){
    this->command = MESSAGE_TYPE_VERACK;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "verack"); 
} 

vector<byte_t> verack_message::to_byte_array(){ 
    return header_to_byte_array(); 
} 

void verack_message::print_msg(){
    print("VERACK MSG ["); 
    this-> print_header(); 
    print("]");  

}

version_message::version_message(){ 
    this->command = MESSAGE_TYPE_VERSION;   
    memset(this->command_name, 0, 12);
    strcpy(this->command_name, "version");
    this->version = 0; 
    this->services = 0; 
    this->timestamp = 0; 
    this->addr_recv_services = 0; 
    memset(this->addr_recv_IP_address, 0, 16); 
    this->addr_recv_port = 0; 
    this->addr_trans_services = 0; 
    memset(this->addr_trans_IP_address, 0, 16);
    this->addr_trans_port = 0; 
    this->nonce = 0; 
    this->user_agent_bytes = 0; 
    this->start_height = 0; 
    this->relay = 0x01;  
} 

vector<byte_t> version_message::to_byte_array() {
    vector<byte_t> message_bytes = this->header_to_byte_array();
    
    //add version
    unsigned int org_size = message_bytes.size();
    message_bytes.resize(org_size + 4); 
    memcpy(&message_bytes[org_size], &this->version, 4); 
    //add services 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 8); 
    memcpy(&message_bytes[org_size], &this->services, 8);  
    //add timestamp 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 8); 
    memcpy(&message_bytes[org_size], &this->timestamp, 8); 
    // add addr_recv_services 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 8); 
    memcpy(&message_bytes[org_size], &this->addr_recv_services, 8); 
    //add addr_recv_IP_address 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 16); 
    memcpy(&message_bytes[org_size], this->addr_recv_IP_address, 16); 
    //add addr_recv_port 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 2);  
    uint16_t addr_recv_port_buffer = htons(this->addr_recv_port);
    memcpy(&message_bytes[org_size], &addr_recv_port_buffer, 2);  
    // add addr_trans_services 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 8); 
    memcpy(&message_bytes[org_size], &this->addr_trans_services, 8); 
    //add addr_trans_IP_address 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 16); 
    memcpy(&message_bytes[org_size], this->addr_trans_IP_address, 16); 
    //add addr_trans_port 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 2);  
    uint16_t addr_trans_port_buffer = htons(this->addr_trans_port);
    memcpy(&message_bytes[org_size], &addr_trans_port_buffer, 2);  
    //add nonce 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 8); 
    memcpy(&message_bytes[org_size], &this->nonce, 8); 
    //add user_agent_bytes 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 1); 
    memcpy(&message_bytes[org_size], &this->user_agent_bytes, 1); 
    //add start_height 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 4); 
    memcpy(&message_bytes[org_size], &this->start_height, 4); 
    //add relay 
    org_size = message_bytes.size();
    message_bytes.resize(org_size + 1); 
    memcpy(&message_bytes[org_size], &this->relay, 1); 

    //set size 
    uint32_t payload_size = message_bytes.size() - 24;
    memcpy(&message_bytes[16], &payload_size, 4);
    
    //compute checksum of payload and set it  
    set_checksum(message_bytes, payload_size);
    return message_bytes;
}  

void version_message::print_msg(){
    print("VERSION MSG[");  

    this->print_header();

    print("version: " + std::to_string(this->version)); 
    print("services: " + std::to_string(this->services)); 
    print("timestamp: " + std::to_string(this->timestamp)); 
    print("addr_recv_services: " + std::to_string(this->addr_recv_services)); 

    string temp = "addr_recv_IP_address: ";
    for(unsigned int i = 0; i < 16; i++){ 
        temp += to_string((unsigned int)((unsigned char)this->addr_recv_IP_address[i])); 
        if(i != 15){
            temp += "."; 
        }
    } 
    print(temp);

    print("addr_recv_port: " + std::to_string(this->addr_recv_port));  
    print("addr_trans_services: " + std::to_string(this->addr_trans_services));  

    temp = "addr_trans_IP_address: ";
    for(unsigned int i = 0; i < 16; i++){ 
        temp += to_string((unsigned int)((unsigned char)this->addr_trans_IP_address[i])); 
        if(i != 15){
            temp += "."; 
        }
    } 
    print(temp);
    
    print("addr_trans_port: " + std::to_string(this->addr_trans_port)); 
    print("nonce: " + std::to_string(this->nonce)); 
    print("user_agent_bytes: " + std::to_string(this->user_agent_bytes)); 
    print("start_height: " + std::to_string(this->start_height)); 
    print("relay: " + std::to_string(this->relay)); 
    print("]"); 
} 

getaddr_message::getaddr_message(){
    this->command = MESSAGE_TYPE_GETADDR;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "getaddr"); 
}   

vector<byte_t> getaddr_message::to_byte_array(){
     return header_to_byte_array();
} 

void getaddr_message::print_msg(){
    print("GETADDR MSG ["); 
    this-> print_header(); 
    print("]"); 
} 

addr_message::addr_message(){
    this->command = MESSAGE_TYPE_ADDR;  
    memset(this->command_name, 0, 12);
    strcpy(this->command_name, "addr"); 
    this->ip_addy_count = 0; 
} 

vector<byte_t> addr_message::to_byte_array(){
    return vector<byte_t>();
} 

void addr_message::print_msg(){
    print("ADDR MSG ["); 
    this-> print_header(); 
    print("]"); 
}  

sendheaders_message::sendheaders_message(){
    this->command = MESSAGE_TYPE_SENDHEADERS;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "sendheaders"); 
}    

vector<byte_t> sendheaders_message::to_byte_array(){
     return header_to_byte_array();
}   

void sendheaders_message::print_msg(){
    print("SENDHEADERS MSG ["); 
    this-> print_header(); 
    print("]");  
}

sendcmpct_message::sendcmpct_message(){ 
    this->command = MESSAGE_TYPE_SENDCMPCT;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "sendcmpct"); 
    this->announce = false; 
    this->version = 0;
} 

vector<byte_t> sendcmpct_message::to_byte_array(){
    vector<byte_t> message_bytes = this->header_to_byte_array();
    
    //add announce
    unsigned int org_size = message_bytes.size();
    message_bytes.resize(org_size + 1); 
    memcpy(&message_bytes[org_size], &this->announce, 1);  

    //add cmpct version
    org_size = message_bytes.size(); 
    message_bytes.resize(org_size + 8); 
    memcpy(&message_bytes[org_size], &this->version, 8); 

    return message_bytes;
}  

void sendcmpct_message::print_msg(){
    print("SENDCMPCT MSG[");  

    this->print_header();
    print("announce: " + std::to_string(this->announce)); 
    print("cmpct_version: " + std::to_string(this->version)); 
   
    print("]");
} 

ping_message::ping_message(){
    this->command = MESSAGE_TYPE_PING;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "ping");  

    this->nonce = 0;  
}  

vector<byte_t> ping_message::to_byte_array(){
    vector<byte_t> message_bytes = this->header_to_byte_array();
    
    //add nonce
    unsigned int org_size = message_bytes.size();
    message_bytes.resize(org_size + 8); 
    memcpy(&message_bytes[org_size], &this->nonce, 8);   

    //set size 
    uint32_t payload_size = message_bytes.size() - 24;
    memcpy(&message_bytes[16], &payload_size, 4);
    
    //compute checksum of payload and set it  
    set_checksum(message_bytes, payload_size);

    return message_bytes;
} 

void ping_message::print_msg(){
    print("PING MSG[");  

    this->print_header();
    print("nonce: " + std::to_string(this->nonce)); 
   
    print("]");
} 

pong_message::pong_message(){
    this->command = MESSAGE_TYPE_PONG;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "pong");  

    this->nonce = 0;  
} 

vector<byte_t> pong_message::to_byte_array(){
    vector<byte_t> message_bytes = this->header_to_byte_array();
    
    //add nonce
    unsigned int org_size = message_bytes.size();
    message_bytes.resize(org_size + 8); 
    memcpy(&message_bytes[org_size], &this->nonce, 8);   

    //set size 
    uint32_t payload_size = message_bytes.size() - 24;
    memcpy(&message_bytes[16], &payload_size, 4);
    
    //compute checksum of payload and set it  
    set_checksum(message_bytes, payload_size);

    return message_bytes;
} 

void pong_message::print_msg(){
    print("PING MSG[");  

    this->print_header();
    print("nonce: " + std::to_string(this->nonce)); 
   
    print("]");
}  

getheaders_message::getheaders_message(){ 
    this->command = MESSAGE_TYPE_GETHEADERS;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "getheaders"); 

    this->version = 0; 
    this->hash_count = 0; 
} 

vector<byte_t> getheaders_message::to_byte_array(){
    vector<byte_t> message_bytes = this->header_to_byte_array();
    
    //add version
    unsigned int org_size = message_bytes.size();
    message_bytes.resize(org_size + 4); 
    memcpy(&message_bytes[org_size], &this->version, 4);   

    //add hashcount 
    org_size = message_bytes.size(); 
    message_bytes.resize(org_size + sizeof(unsigned int)); 
    memcpy(&message_bytes[org_size], &this->hash_count, sizeof(unsigned int)); 

    //add block header hashes
    for(vector<byte_t>& hash : this->block_header_hashes){
        org_size = message_bytes.size(); 
        message_bytes.resize(org_size + 32); 
        memcpy(&message_bytes[org_size], &hash[0], 32); 
    }   

    //add stop hash 
    org_size = message_bytes.size(); 
    message_bytes.resize(org_size + 32);  
    memcpy(&message_bytes[org_size], &this->stop_hash[0], 32); 

    //set up header 

    //set size 
    uint32_t payload_size = message_bytes.size() - 24;
    memcpy(&message_bytes[16], &payload_size, 4);
    
    //compute checksum of payload and set it  
    set_checksum(message_bytes, payload_size);

    return message_bytes;
}  

void getheaders_message::print_msg(){
    print("GETHEADERS MSG[");  

    this->print_header();
    print("version: " + std::to_string(this->version)); 
    print("hash_count" + std::to_string(this->hash_count)); 
    print("hashes:"); 

    //print out the hashes
    cout << hex; 
    string temp = "";
    for(vector<byte_t>& hash : this->block_header_hashes){  
        temp += "   ";
        for(byte_t b : hash){
            temp += "0x" + to_string((unsigned char) b) + " ";
        }     
        print(temp);
    }  

    //print out stop hash 
    print("stop_hash: "); 
    temp = "";
    for(byte_t b : this->stop_hash){
        temp +=  "0x"  + to_string((unsigned char) b) + " ";
    }     
    print(temp);
    cout << dec;
   
    print("]");
}  

headers_message::headers_message(){
    this->command = MESSAGE_TYPE_HEADERS;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "headers"); 

    this->count = 0; 
}

vector<byte_t> headers_message::to_byte_array(){ 
    vector<byte_t> message_bytes = this->header_to_byte_array();
    
    //add count
    unsigned int org_size = message_bytes.size();
    message_bytes.resize(org_size + sizeof(unsigned int)); 
    memcpy(&message_bytes[org_size], &this->count, sizeof(unsigned int));    

    //set up header 

    //set size 
    uint32_t payload_size = message_bytes.size() - 24;
    memcpy(&message_bytes[16], &payload_size, 4);
    
    //compute checksum of payload and set it  
    set_checksum(message_bytes, payload_size);

    return message_bytes;
} 

void headers_message::print_msg(){
    print("GETHEADERS MSG[");  

    this->print_header();
    print("count: " + std::to_string(this->count)); 

    print("]");
} 

inv_message::inv_message(){
    this->command = MESSAGE_TYPE_INV;  
    memset(this->command_name, 0, 12); 
    strcpy(this->command_name, "inv");  
} 

vector<byte_t> inv_message::to_byte_array(){
    return this->header_to_byte_array(); 
} 

void inv_message::print_msg(){
    print("INV MSG[");  

    this->print_header(); 

    print("]");
}

void ip_string_to_array(string ip_addy, unsigned char* ip_addy_array){ 
    //support only ipv4 for convience  

    //set the 000000000011 part to be compatiable with ipv6 per bitcoin protocl
    memset(ip_addy_array, 0, 16); 
    ip_addy_array[10] = (byte_t) 1;  
    ip_addy_array[11] = (byte_t) 1;   

    //parse the ipv4 string for the byte vals and fill in array
    unsigned int s = 0;   
    unsigned int e = 0;
    for(unsigned int idx = 0; idx < 4; idx++){ 
        e = ip_addy.find('.', s);  
        if(e == -1){
            e = ip_addy.size();
        }
        string sub = ip_addy.substr(s, e-s); 
        ip_addy_array[12 + idx] = (uint8_t) stoi(sub); 
        s = e +1; 
    } 

}  

string ip_array_to_string(unsigned char * ip_addy_array, unsigned int start){
    string res = ""; 
    res.append(to_string(ip_addy_array[start]) + "."); 
    res.append(to_string(ip_addy_array[start + 1]) + ".");
    res.append(to_string(ip_addy_array[start + 2]) + "."); 
    res.append(to_string(ip_addy_array[start + 3])); 

    return res; 
} 

void set_checksum(vector<byte_t>& message_bytes, unsigned int payload_size){
    //compute checksum of payload and set it  
    vector<byte_t> payload_buffer; 
    payload_buffer.resize(payload_size); 
    memcpy(&payload_buffer[0], &message_bytes[24], payload_size); 
    payload_buffer = sha256(payload_buffer);  
    payload_buffer = sha256(payload_buffer);
    memcpy(&message_bytes[20], &payload_buffer[0], 4);
}

vector<byte_t> sha256(vector<byte_t>& input){
    CryptoPP::SHA256 sha256_hasher; 
    vector<byte_t> output; 
    output.resize(32); 

    sha256_hasher.CalculateDigest(&output[0], &input[0], input.size());
    
    return output; 
}

void print_msg_bytes(vector<byte_t> msg){
    cout << "MSG: " << setfill('0') << setw(2) << right << hex; 
    for(byte_t& b : msg){
        cout << "0x"; 
        cout << (int)b; 
        cout << " ";
    } 
    cout << dec << endl; 
}