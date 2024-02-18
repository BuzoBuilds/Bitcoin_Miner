#pragma once 

#include <vector> 
#include <unordered_map> 
#include <memory> 
#include <thread>  
#include <unordered_set>


using namespace std; 
 

typedef unsigned int socket_t;  
typedef unsigned char byte_t;   

const unsigned int MAX_POLL_ATTEMPTS = 5; 
const unsigned int POLL_TIMEOUTS_MS = 5000;
const unsigned int READ_SLEEP_TIME_MS = 100;   
const unsigned int ESTABLISH_PEER_WAIT_TIME_MS = 20000;  
const unsigned int CONNECT_TIMEOUT = 5000; 
const unsigned int MAX_PEERS = 50;
const byte_t START_STRING[4] = {(byte_t) 0xf9, (byte_t) 0xbe, (byte_t) 0xb4, (byte_t) 0xd9};  
const string SEED_FILE = "../data/seed_ips.txt";   
const string BLOCK_CHAIN_FILE = "../data/block_chain.txt";
const uint16_t MAINNET_PORT = 8333;  



enum MESSAGE_TYPE{ 
    MESSAGE_TYPE_NONE,
    MESSAGE_TYPE_VERACK, 
    MESSAGE_TYPE_VERSION, 
    MESSAGE_TYPE_GETADDR, 
    MESSAGE_TYPE_ADDR, 
    MESSAGE_TYPE_SENDHEADERS, 
    MESSAGE_TYPE_SENDCMPCT, 
    MESSAGE_TYPE_PING, 
    MESSAGE_TYPE_PONG, 
    MESSAGE_TYPE_GETHEADERS, 
    MESSAGE_TYPE_HEADERS, 
    MESSAGE_TYPE_INV,
}; 

vector<byte_t> sha256(vector<byte_t>& input); 
void ip_string_to_array(string ip_addy, unsigned char* ip_addy_array); 
void print_msg_bytes(vector<byte_t> msg);  
string ip_array_to_string(unsigned char * ip_addy_array, unsigned int start);
void set_checksum(vector<byte_t>& message_bytes, unsigned int payload_size);
class message{  
    public: 
        message(); 
        vector<byte_t> header_to_byte_array();  
        void print_header();
        virtual vector<byte_t> to_byte_array() = 0;   
        virtual void print_msg() = 0;
       
        byte_t start_string[4]; 
        MESSAGE_TYPE command;  
        char command_name[12]; 
        uint32_t payload_size; 
        char checksum[4];  

}; 

class verack_message : public message{
    public:
        verack_message(); 
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
}; 

class version_message : public message{
    public: 
        uint32_t version; 
        uint64_t services; 
        uint64_t timestamp; 
        uint64_t addr_recv_services; 
        char addr_recv_IP_address[16]; 
        uint16_t addr_recv_port; 
        uint64_t addr_trans_services; 
        char addr_trans_IP_address[16]; 
        uint16_t addr_trans_port; 
        uint64_t nonce; 
        uint8_t user_agent_bytes; 
        uint32_t start_height; 
        bool relay;   

        version_message();
        vector<byte_t> to_byte_array() override;  
        void print_msg() override;

}; 

class getaddr_message : public message{
    public:
        getaddr_message(); 
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
}; 

class addr_entry{ 
public:
    uint32_t time; 
    uint64_t services; 
    unsigned char ip_addy[16]; 
    uint16_t port;
};

class addr_message : public message{
    public:  
        unsigned int ip_addy_count; 
        vector<addr_entry> ip_addys;
        addr_message();  
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;

}; 

class sendheaders_message : public message{
    public:  
        sendheaders_message();
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
}; 

class sendcmpct_message : public message{
    public: 
        bool announce; 
        uint64_t version; 
        sendcmpct_message(); 
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
}; 

class ping_message : public message{
    public: 
        uint64_t nonce; 
        ping_message();  
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
}; 

class pong_message : public message{
    public: 
        uint64_t nonce; 
        pong_message();  
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
}; 

class getheaders_message : public message{
    public:  
        uint32_t version; 
        unsigned int hash_count; 
        vector<vector<byte_t>> block_header_hashes; 
        vector<byte_t> stop_hash; 

        getheaders_message(); 
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
}; 

class headers_message : public message{
    public: 
        unsigned int count; 
        //TODO: create block_header class and headers field for this class 
        headers_message(); 
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
};  

//TODO: complete
class inv_message : public message{
    public: 
        inv_message(); 
        vector<byte_t> to_byte_array() override; 
        void print_msg() override;
};

class peer{
    public: 
        socket_t socket; 
        unsigned int peer_id;  
        string ip_addy;
        bool verack_recvd; 
        bool version_recvd; 
        bool established;   
        uint32_t version; 
        uint64_t services; 
        unsigned char IP_address[16]; 
        uint16_t port; 
        uint32_t start_height; 
        bool relay;    
        bool send_headers;  
        bool cmpct_announce; 
        uint64_t cmpct_version;
        vector<shared_ptr<message>> rx_queue;  
        
        
        peer();
        peer(unsigned int peer_id, socket_t peer_socket, string ip_addy, unsigned int peer_port, bool established); 
        vector<shared_ptr<message>> get_rx_msgs(MESSAGE_TYPE msg_type);
    private: 
        
};

class node{

    public:  
        unsigned int curr_peer_id;  
        unique_ptr<thread> reader_thread;   
        unique_ptr<thread> listener_thread; 
        vector<shared_ptr<thread>> handler_threads;
        socket_t server_sock; 
        unsigned int node_count; 
        //unordered_set<string> invalid_ips; 

        node(); 
        unordered_map<unsigned int, peer> peers; 
        
        void start_node();
        void start_reader(); 
        int read_messages();   
        vector<byte_t> read_from_socket(socket_t socket);  
        vector<shared_ptr<message>> parse_messages(vector<byte_t> data); 
        void handle_messages(vector<shared_ptr<message>> messages, unsigned int peer_id); 
        void clean_unestablished_peers();
        void plant_network_seed(); 
        version_message make_version_message(unsigned char * recv_ip_address, uint16_t recv_port);    
        int send_message(unsigned int peer_id, message &msg);
        int make_outbound_connection(string ip_addy, uint16_t port);  
        unsigned int add_unestablished_peer(int peer_socket, string peer_ip_addy, unsigned int peer_port); 
        void start_server();  
        void establish_connection(socket_t peer_sock, string peer_ip_addy, unsigned int peer_port);  
        void grow_network();  
        

}; 

