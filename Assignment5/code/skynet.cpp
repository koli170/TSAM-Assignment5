#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>
#include <list>

#include <poll.h>
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <deque>
#include <fstream>
#include <set>

#include <unistd.h>

// fix SOCK_NONBLOCK for OSX
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define MAX_BACKLOG 8



class Client
{
  public:
    int sock;              // socket of client connection
    std::string name;           // Limit length of name of client's user

    Client(int socket) : sock(socket){} 

    ~Client(){}            // Virtual destructor defined for base class
};

struct serverConnection{
    std::string name;
    std::string addr;
    std::vector<char> buffer;
    int recieved;
    int port; 
    int socket;
};

struct messageStruct{
    std::string from_name;
    std::string to_name;
    std::string message_data;
    std::vector<std::string> hops;
};

std::map<int, Client*> clients;
std::map<std::string, serverConnection> one_hop_connections; // KEY: SERVER NAME
std::map<std::string, serverConnection> known_servers;
std::map<std::string, std::deque<messageStruct> > message_queues;
std::vector<int> ports_pending_connection;
std::chrono::steady_clock::time_point start_pending_timer;
std::vector<int> clientSocketList; // LIST OF SOCKETS THAT ARE NOT SERVERS
// TODO: HARDCODED CHANGE LATER
std::string TSAM_IP = "130.208.246.98";
//std::vector<int> BANNED_PORTS = {4026, 5044, 4005, 4013, 4030, 4099};
std::vector<int> BANNED_PORTS = {4030, 4130, 60908, 4015, 4042, 4003, 4060, 4444, 4013, 4069, 4130, 4144, 4077, 4023};
const char *path="mission_report";
std::ofstream mission_report(path);

bool SENDINGSTATUS = true;

void log_message(std::ofstream &file, char message_type = 'i',  std::string message = ""){
    // i: INFO
    // e: ERROR
    // a: ACTION
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    file << std::put_time(&tm, "[%F %T] ");
    if (message_type == 'i'){
        file << "[INFO]   ";
    }
    if (message_type == 'e'){
        file << "[ERROR]  ";
    }
    if (message_type == 'a'){
        file << "[ACTION] ";
    }
    file << message << "\n";
}


int open_sock(int port_nr){

    struct sockaddr_in sk_addr;   // address settings for bind()
    int sock;                     // socket opened for this port
    int set = 1;                  // for setsockopt

#ifdef __APPLE__     
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Failed to open socket");
        log_message(mission_report, 'e', "Failed to open socket");
        return(-1);
    }
#else
    if((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
    {
        perror("Failed to open socket");
        log_message(mission_report, 'e', "Failed to open socket");
        return(-1);
    }
#endif

   if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
   {
      perror("Failed to set SO_REUSEADDR:");
      log_message(mission_report, 'e', "Failed to set SO_REUSEADDR");
   }
   set = 1;
#ifdef __APPLE__     
   if(setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0)
   {
     perror("Failed to set SOCK_NOBBLOCK");
     log_message(mission_report, 'e', "Failed to set SOCK_NOBBLOCK");
   }
#endif
   memset(&sk_addr, 0, sizeof(sk_addr));

   sk_addr.sin_family      = AF_INET;
   sk_addr.sin_addr.s_addr = INADDR_ANY;
   sk_addr.sin_port        = htons(port_nr);

   // Bind to socket to listen for connections from clients

   if(bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0)
   {
      perror("Failed to bind to socket:");
      log_message(mission_report, 'e', "Failed to bind to socket");
      return(-1);
   }
   else
   {
      return(sock);
   }
}

void closeClient(int clientSocket, std::vector<pollfd>& autobots)
{

    printf("[ACTION] Closing client socket: %d\n", clientSocket);
    log_message(mission_report, 'a', "Closing client socket: " + std::to_string(clientSocket));

     // If this client's socket is maxfds then the next lowest
     // one has to be determined. Socket fd's can be reused by the Kernel,
     // so there aren't any nice ways to do this.

    close(clientSocket);      
    auto remove_index = std::find_if(autobots.begin(), autobots.end(),
    [clientSocket](const pollfd& p) { return p.fd == clientSocket; });
    if (remove_index != autobots.end()){
        autobots.erase(remove_index);
    }

}

void sendMessage(std::string client_name, std::string send_message, int socket = -1, bool forwarding=false, messageStruct message_to_forward=messageStruct()){
    int send_socket = -1;
    if (one_hop_connections.find(client_name) != one_hop_connections.end()){
        send_socket = one_hop_connections[client_name].socket;
    }
    else if(socket != -1){
        send_socket = socket;
    }
    else if (forwarding){
        uint8_t SOH = 0x01;
        uint8_t STX = 0x02;
        uint8_t ETX = 0x03;
        uint8_t EOD = 0x04;
        std::vector<uint8_t> message;
        std::string test = "";
        std::string command = "SENDMSG," + message_to_forward.to_name + "," + message_to_forward.from_name + message_to_forward.message_data;
        std::cout << "[INFO] THE COMMAND: " << command + "\n";
        uint16_t length = 1 + 2 + 1 + command.size() + 1;
        uint16_t length_nbo = htons(length);
        message.push_back(SOH);
        message.push_back(static_cast<uint8_t>(length_nbo & 0xFF));
        message.push_back(static_cast<uint8_t>((length_nbo >> 8) & 0xFF));
        message.push_back(STX);
        message.insert(message.end(), command.begin(), command.end());
        message.push_back(static_cast<char>(EOD));
        for (int i = 0; i < message_to_forward.hops.size(); i++)
        {
            message.insert(message.end(), message_to_forward.hops[i].begin(), message_to_forward.hops[i].end());
            if(i < message_to_forward.hops.size()-1){
                message.push_back(',');
            }
        }
        message.push_back(static_cast<char>(ETX));
        std::cout << "[INFO] FORWARDING MESSAGE" << command << "\n";
        int result = send(send_socket, message.data(), message.size(), 0);
        std::cout << result << "\n";
        std::cout << message.data() << "\n";
        
    }
    else{
        std::cout << "[ERROR] NOT FOUND CONNECTION FOR SENDING\n";
        log_message(mission_report, 'e', "NOT FOUND CONNECTION FOR SENDING");
        return;
    }
        uint8_t SOH = 0x01;
        uint8_t STX = 0x02;
        uint8_t ETX = 0x03;
        std::vector<uint8_t> message;
        std::string command = send_message;
        uint16_t length = 1 + 2 + 1 + command.size() + 1;
        uint16_t length_nbo = htons(length);
        message.push_back(SOH);
        message.push_back(static_cast<uint8_t>(length_nbo & 0xFF));
        message.push_back(static_cast<uint8_t>((length_nbo >> 8) & 0xFF));
        message.push_back(STX);
        message.insert(message.end(), command.begin(), command.end());
        message.push_back(static_cast<char>(ETX));
        std::cout << "[ACTION] SENDING: " << client_name << " A MESSAGE\n";
        log_message(mission_report, 'a', "SENDING: " + client_name + " A MESSAGE");
        int result = send(send_socket, message.data(), message.size(), 0);
        std::cout << result << "\n";
        std::cout << message.data() << "\n";
    // TODO: ERROR HANDLING
}

int connectToServer(serverConnection &victim, std::vector<pollfd> &autobots){
    int connectSock = socket(AF_INET, SOCK_STREAM, 0);
    std::cout << "[INFO] ATTEMPTING TO CONNECT TO " << victim.name << "\n";
    log_message(mission_report, 'i', "ATTEMPTING TO CONNECT TO " + victim.name);
    if(connectSock < 0){
        perror("Failed to create client socket");
        log_message(mission_report, 'e', "Failed to create client socket");
        return -1;
    }

    if (connectSock == -1){
        std::cout << "[ERROR] opening connect sock\n";
        log_message(mission_report, 'e', "opening connect sock");
        return -1;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr)); 

    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, victim.addr.c_str(), &server_addr.sin_addr);
    if (victim.port == -1){
        int pos = victim.name.find("_");
        std::string id = victim.name.substr(pos + 1);
        victim.port = 4000 + stoi(id);
    }
    std::cout << "                PORT " << victim.port << "\n";
    log_message(mission_report, 'i', "PORT: " + victim.port);
    server_addr.sin_port = htons(victim.port);

    for(int port : BANNED_PORTS){
        if(victim.port == port){
            std::cout << "[INFO] Port " << port << " is BANNED, skipping connection\n";
            return -1;
        }
    }

    if (victim.port == 4067 || victim.port > 5500 || victim.port < 4000){
        return -1;
    }

    if (find(ports_pending_connection.begin(), ports_pending_connection.end(), victim.port) != ports_pending_connection.end()){
        std::cout << "[INFO] Port " << victim.port << " is pending\n";
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(connectSock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(connectSock, (sockaddr*) &server_addr, sizeof(server_addr)) < 0){
        std::cout << "[ERROR] Initial connection sock\n";
        log_message(mission_report, 'e', "Initial connection sock");
        return 0;
    }
    victim.socket = connectSock;
    pollfd temp{.fd=connectSock, .events=POLLIN, .revents=0};
    ports_pending_connection.push_back(victim.port);
    start_pending_timer = std::chrono::steady_clock::now();
    autobots.push_back(temp);
    clients[temp.fd] = new Client(temp.fd);


    std::string command = "HELO,A5_67";
    sendMessage(victim.name, command, connectSock);
    return connectSock;
}


void clientCommand(int clientSocket, std::vector<pollfd>& autobots, char *buffer, int recieved){

    if (find(clientSocketList.begin(), clientSocketList.end(), clientSocket) != clientSocketList.end()){
        std::cout << "[INFO] COMMAND FROM OUR CLIENT (NOT SERVER)\n";
        log_message(mission_report, 'i', "COMMAND FROM OUR CLIENT (NOT SERVER");
        std::string msg(buffer);
        if (msg.find("SENDMSG") != std::string::npos){
            std::string cur_message;
            bool got_id = false;
            std::string group_str = "";

            for (int i = MAX_BACKLOG; i < recieved; i++) {
                if (!got_id && buffer[i] == ',') {
                    got_id = true;
                    continue;
                }
                if (got_id)
                    cur_message += buffer[i];
                else
                    group_str += buffer[i];
            }

            std::cout << "[ACTION] Sending message: " << cur_message << " TO " << group_str << "\n";
            log_message(mission_report, 'a', "Sending message: " + cur_message + " TO " + group_str);

            if (one_hop_connections.find(group_str) != one_hop_connections.end()){
                std::string send_str = "SENDMSG," + group_str + ",A5_67," + cur_message;
                sendMessage(group_str, send_str);
                return;
            }
            else{
                messageStruct relayed = messageStruct();
                relayed.from_name = "A5_67";
                relayed.to_name = group_str;
                relayed.message_data = cur_message;
                if (!one_hop_connections.empty()) {
                    auto it = one_hop_connections.begin();
                    sendMessage(it->first, relayed.message_data, it->second.socket, true, relayed);
                }
            }

            std::cout << "[INFO]   RECIPIENT NOT FOUND IN ONE HOP CONNECTIONS, ADDING MESSAGE TO QUEUE AND RELAYING\n";
            log_message(mission_report, 'i', "RECIPIENT NOT FOUND IN ONE HOP CONNECTIONS, ADDING MESSAGE TO QUEUE");

            messageStruct new_message;
            new_message.from_name = "A5_67";
            new_message.to_name = group_str;
            new_message.message_data = cur_message;
            if(message_queues.find(new_message.to_name) == message_queues.end()){
                message_queues[new_message.to_name] = {new_message};
            }
            else{
                message_queues[new_message.to_name].push_back(new_message);
            }
            std::string reply = "MESSAGE SENT TO " + group_str;
            int nsent = send(clientSocket, reply.c_str(), reply.size(), 0);
            if (nsent == -1){
                std::cout << "[ERROR] FAILED TO SEND REPLY TO CLIENT\n";
                log_message(mission_report, 'e', "FAILED TO SEND REPLY TO CLIENT");
            }
            return;
        }
        if (msg.find("GETMSG") != std::string::npos){
            std::string reply;
            if(message_queues.find("A5_67") == message_queues.end()){
                message_queues["A5_67"] = std::deque<messageStruct>();
            }
            if(message_queues["A5_67"].empty()){
                std::cout << "[INFO]   NO NEW MESSAGES\n";
                log_message(mission_report, 'i', "NO NEW MESSAGES");
                reply = "NO NEW MESSAGES ON SERVER";
            } else {
                std::cout << "[ACTION] Showing oldest message: " << message_queues["A5_67"].front().message_data << "\n";
                log_message(mission_report, 'a', "Showing oldest message: " + message_queues["A5_67"].front().message_data);
                reply = "[" + message_queues["A5_67"].front().from_name +  "] " + message_queues["A5_67"].front().message_data;
                message_queues["A5_67"].pop_front();
            }
            int nsent = send(clientSocket, reply.c_str(), reply.size(), 0);
            if (nsent == -1){
                std::cout << "[ERROR] FAILED TO SEND REPLY TO CLIENT\n";
                log_message(mission_report, 'e', "FAILED TO SEND REPLY TO CLIENT");
            }
            return;
        }
        if (msg.find("LISTSERVERS") != std::string::npos){
            std::string all_servers;
            int index = 0;
            for (auto& serv : one_hop_connections){
                if (index == 0){
                    all_servers += serv.second.name;
                    index = 1;
                }
                else{
                    all_servers += ","+serv.second.name;
                }
            }
            std::cout << "[ACTION] LISTING SERVERS: " << all_servers << "\n";
            log_message(mission_report, 'a', "LISTING SERVERS: " + all_servers);
            std::string reply = all_servers;  // <-- MISSING SEMICOLON WAS HERE
            int nsent = send(clientSocket, reply.c_str(), reply.size(), 0);
            if (nsent == -1){
                std::cout << "[ERROR] FAILED TO SEND REPLY TO CLIENT\n";
                log_message(mission_report, 'e', "FAILED TO SEND REPLY TO CLIENT");
            }
            for (auto& i : clientSocketList){
                std::cout << i << " ";
            }
            std::cout << "\n";
            return;
        }
        //return;
    }
    int total_len = 0;

    std::vector<char> full_buffer;
    

    serverConnection* cur_connection_ptr = nullptr;
    for (auto& connection : one_hop_connections) {
        if (connection.second.socket == clientSocket) {
            cur_connection_ptr = &connection.second;
            break;
        }
    }
    

    if (cur_connection_ptr != nullptr && cur_connection_ptr->recieved > 0){
        full_buffer.insert(full_buffer.end(), cur_connection_ptr->buffer.begin(), cur_connection_ptr->buffer.end());
        cur_connection_ptr->recieved = 0;
        cur_connection_ptr->buffer.clear();
        std::cout << "[ACTION] FETCHING OLD UNFINISHED DATA\n";
        std::cout << "[INFO] " << full_buffer.size() << " AMOUNT OF DATA WAS FETCHED\n";
    }
    
    full_buffer.insert(full_buffer.end(), buffer, buffer + recieved);

    std::cout << "[ACTION] DOING SERVER COMMAND\n";
    log_message(mission_report, 'a', "DOING SERVER COMMAND");
    
    if (full_buffer.size() < 5) {
        std::cout << "[ERROR] Command too short\n";
        log_message(mission_report, 'e', "Command too short");
        return;
    }

    while (total_len < (int)full_buffer.size()) {
        if (total_len + 3 > (int)full_buffer.size()) {
            for (auto &connection : one_hop_connections) {
                if (connection.second.socket == clientSocket) {
                    connection.second.buffer.clear();
                    connection.second.buffer.insert(connection.second.buffer.end(),
                                                full_buffer.begin() + total_len,
                                                full_buffer.end());
                    connection.second.recieved = full_buffer.size() - total_len;
                    std::cout << "[ACTION] PARTIAL HEADER, SAVING AND MOVING ON\n";
                    break;
                }
            }
            std::cout << "[ERROR] CONNECTION NOT FOUND";
            return;
        }

        uint16_t net_len = 0;
        memcpy(&net_len, full_buffer.data() + total_len + 1, sizeof(net_len));
        uint16_t msg_len = ntohs(net_len); 

        const uint16_t MIN_FRAME = 1 + 2 + 1 + 0 + 1;
        if (msg_len < MIN_FRAME) {
            std::cerr << "[ERROR] declared msg_len too small: " << msg_len << "\n";
            return;
        }

        if ((int)msg_len + total_len > (int)full_buffer.size()) {
            for (auto &connection : one_hop_connections) {
                if (connection.second.socket == clientSocket) {
                    connection.second.buffer.clear();
                    connection.second.buffer.insert(connection.second.buffer.end(),
                                                full_buffer.begin() + total_len,
                                                full_buffer.end());
                    connection.second.recieved = full_buffer.size() - total_len;
                    std::cout << "[ACTION] UNFINISHED DATA, SAVING AND MOVING ON\n";
                    break;
                }
            }
            return;
        }

        std::cout << "[INFO]   received message has a length of: " << msg_len << "\n";

        std::string message;
        message.insert(message.end(),
            full_buffer.begin() + total_len,
            full_buffer.begin() + total_len + msg_len);

        // now you can sanity-check
        if (msg_len > (uint16_t)full_buffer.size()) {
            std::cout << "[ERROR] incomplete frame: declared " << msg_len << " got " << full_buffer.size() << "\n";
            std::cout << "[INFO]   The Buffer(hex): ";
            for (size_t i = total_len; i < full_buffer.size(); i++) {
                unsigned char c = full_buffer[i];
                if (isprint(c))
                    std::cout << c;
                else
                    std::cout << "\\x" << std::hex << (int)c << std::dec;
            }
            std::cout << "\n"; 
            return;
        }

        std::string command_prefix = "";
        bool found = false;
        
        if (message.find("HELO") != std::string::npos){
            try{
                command_prefix = "HELO";
                found = true;
                std::cout << "[ACTION] DOING HELO\n";
                    log_message(mission_report, 'a', "Doing HELO");
                std::string group_name_str = "";
                group_name_str.insert(group_name_str.end(), full_buffer.begin() + total_len + 9, full_buffer.begin() + total_len + msg_len - 1);
                std::cout << "[INFO]   The current group name: " << group_name_str << "\n";
                    log_message(mission_report, 'i', "The current group name: " + group_name_str);
                serverConnection temp={.name=group_name_str, .addr=TSAM_IP, .port=-1, .socket=clientSocket};
                one_hop_connections[group_name_str] = temp;
                if (message_queues.find(group_name_str) == message_queues.end()){
                    message_queues[group_name_str] = {};
                }
                if (cur_connection_ptr == nullptr) {
                    for (auto& connection : one_hop_connections) {
                        if (connection.second.socket == clientSocket) {
                            cur_connection_ptr = &connection.second;
                            break;
                        }
                    }
                }

                // REMOVE FROM CLIENT LIST, SINCE THIS IS A SERVER
                auto client_index = find(clientSocketList.begin(), clientSocketList.end(), clientSocket);
                if (client_index != clientSocketList.end()){
                    clientSocketList.erase(client_index);
                }

                if (one_hop_connections.size() - clientSocketList.size() > MAX_BACKLOG){
                    std::cout << "[ACTION] SERVER FULL, DISCONNECTING SOCKET " << clientSocket << "\n";
                    log_message(mission_report, 'a', "SERVER FULL, DISCONNECTING SOCKET " + clientSocket);
                    closeClient(clientSocket, autobots);
                }
                
                std::string send_str = "SERVERS,";
                send_str += "A5_67," + TSAM_IP + ",4067;";
                for (auto& one_hopper : one_hop_connections){
                    // Validate before adding to broadcast
                    if (one_hopper.second.port > 0 && 
                        one_hopper.second.port < 65536 &&
                        one_hopper.second.name.find('.') == std::string::npos) {
                        
                        send_str += one_hopper.second.name + ",";
                        send_str += one_hopper.second.addr + ",";
                        send_str += std::to_string(one_hopper.second.port) + ";";
                    }
                }
                std::cout << "[INFO]   The send string: " << send_str << "\n";
                    log_message(mission_report, 'i', "The send string: " + send_str);
                sendMessage(group_name_str, send_str);
            }
        catch(...){
            std::cout << "[ERROR] HELO COMMAND NOT IN PROTOCOL\n";
        }
        } 
            else if (message.rfind("KEEPALIVE") != -1){
                try
                    {
                    std::cout << "[ACTION] DOING KEEPALIVE WITH: " << message << " \n";
                    std::string message_len = "";
                    std::string TEST = "";
                    bool found = false;
                    for (int i = 0; i < msg_len-1; i++)
                    {
                        if (found){
                            message_len += message[i];
                        }
                        if (message[i] == ','){
                            found = true;
                        }
                        TEST+=message[i];
                    }
                    std::cout << "[INFO] CONVERTING: " << message_len << " TO INT " << TEST<< "\n";
                    int message_len_int = std::stoi(message_len);
                    if(message_len_int > 0){
                        std::cout << "[ACTION] SENDING GETMSGS\n";
                        sendMessage("", "GETMSGS,A5_67", clientSocket);
                    }
                    
                    log_message(mission_report, 'a', "Doing KEEPALIVE");
                    command_prefix = "KEEPALIVE";
                    found = true;
                }
                catch(...){
                    std::cout << "[ERROR] KEEPALIVE FAILED, CONTINUING\n";
                    log_message(mission_report, 'e', "KEEPALIVE FAILED, CONTINUING");
                }
            } 
            else if (message.rfind("GETMSGS") != -1){
                command_prefix = "GETMSGS";
                found = true;
                std::cout << "[ACTION] DOING GETMSGS\n";
                log_message(mission_report, 'a', "Doing GETMSGS");
                bool exists = false;
                serverConnection recipient;
                for (auto& recipient_check : one_hop_connections){
                    if (recipient_check.second.socket == clientSocket){
                        recipient = recipient_check.second;
                        exists = true;
                    }
                }
                if (exists){
                    while (message_queues[recipient.name].size() > 0){
                        messageStruct current_msg = message_queues[recipient.name].front();
                        message_queues[recipient.name].pop_front();
                        std::string send_str = "SENDMSG," + current_msg.to_name + "," + current_msg.from_name + "," + current_msg.message_data;
                        sendMessage(recipient.name, send_str);
                    }
                }
            } 
            else if (message.rfind("SENDMSG") != -1){
                command_prefix = "SENDMSG";
                found = true;

                std::cout << "[ACTION] DOING SENDMSG\n";
                log_message(mission_report, 'a', "Doing SENDMSG");
                
                std::cout << "[INFO]   The message: "<< message << "\n";
                log_message(mission_report, 'i', "The message: "+ message);

                messageStruct new_message;
                std::string building_message = "";
                int checks = 0;
                std::string send_message_to = "";
                uint8_t EOD = 0x04;
                int hop_index = 0;
                bool message_has_hops = false;
                std::string send_message_from = "";
                std::cout << "[INFO] PARSING SEND MESSAGE STRING: " << building_message << " ";
                log_message(mission_report, 'i', "PARSING SEND MESSAGE STRING: " + building_message);
                for (int i = 11; i < msg_len; i++)
                {
                    if (message[i] == ',' && checks <3){
                        if(checks == 1){
                            send_message_to = building_message;
                            std::cout << "SENDING MESSAGE TO: " << send_message_to << " ";
                            log_message(mission_report, 'a', "SENDING MESSAGE TO: " + send_message_to);
                            building_message = "";
                        }
                        else if (checks == 2){
                            send_message_from = building_message;
                            std::cout << "SENDING MESSAGE FROM: " << send_message_from<< " ";
                            log_message(mission_report, 'a', "SENDING MESSAGE FROM: " + send_message_from);
                            building_message = "";
                        }
                        checks += 1;
                        continue;
                    }
                    else{
                        uint8_t static_cast_val = static_cast<int>(message[i]);
                        if (static_cast_val == EOD){
                            message_has_hops = true;
                            hop_index = i+1;
                            break;
                        }
                        building_message += message[i];
                    }
                }
                if (message_has_hops){
                    std::string cur_group = "";
                    for (int i = hop_index; i < msg_len; i++)
                    {
                        if (message[i] == ','){
                            std::cout << "[INFO] adding " << cur_group << " to message hop\n";
                            new_message.hops.push_back(cur_group);
                            cur_group = "";
                        }
                        else{
                            cur_group += message[i];
                        }
                    }
                    new_message.hops.push_back("A5_67");
                    
                }
                std::cout << "THE MESSAGE DATA: " << building_message << "\n";
                log_message(mission_report, 'i', "THE MESSAGE DATA: " + building_message);
                new_message.from_name = send_message_from;
                new_message.to_name = send_message_to;
                new_message.message_data = building_message;

                if (new_message.to_name != "A5_67" || new_message.to_name != "67"){
                    if (one_hop_connections.find(new_message.to_name) != one_hop_connections.end()) {
                        std::cout << "[ACTION] " << new_message.to_name << " FOUND RIGHT PERSON!\n";
                        sendMessage(new_message.to_name, new_message.message_data, -1, true, new_message);
                    }
                    for (auto &current_pair : one_hop_connections) {
                        serverConnection &current_connections = current_pair.second;
                        if(find(new_message.hops.begin(), new_message.hops.end(), current_connections.name) != new_message.hops.end()){
                            std::cout << "[ACTION] " << current_connections.name << " NOT FOUND IN HOPS LIST, FORWARDING MESSAGE\n";
                            sendMessage(current_connections.name, new_message.message_data, current_connections.socket, true, new_message);
                        }
                    }
                }
                if(message_queues.find(send_message_to) == message_queues.end()){
                    message_queues[send_message_to] = {new_message};
                }
                else{
                    message_queues[send_message_to].push_back(new_message);
                }
            } 
            else if (message.rfind("STATUSREQ") != -1){
                std::string send_str = "";
                int index = 0;
                for (const auto& pair : one_hop_connections){
                    serverConnection server = pair.second;
                    if (index == 0){
                        if (message_queues.find(server.name) != message_queues.end()){
                            send_str += server.name + "," + std::to_string(message_queues[server.name].size());
                        }
                        else{
                            send_str += server.name + "," + "0,";
                        }
                        index = 1;
                    }
                    else{
                        if (message_queues.find(server.name) != message_queues.end()){
                            send_str += "," + server.name + "," + std::to_string(message_queues[server.name].size());
                        }
                        else{
                            send_str += "," + server.name + "," + "0,";
                        }
                    }
                }
                send_str = "STATUSRESP," + send_str;
                std::cout << "[ACTION] Sending statusresp, the message is: " << send_str << "\n";
                log_message(mission_report, 'a', "Sending statusresp, the message is: " + send_str);
                sendMessage("", send_str, clientSocket);
                command_prefix = "STATUSREQ";

                found = true;
                
            } 
            else if (message.rfind("SERVER") != -1){
                command_prefix = "SERVER";
                found = true;

                std::cout << "[ACTION] DOING SERVER\n";
                log_message(mission_report, 'a', "Doing SERVER");
                
                int index = 12;
                int cur_part = 0;
                std::string current_server = "";
                serverConnection current_connection;
                std::vector<int> try_connections;
                
                while(index < message.size()){
                    if(message[index] == ';'){
                        if (cur_part == 2) {  // Only process if we have all 3 parts
                            current_connection.port = std::stoi(current_server);
                            
                            // VALIDATION: Check if this entry makes sense
                            if (current_connection.port > 3000 && current_connection.port < 65536 &&
                                !current_connection.name.empty() && 
                                current_connection.name.find('.') == std::string::npos &&  // Name shouldn't contain dots
                                current_connection.addr.find('.') != std::string::npos) {  // IP should contain dots
                                
                                std::cout << "NAME: " << current_connection.name << " ";
                                std::cout << "IP: " << current_connection.addr << " ";
                                std::cout << "PORT: " << current_connection.port << "\n";
                                
                                // Store and potentially connect...
                                known_servers[current_connection.name] = current_connection;
                                
                                if(one_hop_connections.find(current_connection.name) == one_hop_connections.end() && 
                                current_connection.name != "A5_67" && find(try_connections.begin(), try_connections.end(), current_connection.socket) == try_connections.end()){
                                    if (one_hop_connections.size() + try_connections.size() < MAX_BACKLOG){
                                        int result = connectToServer(current_connection, autobots);
                                        if (result > 0){
                                            try_connections.push_back(current_connection.socket);
                                        }
                                    }
                                }
                            } else {
                                std::cout << "[ERROR] Invalid server entry - skipping\n";
                                log_message(mission_report, 'e', "Invalid server entry: " + current_connection.name);
                            }
                        }
                        
                        current_connection = serverConnection{};
                        current_server = "";
                        cur_part = 0;
                    }
                    else if(message[index] == ','){
                        if(cur_part == 0){
                            current_connection.name = current_server;
                            current_server = "";
                        }
                        else if(cur_part == 1){
                            current_connection.addr = current_server;
                            current_server = "";
                        }
                        cur_part += 1;
                    }
                    else{
                        current_server += message[index];
                    }
                    index += 1;
                }
            }
            else if (message.rfind("STATUSRESP") != -1){
                command_prefix = "STATUSRESP";
                found = true;
            } 
            std::cout << "[INFO]   The current command prefix: " << command_prefix << "\n";
            log_message(mission_report, 'i', "The current comman prefix: " + command_prefix);
            if(found == false){
                //std::cout << "Unrecognized command prefix";
                return;
            }
            total_len += msg_len;
    }
        if (total_len == full_buffer.size() && cur_connection_ptr) {
        cur_connection_ptr->buffer.clear();
        cur_connection_ptr->recieved = 0;
    }
}
int main(int argc, char const *argv[])
{

    // fd_set openSockets;             // Current open sockets 
    // fd_set readSockets;             // Socket list for select()        
    // fd_set exceptSockets;           // Exception socket list
    // int maxfds;                     // Passed to select() as max fd in set

    int clientSock; 
    struct sockaddr_in client;
    socklen_t clientLen = sizeof(client);
    std::vector<pollfd> autobots;
    bool finished = false;
    char buffer[5100];

    if (argc < 4){
        std::cout << "[ERROR] Incorrect number of arguments\n";
        return 0;
    }
    mission_report.setf(std::ios::unitbuf);
    log_message(mission_report, 'i', "START OF LOG");


    int port = atoi(argv[1]);   
    const char* address = argv[2]; //130.208.246.98
    int connect_port = atoi(argv[3]);

    int listenSock = open_sock(port);

    if (listenSock == -1){
        std::cout << "[ERROR] Opening listen sock\n";
        log_message(mission_report, 'e', "Opening listen sock");
        return 0;
    }

    if(listen(listenSock, MAX_BACKLOG) < 0){
        printf("Listen failed on port %s\n", argv[1]);
        log_message(mission_report, 'e', "Listen failed on port");
        exit(0);
    }
    else {
        pollfd temp{.fd=listenSock, .events=POLLIN, .revents=0};
        autobots.push_back(temp);
    }

    int connectSock = socket(AF_INET, SOCK_STREAM, 0);
    if(connectSock < 0){
        perror("Failed to create client socket");
        log_message(mission_report, 'e', "Failed to create client socket");
        return 0;
    }

    if (connectSock == -1){
        std::cout << "[ERROR] opening connect sock\n";
        log_message(mission_report, 'e', "Opening connect sock");
        return 0;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr)); 

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(connect_port);

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(connectSock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(connectSock, (sockaddr*) &server_addr, sizeof(server_addr)) < 0){
        std::cout << "[ERROR] Initial connection sock\n";
        log_message(mission_report, 'e', "Initial connection sock");
        return 0;
    }
    pollfd temp{.fd=connectSock, .events=POLLIN, .revents=0};
    autobots.push_back(temp);
    clients[temp.fd] = new Client(temp.fd);

    sendMessage("", "HELO,A5_67", connectSock);

    std::cout << "[ACTION] starting loop\n";
    log_message(mission_report, 'a', "Starting loop!");
    auto start = std::chrono::steady_clock::now();
    start_pending_timer = std::chrono::steady_clock::now();
    while(!finished){
        int n = poll(autobots.data(), autobots.size(), 500);

        // KEEP ALIVE SENDING
        auto time_passed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start);
        auto time_passed_pending_timer = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start);
        if (time_passed.count() >= 65){
            std::cout << "[ACTION] SENDING KEEPALIVES NOW NOW NOW\n";
            log_message(mission_report, 'a', "Sending keepalives");
            start = std::chrono::steady_clock::now();
            for (auto& connection : one_hop_connections){
                serverConnection recipient = connection.second;
                if(recipient.name == "A5_67"){
                    continue;
                }
                if(SENDINGSTATUS){
                    sendMessage(recipient.name, "STATUSREQ");
                }
                std::string message_to_send = "KEEPALIVE," + std::to_string(message_queues[recipient.name].size());
                sendMessage(recipient.name, message_to_send);
            }

            // std::cout << "\n\n\nTEST\nALL SOCKS: ";
            // for (auto& sock : autobots){
            //     std::cout << sock.fd << " ";
            // }
            // std::cout << "\nCLIENT SOCKS: ";
            // for (auto& sock : clientSocketList){
            //     std::cout << sock << " ";
            // }
            // std::cout << "\n";
            SENDINGSTATUS = !SENDINGSTATUS;
        }

        if (time_passed_pending_timer.count() >= 20){
            start_pending_timer = std::chrono::steady_clock::now();
            if (ports_pending_connection.size() > 0){
                std::cout << "[ACTION] Clearing pending connections, " << ports_pending_connection.size() << " ports removed\n";
                ports_pending_connection.clear();
            }
        }

        if (n < 0){
            perror("poll failed - closing down\n");
            log_message(mission_report, 'e', "Poll failed - closing down");
            finished = true;
        }
        else{
            //std::cout << n << " new events\n";
            std::vector<pollfd> autobots_to_add;
            for(pollfd &bot : autobots){
                if((int)bot.fd == listenSock){
                    if(bot.revents & POLLIN){
                            clientSock = accept(listenSock, (struct sockaddr *)&client,&clientLen);
                            if (clientSock == -1){
                                std::cout << "[ERROR] Unable to accept connection\n";
                                log_message(mission_report, 'e', "Unable to accept connection");
                                continue;
                            }
                            pollfd temp{.fd=clientSock, .events=POLLIN, .revents=0};
                            autobots_to_add.push_back(temp);
                            clientSocketList.push_back(temp.fd);
                            printf("accept***\n");
                            clients[clientSock] = new Client(clientSock);
                            n--;
                            printf("Client connected on server: %d\n", clientSock); //TODO: SEND HELO
                            log_message(mission_report, 'i', "Client connected on server " + std::to_string(clientSock));
                            sendMessage("", "HELO,A5_67", clientSock);
                    }
                    bot.revents = 0;
                    break;
                }
            }

            for (pollfd &bot : autobots_to_add){
                autobots.push_back(bot);
            }
            autobots_to_add.clear();
            std::set<int> unique_fds;
            for(auto &bot : autobots) {
                if (unique_fds.count(bot.fd)) {
                    std::cout << "[ERROR] DUPLICATE FD IN AUTOBOTS: " << bot.fd << "\n";
                }
                unique_fds.insert(bot.fd);
            }

                // Now check for commands from clients
                std::vector<Client *> disconnectedClients;  
                for(auto const& pair : clients)
                {
                    Client *client = pair.second;
                    
                    for(pollfd &check_fd : autobots){
                        if (check_fd.revents == 0)
                            continue;

                        if (check_fd.fd == client->sock){
                            std::cout << "[INFO]   FOUND SOCKET\n";
                            log_message(mission_report, 'i', "Found socket");
                            std::cout << "[DEBUG] Processing socket " << client->sock << " revents=" << check_fd.revents << "\n";
                            {
                                // recv() == 0 means client has closed connection
                                if(check_fd.revents & POLLHUP)
                                {
                                    disconnectedClients.push_back(client);
                                    closeClient(client->sock, autobots);
                                    check_fd.revents = 0;
                                }
                                // We don't check for -1 (nothing received) because select()
                                // only triggers if there is something on the socket for us.
                                else if (check_fd.revents & POLLIN)
                                {
                                    std::cout << "[INFO]   RECIEVING\n";
                                    log_message(mission_report, 'i', "Recieving");
                                    memset(buffer, 0, sizeof(buffer));
                                    int recieved = recv(client->sock, buffer, sizeof(buffer), 0);
                                    std::cout << "[INFO]   Recieved: " << recieved << "\n";

                                    if (recieved == 0)
                                    {
                                        std::cout << "[INFO]   Peer closed connection\n";
                                        log_message(mission_report, 'i', "Peer closed connection");
                                        disconnectedClients.push_back(client);
                                        closeClient(client->sock, autobots);
                                        check_fd.revents = 0;
                                        break;
                                    }

                                    std::cout << "[INFO]   The Buffer(hex): ";
                                    log_message(mission_report, 'i', "The buffer(hex)");
                                    std::string buffer_str;
                                    for (int i = 0; i < recieved; i++) {
                                        unsigned char c = buffer[i];
                                        if (isprint(c)){
                                            std::cout << c;
                                            buffer_str += c;
                                        }else{
                                            std::cout << "\\x" << std::hex << (int)c << std::dec;
                                            buffer_str += "\\x" + int(c);
                                        }}
                                    std::cout << "\n"; 
                                    log_message(mission_report, 'i', buffer_str);
                                    clientCommand(client->sock, autobots, buffer, recieved);
                                    std::cout << "[DEBUG] After processing, revents = " << check_fd.revents << "\n";
                                    check_fd.revents = 0;
                                    }
                                else{
                                    std::cout << "[ERROR] Unknown poll event on socket " << check_fd.fd << "\n";
                                    log_message(mission_report, 'e', "Unknown poll event on socket");
                                    check_fd.revents = 0;
                                }
                            }
                            break;
                        }
                    }
                }
                // Remove client from the clients list
                for (auto const& c : disconnectedClients) {
                    for (auto it = one_hop_connections.begin(); it != one_hop_connections.end(); ) {
                        if (it->second.socket == c->sock) {
                            it = one_hop_connections.erase(it);
                            break;
                        } else {
                            ++it;
                        }
                    }
                    clients.erase(c->sock);
                }


            }
        }




    return 0;
}