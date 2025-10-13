// SERVER

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
    int port; 
    int socket;
};

struct messageStruct{
    std::string from_name;
    std::string to_name;
    std::string message_data;
};

std::map<int, Client*> clients;
std::map<std::string, serverConnection> one_hop_connections;
std::map<std::string, serverConnection> known_servers;
std::map<std::string, std::deque<messageStruct> > message_queues;
// TODO: HARDCODED CHANGE LATER
std::string TSAM_IP = "130.208.246.98";


int open_sock(int port_nr){

    struct sockaddr_in sk_addr;   // address settings for bind()
    int sock;                     // socket opened for this port
    int set = 1;                  // for setsockopt

#ifdef __APPLE__     
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Failed to open socket");
        return(-1);
    }
#else
    if((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
    {
        perror("Failed to open socket");
        return(-1);
    }
#endif

   if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
   {
      perror("Failed to set SO_REUSEADDR:");
   }
   set = 1;
#ifdef __APPLE__     
   if(setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0)
   {
     perror("Failed to set SOCK_NOBBLOCK");
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
      return(-1);
   }
   else
   {
      return(sock);
   }
}

void closeClient(int clientSocket, std::vector<pollfd>& autobots)
{

    printf("ACTION] Closing client socket: %d\n", clientSocket);

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

void sendMessage(std::string client_name, std::string send_message, int socket = -1){
    int send_socket = -1;
    if (one_hop_connections.find(client_name) != one_hop_connections.end()){
        send_socket = one_hop_connections[client_name].socket;
    }
    else if(socket != -1){
        send_socket = socket;
    }
    else{
        std::cout << "[ERROR] NOT FOUND CONNECTION FOR SENDING\n";
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
        int result = send(send_socket, message.data(), message.size(), 0);
    // TODO: ERROR HANDLING
}

void clientCommand(int clientSocket, std::vector<pollfd>& autobots, char *buffer, int recieved){
    std::string msg(buffer);
    if (msg.find("SENDMSG") != std::string::npos){
        std::string cur_message;
        bool got_id = false;
        std::string group_str = "";

        for (int i = 8; i < recieved; i++) {
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
        messageStruct new_message;
        new_message.from_name = "A_67";
        new_message.to_name = "A_" + group_str;
        new_message.message_data = cur_message;
        if(message_queues.find(new_message.to_name) == message_queues.end()){
            message_queues[new_message.to_name] = {new_message};
        }
        else{
            message_queues[new_message.to_name].push_back(new_message);
        }
        return;
    }
    if (msg.find("GETMSG") != std::string::npos){
        if(message_queues.find("A_67") == message_queues.end()){
            message_queues["A_67"] = std::deque<messageStruct>();
        }
        if(message_queues["A_67"].empty()){
            std::cout << "[INFO] NO NEW MESSAGES\n";
        } else {
            std::cout << "[ACTION] Showing oldest message: " << message_queues["A_67"].front().message_data << "\n";
            message_queues["A_67"].pop_front();
        }
        return;
    }



    int total_len = 0;
    std::cout << "[ACTION] DOING CLIENT COMMAND\n";
    if (recieved < 5) { // minimum frame size
        std::cout << "[ERROR] Command too short\n";
        return;
    }

    while (total_len < recieved){
        uint16_t netlen;
        memcpy(&netlen, buffer + total_len + 1, sizeof(netlen));
        uint16_t msg_len = ntohs(netlen);

        std::cout << "[INFO]   recieved message has a length of: " << msg_len << "\n";

        std::string message;
        message.insert(message.end(), buffer + total_len, buffer + total_len + msg_len);

        // now you can sanity-check
        if (msg_len > (uint16_t)recieved) {

            std::cout << "[ERROR] incomplete frame: declared " << msg_len << " got " << recieved << "\n";
            std::cout << "[INFO]   The Buffer(hex): ";
            for (int i = total_len; i < recieved; i++) {
                unsigned char c = buffer[i];
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
        
        if (message.rfind("HELO") != -1){
            command_prefix = "HELO";
            found = true;
            std::cout << "[ACTION] DOING HELO\n";
            std::string group_name_str = "";
            group_name_str.insert(group_name_str.end(), buffer+total_len+9, buffer + total_len + msg_len-1);
            std::cout << "[INFO]   The current group name: " << group_name_str << "\n";
            
            if(known_servers.find(group_name_str) != known_servers.end()){
                one_hop_connections[group_name_str] = known_servers[group_name_str];
            }
            else{
                serverConnection temp={.name=group_name_str, .addr=TSAM_IP, .port=-1, .socket=clientSocket}; //TODO: FIX THE IP HARDCODE
                one_hop_connections[group_name_str] = temp;
            }
            if (message_queues.find(group_name_str) == message_queues.end()){
                message_queues[group_name_str] = {};
            }
            if(known_servers.find(group_name_str) == known_servers.end()){
                known_servers[group_name_str] = one_hop_connections[group_name_str];
            }
            
            std::string send_str = "SERVERS,";
            send_str += "A5_67," + TSAM_IP + ",4067;";
            for (auto& one_hopper : one_hop_connections){
                send_str += one_hopper.second.name + ",";
                send_str += one_hopper.second.addr + std::string(",");
                send_str += std::to_string(one_hopper.second.port) + ";";
            }
            std::cout << "[INFO]   The send string: " << send_str << "\n";
            sendMessage(group_name_str, send_str);
        } 
        else if (message.rfind("KEEPALIVE") != -1){
            command_prefix = "KEEPALIVE";
            found = true;
        } 
        else if (message.rfind("GETMSGS") != -1){
            command_prefix = "GETMSGS";
            found = true;
            std::cout << "[ACTION] DOING GETMSGS\n";
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
            
            std::cout << "[INFO]   The message: "<< message << "\n";

            messageStruct new_message;
            std::string building_message = "";
            int checks = 0;
            std::string send_message_to = "";
            std::string send_message_from = "";
            std::cout << "[INFO] PARSING SEND MESSAGE STRING: " << building_message << " ";
            for (int i = 11; i < msg_len; i++)
            {
                if (message[i] == ',' && checks < 3){
                    if(checks == 1){
                        send_message_to = building_message;
                        std::cout << "SENDING MESSAGE TO: " << send_message_to << " ";
                        building_message = "";
                    }
                    else if (checks == 2){
                        send_message_from = building_message;
                        std::cout << "SENDING MESSAGE FROM: " << send_message_from<< " ";  
                        building_message = "";
                    }
                    checks += 1;
                    continue;
                }
                else{
                    building_message += message[i];
                }
            }
            std::cout << "THE MESSAGE DATA: " << building_message << "\n";
            new_message.from_name = send_message_from;
            new_message.to_name = send_message_to;
            new_message.message_data = building_message;
            
            if(message_queues.find(send_message_to) == message_queues.end()){
                message_queues[send_message_to] = {new_message};
            }
            else{
                message_queues[send_message_to].push_back(new_message);
            }
        } 
        else if (message.rfind("STATUSREQ") != -1){
            command_prefix = "STATUSREQ";
            found = true;
        } 
        else if (message.rfind("SERVER") != -1){
            command_prefix = "SERVER";
            found = true;

            std::cout << "[ACTION] DOING SERVER\n";
            
            std::cout << "[INFO]   The message: "<< message << "\n";

            int index = 12;
            int cur_part = 0;
            std::string current_server = "";
            serverConnection current_connection;
            while(index < message.size()){
                if(message[index] == ';'){
                    current_connection.port = std::stoi(current_server);
                    std::cout << "PORT: " << current_server << " ";
                    current_server = "";
                    if(one_hop_connections.find(current_connection.name) != one_hop_connections.end()){
                        std::string lookup_name = current_connection.name;
                        if(one_hop_connections[lookup_name].port == -1){
                            one_hop_connections[lookup_name].port = current_connection.port;
                        }
                    }

                    known_servers[current_connection.name] = current_connection;
                    current_connection = serverConnection{};
                    current_server = "";
                    cur_part = 0;
                    std::cout << "\n";
                }
                else if(message[index] == ','){
                    if(cur_part == 0){
                        current_connection.name = current_server;
                        std::cout << "[INFO]   NAME: " << current_server << " ";
                        current_server = "";
                    }
                    else if(cur_part == 1){
                        current_connection.addr = current_server;
                        std::cout << "IP: " << current_server << " ";
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
        if(found == false){
            //std::cout << "Unrecognized command prefix";
            return;
        }
        total_len += msg_len;
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
    int port = atoi(argv[1]);   
    const char* address = argv[2]; //130.208.246.98
    int connect_port = atoi(argv[3]);

    int listenSock = open_sock(port);

    if (listenSock == -1){
        std::cout << "[ERROR] Opening listen sock\n";
        return 0;
    }

    if(listen(listenSock, MAX_BACKLOG) < 0){
        printf("Listen failed on port %s\n", argv[1]);
        exit(0);
    }
    else {
        pollfd temp{.fd=listenSock, .events=POLLIN, .revents=0};
        autobots.push_back(temp);
    }

    int connectSock = socket(AF_INET, SOCK_STREAM, 0);
    if(connectSock < 0){
        perror("Failed to create client socket");
        return 0;
    }

    if (connectSock == -1){
        std::cout << "[ERROR] opening connect sock\n";
        return 0;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr)); 

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(connect_port);

    if (connect(connectSock, (sockaddr*) &server_addr, sizeof(server_addr)) < 0){
        std::cout << "[ERROR] Initial connection sock\n";
        return 0;
    }
    pollfd temp{.fd=connectSock, .events=POLLIN, .revents=0};
    autobots.push_back(temp);
    clients[temp.fd] = new Client(temp.fd);

    uint8_t SOH = 0x01;
    uint8_t STX = 0x02;
    uint8_t ETX = 0x03;
    std::vector<uint8_t> message;
    std::string command = "HELO,A5_67";
    uint16_t length = 1 + 2 + 1 + command.size() + 1;
    uint16_t length_nbo = htons(length);

    message.push_back(SOH);
    message.push_back(static_cast<uint8_t>(length_nbo & 0xFF));
    message.push_back(static_cast<uint8_t>((length_nbo >> 8) & 0xFF));
    message.push_back(STX);
    message.insert(message.end(), command.begin(), command.end());
    message.push_back(static_cast<char>(ETX));
    int sendtest = send(connectSock, message.data(), message.size(), 0);

    std::cout << sendtest << "\n";

    std::cout << "[ACTION] starting loop\n";
    auto start = std::chrono::high_resolution_clock::now();
    while(!finished){
        int n = poll(autobots.data(), autobots.size(), 500);

        // KEEP ALIVE SENDING
        auto time_passed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start);
        if (time_passed.count() == 65){
            std::cout << "[ACTION] SENDING KEEPALIVES NOW NOW NOW\n";
            start = std::chrono::high_resolution_clock::now();
            for (auto& connection : one_hop_connections){
                serverConnection recipient = connection.second;
                if(recipient.name == "A5_67"){
                    continue;
                }
                std::string message_to_send = "KEEPALIVE," + std::to_string(message_queues[recipient.name].size());
                sendMessage(recipient.name, message_to_send);
            }
        }

        if (n < 0){
            perror("poll failed - closing down\n");
            finished = true;
        }
        else{
            //std::cout << n << " new events\n";
            for(pollfd &bot : autobots){
                if((int)bot.fd == listenSock){
                    if(bot.revents & POLLIN){
                        clientSock = accept(listenSock, (struct sockaddr *)&client,&clientLen);
                        pollfd temp{.fd=clientSock, .events=POLLIN, .revents=0};
                        autobots.push_back(temp);
                        printf("accept***\n");
                        clients[clientSock] = new Client(clientSock);
                        n--;
                        printf("Client connected on server: %d\n", clientSock); //TODO: SEND HELO
                        sendMessage("", "HELO,67", clientSock);
                    }
                    break;
                }
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
                            {
                                // recv() == 0 means client has closed connection
                                if(check_fd.revents & POLLHUP)
                                {
                                    disconnectedClients.push_back(client);
                                    closeClient(client->sock, autobots);

                                }
                                // We don't check for -1 (nothing received) because select()
                                // only triggers if there is something on the socket for us.
                                else if (check_fd.revents & POLLIN)
                                {
                                    std::cout << "[INFO]   RECIEVING\n";
                                    int recieved = recv(client->sock, buffer, sizeof(buffer), 0);

                                    if (recieved == 0)
                                    {
                                        std::cout << "[INFO]   Peer closed connection\n";
                                        disconnectedClients.push_back(client);
                                        closeClient(client->sock, autobots);
                                        check_fd.revents = 0;
                                        break;
                                    }

                                    std::cout << "[INFO]   The Buffer(hex): ";
                                    for (int i = 0; i < recieved; i++) {
                                        unsigned char c = buffer[i];
                                        if (isprint(c))
                                            std::cout << c;
                                        else
                                            std::cout << "\\x" << std::hex << (int)c << std::dec;
                                    }
                                    std::cout << "\n"; 
                                    clientCommand(client->sock, autobots, buffer, recieved);
                                    check_fd.revents = 0;
                                }
                                else{
                                    std::cout << "[ERROR] Unknown poll event on socket " << check_fd.fd << "\n";
                                }
                            }
                        }
                    }
                }
                // Remove client from the clients list
                for(auto const& c : disconnectedClients){
                    clients.erase(c->sock);
                    
                }

            }
        }




    return 0;
}


