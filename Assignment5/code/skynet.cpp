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
#include <map>

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
    const char* addr;
    int port; 
    int socket;
};

std::map<int, Client*> clients;
std::map<int, serverConnection> one_hop_connections;
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

    printf("Client closed connection: %d\n", clientSocket);

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

void sendMessage(int clientId, std::string message){
    serverConnection connection = one_hop_connections[clientId];
    int result = sendto(connection.socket, message.c_str(), message.size(), 0, (const sockaddr*)&connection.addr, sizeof(connection.addr));
    // TODO: ERROR HANDLING
}

void clientCommand(int clientSocket, std::vector<pollfd>& autobots, char *buffer, int recieved){
    std::string command_prefix = "";
    bool found = false;
    for (int i = 0; i < recieved; i++)
    {
        command_prefix += buffer[i];
        if(command_prefix == "HELO"){
            found = true;
            break;
        }
        else if (command_prefix == "KEEPALIVE"){
            found = true;
            break;
        }
        else if (command_prefix == "GETMSGS"){
            found = true;
            break;
        }
        else if (command_prefix == "SENDMSG"){
            found = true;
            break;
        }
        else if (command_prefix == "STATUSREQ"){
            found = true;
            break;
        }
        else if (command_prefix == "STATUSRESP"){
            found = true;
            break;
        }
        else if (command_prefix == "SERVERS"){
            found = true;
            break;
        }
    }
    if(found == false){
        std::cout << "Unrecognized command prefix";
    }
    if(command_prefix == "HELO"){
        std::cout << "DOING HELO\n";
        int group_id = 0;
        std::string group_id_str = "";
        for (int i = command_prefix.size()+1; i < recieved; i++)
        {
            group_id_str += buffer[i];
        }
        group_id = std::stoi(group_id_str);

        int group_port = 4000 + group_id;
        
        serverConnection temp={.name="A5_"+group_id_str, .addr=TSAM_IP.c_str(), .port=group_port, .socket=clientSocket}; //TODO: FIX THE IP HARDCODE
        one_hop_connections[group_id] = temp;
        
        std::string send_str = "SERVERS,";
        for (auto& one_hopper : one_hop_connections){
            send_str += one_hopper.second.name + ",";
            send_str += one_hopper.second.addr + std::string(",");
            send_str += std::to_string(one_hopper.second.port) + ";";
        }

        sendMessage(clientSocket, send_str);
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
    char buffer[1025];

    if (argc < 4){
        std::cout << "Incorrect number of arguments\n";
        return 0;
    }
    int port = atoi(argv[1]);   
    const char* address = argv[2]; //130.208.246.98
    int connect_port = atoi(argv[3]);

    int listenSock = open_sock(port);

    if (listenSock == -1){
        std::cout << "Error opening listen sock\n";
        return 0;
    }

    if(listen(listenSock, MAX_BACKLOG) < 0){
        printf("Listen failed on port %s\n", argv[1]);
        exit(0);
    }
    else {
        pollfd temp{.fd=listenSock};
        autobots.push_back(temp);
    }

    int connectSock = socket(AF_INET, SOCK_STREAM, 0);
    if(connectSock < 0){
        perror("Failed to create client socket");
        return 0;
    }

    if (connectSock == -1){
        std::cout << "Error opening connect sock\n";
        return 0;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr)); 

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(address);
    server_addr.sin_port = htons(connect_port);

    if (connect(connectSock, (sockaddr*) &server_addr, sizeof(server_addr)) < 0){
        std::cout << "Error on initial connection sock\n";
        return 0;
    }
    pollfd temp{.fd=connectSock};
    autobots.push_back(temp);

    short SOH = 0x01;
    short STX = 0x02;
    short ETX = 0x03;
    std::string message = "";
    std::string command = "HELO,67";
    uint16_t length = 1 /*SOH*/ + 2 /*length*/ + 1 /*STX*/ + command.size() + 1 /*ETX*/;
    int length_nbo = htons(length);

    message.push_back(static_cast<char>(SOH));
    message.append(reinterpret_cast<const char*>(&length_nbo), sizeof(length_nbo));
    message.push_back(static_cast<char>(STX));
    message.append(command);
    message.push_back(static_cast<char>(ETX));
    int sendtest = send(connectSock, message.c_str(), message.size(), 0);
    int recieved = recv(connectSock, buffer, sizeof(buffer), MSG_DONTWAIT);
    std::cout << buffer;

    std::cout << "starting loop\n";

    while(!finished){
        int n = poll(autobots.data(), autobots.size(), 500);
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
                        pollfd temp{.fd=clientSock};
                        autobots.push_back(temp);
                        printf("accept***\n");
                        clients[clientSock] = new Client(clientSock);
                        n--;
                        printf("Client connected on server: %d\n", clientSock);
                    }
                    break;
                }
            }

                // Now check for commands from clients
                std::vector<Client *> disconnectedClients;  
            while(n-- > 0)
                {
                for(auto const& pair : clients)
                {
                    Client *client = pair.second;

                    for(pollfd check_fd : autobots){
                        if (check_fd.fd == client->sock){
                            {
                                // recv() == 0 means client has closed connection
                                if(check_fd.revents == POLLHUP)
                                {
                                    disconnectedClients.push_back(client);
                                    closeClient(client->sock, autobots);

                                }
                                // We don't check for -1 (nothing received) because select()
                                // only triggers if there is something on the socket for us.
                                else
                                {
                                    int recieved = recv(client->sock, buffer, sizeof(buffer), MSG_DONTWAIT);
                                    std::cout << buffer;
                                    clientCommand(client->sock, autobots, buffer, recieved);
                                }
                            }
                        }
                    }
                }
                // Remove client from the clients list
                for(auto const& c : disconnectedClients)
                    clients.erase(c->sock);
                }


        }

    }



    return 0;
}


