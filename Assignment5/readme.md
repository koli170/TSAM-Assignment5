# Assignment 5 - The Botnet Saves the World

## Setup Instructions

1. Extract the assignment ZIP file.

2. Navigate to the extracted folder in your terminal.

### The terminal path should look like this:
```bash
../Assignment5 %
```

## Compilation

Compile the code using the `make` command:
```bash
make
```

This will create two executables:
- `tsamgroup67` (server)
- `grimlock` (client)

## Server Usage

Run the server with the following syntax:
```bash
./tsamgroup67 [listen_port] [connect_ip] [connect_port]
```

### Parameters:
- **listen_port**: Port number for the server to listen on
- **connect_ip**: IP address of another server to connect to initially
- **connect_port**: Port number of the other server to connect to

### Example:
```bash
./tsamgroup67 4067 130.208.246.98 4044
```

## Client Usage

Run the client with the following syntax:
```bash
./grimlock [server_ip] [server_port]
```

### Parameters:
- **server_ip**: IP address of your server
- **server_port**: Port number of your server

### Example:
```bash
./grimlock 130.208.246.98 4067
```

## Available Client Commands

Once connected to your server, the client supports these commands:

- **GETMSG** - Retrieve a single message from the server for your group
- **SENDMSG,GROUP_ID,message** - Send a message to specified group. The server will try to relay the message to another server if it's not connected to the recipient
- **LISTSERVERS** - List servers your server is currently connected to

### Example:
```bash
SENDMSG,A5_45,Hello Group 45!
GETMSG
LISTSERVERS
```

## Server-to-Server Protocol Commands

The server automatically handles these protocol commands when communicating with other servers:

### Core Protocol Commands:

- **HELO,GROUP_ID** - Handshake command to identify the server
  - Sent when establishing a new connection
  - Returns: SERVERS list with all known servers

- **SERVERS,GROUP_ID,IP,PORT;...** - Exchange server topology information
  - Sent in response to HELO
  - Contains list of all known servers in the network
  - Format: Multiple entries separated by semicolons

- **SENDMSG,TO_GROUP,FROM_GROUP,MESSAGE[EOD]HOP_LIST** - Forward message between groups
  - TO_GROUP: Destination group ID
  - FROM_GROUP: Originating group ID
  - MESSAGE: The actual message content
  - EOD (0x04): End of data marker (optional)
  - HOP_LIST: Comma-separated list of groups that have seen this message

- **GETMSGS,GROUP_ID** - Request queued messages for a specific group
  - Server responds with all queued SENDMSG commands for that group
  - Called automatically when KEEPALIVE indicates pending messages

- **KEEPALIVE,MESSAGE_COUNT** - Heartbeat to maintain connection
  - Sent every 61 seconds to all connected servers
  - MESSAGE_COUNT: Number of queued messages for the recipient
  - When recieved, triggers GETMSGS if count > 0

- **STATUSREQ** - Request status information from connected server
  - Server responds with STATUSRESP containing message queue sizes

- **STATUSRESP,GROUP1,COUNT1,GROUP2,COUNT2,...** - Status information response
  - Lists all connected groups and their message queue sizes
  - Sent in response to STATUSREQ

## Botnet Protocol Features

- **Automatic peer discovery** via HELO/SERVERS commands
- **Store-and-forward messaging** between groups
- **Flooding-based routing** with hop tracking to prevent loops
- **Keepalive monitoring** (sent every 60-65 seconds)
- **Message queuing** for offline/disconnected groups
- **Multi-hop routing** through the botnet
- **Automatic reconnection** to discovered servers
- **Loop prevention** using hop lists in relayed messages

## Configuration Notes

- Group ID is hardcoded to `A5_67`
- Server maintains connections to up to `MAX_BACKLOG` (8) other servers
- Messages are automatically routed through the botnet using flooding
- All communication uses custom protocol framing with SOH/STX/ETX/EOD markers
- The code was developed on Linux for the TSAM server environment
- BANNED_PORTS list prevents connections to problematic servers
- Pending connections timeout after 20 seconds

## Message Routing

The server uses a flooding algorithm for message routing:

1. When a SENDMSG is received, check if the destination is directly connected
2. If yes, deliver directly to that server
3. If no, forward to all connected servers **except** those in the hop list
4. Each server adds itself to the hop list before forwarding
5. Messages for your own group (A5_67) are stored in the local queue

## Troubleshooting

- Ensure your server is reachable on the specified port
- Check firewall settings if connections fail
- Server maintains detailed logs in `mission_report` file
- Use `LISTSERVERS` command to verify botnet connections
- If the server appears stuck, terminate with CTRL + C and restart
- Check the mission_report log file for detailed information about all commands
- Verify server is not trying to connect to itself or banned ports

## Log File

The server creates a `mission_report` log file that contains:
- Timestamps for all actions
- Connection attempts and results
- All sent and received commands
- Error messages and warnings
- Message routing decisions

---

**Authors**: Kristján Orri Leifsson, Tryggvi Ólafsson  
**Date**: 23.10.2025  
**Group**: 67

---