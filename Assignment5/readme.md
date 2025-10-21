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
(Note that for this early version, responses to these are printed in the servers console and not sent to the client)

- **GETMSG** - Retrieve a single message from the server for your group
- **SENDMSG,GROUP_ID,message** - Send a message to specified group
- **LISTSERVERS** - List servers your server is currently connected to

### Example:
```bash
SENDMSG,45,Hello Group 45!
GETMSG
LISTSERVERS
```

## Botnet Protocol Features

- **Automatic peer discovery** via HELO/SERVERS commands
- **Store-and-forward messaging** between groups
- **Keepalive monitoring** (sent every 60 seconds)
- **Message queuing** for offline/disconnected groups
- **Multi-hop routing** through the botnet

## Configuration Notes

- Group ID is hardcoded to `A5_67`
- Server maintains connections to 3-8 other servers
- Messages are automatically routed through the botnet
- All communication uses custom protocol framing with SOH/STX/ETX

## Troubleshooting

- Ensure your server is reachable on the specified port
- Check firewall settings if connections fail
- Server maintains detailed logs of all sent/received commands
- Use `LISTSERVERS` command to verify botnet connections
- If the server appears stuck, terminate with CTRL + C and restart

---

**Authors**: Kristján Orri Leifsson, Tryggvi Ólafsson  
**Date**: 13.10.2025
**Group**: 67

---

TODO:
-FIX SEGFAULT WHEN INVALID COMMAND
-LOGS DONT OUTPUT HEX
-MESSAGE NEW PROTOCOL -> FORWARD
-SOME PEOPLE USE DIFFERENT HELO
-CLIENT CANT CONNECT IF FULL
-CINNECTED ON SERVER: -1 CRASH