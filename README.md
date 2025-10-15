# net2_utils - MZ Networking Library v2

A modern, asynchronous C++ networking library built on ASIO with built-in security and thread-safe design.

## Overview

net2_utils is a high-performance networking library designed for creating secure client-server applications in C++. It provides an abstraction layer over ASIO (Asynchronous I/O) with additional features like:

- Secure communication with encryption
- Thread-safe message handling
- Asynchronous operation for maximum performance
- Clean interfaces for both client and server implementations
- Strong type safety with modern C++ concepts
- Comprehensive error handling
- Cross-platform compatibility (Windows, Linux, macOS)

## Features

### Core Components

- **Client Interface**: Easy-to-use API for connecting to servers, sending messages, and handling responses
- **Server Interface**: Robust server implementation with connection management and client authentication
- **Encryption**: Built-in encryption support for secure communications
- **Message Queuing**: Thread-safe message queue system for asynchronous processing
- **Connection Management**: Automatic connection tracking and cleanup
- **Error Handling**: Comprehensive error reporting and handling
- **Endian Handling**: Automatic handling of network byte order

### Technical Highlights

- Built on standalone ASIO library for asynchronous I/O operations
- Uses modern C++17/20 features including concepts, span, and formatting
- Microsecond-precision timing for network operations
- Thread-safe design with ASIO strands for concurrent processing
- Clean separation of concerns with clear class hierarchies
- Extensive documentation using Doxygen format

## Requirements

- C++17 or later compiler (C++20 recommended)
- ASIO standalone library
- Platform: Windows, Linux, or macOS

## Installation

1. Include the net2_utils headers in your project
2. Link against ASIO standalone library
3. Ensure your compiler supports required C++ features
```
// Example CMake configuration add_subdirectory(net2_utils) target_link_libraries(your_application PRIVATE net2_utils)
```


## Basic Usage

### Creating a Client
```
#include "net2_client_interface.h"
// Create client application class MyClient : public mz::net2::client_interface
{
  protected:
  // Override to handle received messages
  void process_message(stdshared_ptr<mz::net2::connection>& remote, mz::net2::packet& msg) override
  {
    // Process received messages
    stdcout << "Received message, command: " << msg.Head.Command << std::endl;
    }
  };

int main()
{
  // Create client MyClient client;
  // Connect to server
  client.connect("localhost", 60000);

  // Main loop - process up to 10 messages per update
  while (true)
  {
    client.update(10, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return 0;
}
```

### Creating a Server
```
#include "net2_server_interface.h"
// Create server application
class MyServer : public mz::net2::server_interface
{
public:
  MyServer(uint16_t port) : mz::net2::server_interface(port) {}

protected:
  // Override to handle received messages
  void process_message(std::shared_ptr<mz::net2::connection>& client, mz::net2::packet& msg) override
  {
    // Process received messages
    stdcout << "Message from client: " << client->string() << std::endl;
    // Send response if needed
    // ...
  }

  // Optional: Override to add custom client authentication
  void authenticate_client(std::shared_ptr<mz::net2::connection> client) noexcept override
  {
    // Implement your authentication logic
  }
};

int main()
{
  // Create server on port 60000 MyServer server(60000);
  // Start server
  if (!server.start())
  {
    // Main loop - process up to 100 messages per update
    while (true) {
        server.update(100, true);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
return 0;
}
```

## Architecture

The library is organized into several key components:

- `basic_interface`: Base class for network interfaces
- `client_interface`: Client-side implementation
- `server_interface`: Server-side implementation
- `connection`: Manages individual network connections
- `packet`: Data container for network messages
- `safe_queue`: Thread-safe message queue

All components reside within the `mz::net2` namespace.

## Security

The library implements encryption using the BlowFish algorithm with a secure handshake protocol. This ensures that all communications between clients and servers are encrypted and protected from eavesdropping.

## Performance Considerations

- Uses asynchronous I/O for maximum performance
- Employs strand-based synchronization to avoid explicit locking
- Minimizes memory allocations through efficient buffer management
- Optimizes endian conversion only when necessary

## License

Copyright (c) 2021-2024 Meysam Zare. All rights reserved.

