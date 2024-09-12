# Reliable Transport Protocol (DRTP)

<div align="center">
  <img src="https://cdn.freebiesupply.com/logos/large/2x/python-5-logo-png-transparent.png" alt="Python-Logo" width="500"/>
</div>

**Candidate Number:** 311  
**Course Code:** DATA2410  
**Course Name:** Datanettverk og skytjenester  
**Study Program:** Bachelor i Dataingeniørfag  
**Submission Deadline:** 21.05.2024
### **Grade:** A

## Overview

The Reliable Transport Protocol (DRTP) is a file transfer application designed to ensure reliable data transmission over UDP. Developed as part of the DATA2410 course on data networks and cloud services, this project features a client-server model that guarantees accurate file transfers through advanced networking techniques.

The DRTP application includes both client and server components that work in unison to transfer files reliably. The design is based on theoretical concepts from lectures and has been tested using Mininet, a network emulator.

### Key Features

- **UDP Socket Communication**: Manages file transfers using UDP sockets.
- **Sliding Window Mechanism**: Implements a sliding window protocol to control data flow and ensure reliability.
- **Three-Way Handshake**: Establishes a reliable connection between client and server.
- **Connection Teardown**: Properly closes the connection after file transfer completion.
- **Go-Back-N Protocol**: Ensures reliability through packet retransmission and acknowledgment.

## Implementation Details

For detailed implementation information, including code and technical descriptions, please refer to the provided PDF document titled [311_documentation.pdf](311_documentation.pdf). This document covers the code structure, testing methodologies, and overall protocol design.

## Getting Started

To use the DRTP application, follow these instructions:

**For the Server:**
```bash
python application.py -s -i <ip> -p <port> -d <discard_sequence_number>
```

**For the Client:**
```bash
python application.py -c -i <ip> -p <port> -f <file_path> -w <window_size>
```

Ensure that the IP address and port number are the same for both client and server.

### How to Test `application.py`:

1. **Install Ubuntu**: Set up Ubuntu inside Oracle VM VirtualBox.
2. **Install Required Tools**: Install Mininet, Xterm, and Ubuntu utilities.
3. **Configure Shared Folder**: Create a shared folder between the Host OS and Ubuntu OS for your Python files.
4. **Run Mininet**: Use `sudo mn --custom <custom_topo_file>` to start Mininet with your custom topology file.
5. **Test the Application**: Use Xterm to test the interaction between separate nodes (e.g., client on h1 and server on h2).

For additional instructions and detailed usage, consult the [PDF document](311_documentation.pdf).

## Contact

For any questions or feedback, please reach out to me on [LinkedIn](https://www.linkedin.com/in/rafey-afzal-21a618290/).

Note: The PDF document provides comprehensive technical details of the DRTP implementation and should be referred to for a complete understanding of the protocol and code.
