# NETSECURE MONITOR — Java & Data Structures

A menu-driven Java project demonstrating simulated network traffic monitoring and basic anomaly detection.

## Features

1. Display network traffic
2. Show traffic statistics
3. Detect network anomalies
4. Search packets by source or destination IP
5. Add a network packet
6. Exit the system

## Data structures and Java concepts

- `Packet` class: represents one packet record.
- `ArrayList<Packet>`: stores the collection of packet objects.
- `Scanner`: reads user input.
- `for` loops: traverse packet records.
- `if-else`: classify protocols and detect anomalies.
- `switch`: selects the menu operation.
- Methods: separate the program into manageable operations.

The packet list is limited to 100 records to match the original C project.

## Packet fields

- ID
- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Packet size in bytes

## Anomaly detection rules

- Large packet: `packetSize > 1400`
- Telnet traffic: `destinationPort == 23`
- High source port: `sourcePort > 60000`

These are simple educational rules, not a complete security detection system.

## Requirements

- JDK (Java Development Kit) installed
- Command Prompt, terminal, or Java IDE

## Compile and run

Save the source as `NetSecureMonitor.java`.

```bash
javac NetSecureMonitor.java
java NetSecureMonitor
```

## GitHub upload

Create a repository named `netsecure-monitor-java` and upload:

- `NetSecureMonitor.java`
- `README.md`

Suggested repository description:

`A Java and Data Structures project for simulated network traffic monitoring, traffic statistics, IP search, and basic anomaly detection.`

## Important note

This project works with sample and user-entered packet records. It does not capture, inspect, or monitor live network traffic.
