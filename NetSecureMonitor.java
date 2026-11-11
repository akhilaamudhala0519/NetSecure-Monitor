import java.util.ArrayList;
import java.util.Scanner;

class Packet {
    int id;
    String sourceIP;
    String destinationIP;
    int sourcePort;
    int destinationPort;
    String protocol;
    int packetSize;

    Packet(int id, String sourceIP, String destinationIP,
           int sourcePort, int destinationPort,
           String protocol, int packetSize) {
        this.id = id;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol.toUpperCase();
        this.packetSize = packetSize;
    }

    void displayPacket() {
        System.out.printf("%-5d %-16s %-16s %-8d %-8d %-8s %-10d%n",
                id, sourceIP, destinationIP,
                sourcePort, destinationPort, protocol, packetSize);
    }
}

public class NetSecureMonitor {

    private static final int MAX_PACKETS = 100;
    private static final ArrayList<Packet> packets = new ArrayList<>();
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {

        loadSamplePackets();

        int choice;

        do {
            System.out.println("\n====================================");
            System.out.println("        NETSECURE MONITOR");
            System.out.println("====================================");
            System.out.println("1. Display Network Traffic");
            System.out.println("2. Show Traffic Statistics");
            System.out.println("3. Detect Network Anomalies");
            System.out.println("4. Search Traffic by IP");
            System.out.println("5. Add Network Packet");
            System.out.println("6. Exit System");
            System.out.println("------------------------------------");

            choice = readInt("Enter your choice: ");

            switch (choice) {
                case 1:
                    displayAllPackets();
                    break;

                case 2:
                    showStatistics();
                    break;

                case 3:
                    detectAnomalies();
                    break;

                case 4:
                    searchByIP();
                    break;

                case 5:
                    addPacket();
                    break;

                case 6:
                    System.out.println("Exiting NetSecure Monitor...");
                    break;

                default:
                    System.out.println("Invalid choice. Select 1 to 6.");
            }

        } while (choice != 6);

        scanner.close();
    }

    private static void loadSamplePackets() {

        packets.add(new Packet(1, "192.168.1.10", "192.168.1.20",
                5000, 80, "TCP", 800));

        packets.add(new Packet(2, "192.168.1.20", "192.168.1.10",
                80, 5000, "TCP", 1200));

        packets.add(new Packet(3, "192.168.1.15", "8.8.8.8",
                5200, 53, "UDP", 500));

        packets.add(new Packet(4, "192.168.1.30", "192.168.1.10",
                65000, 23, "TCP", 900));

        packets.add(new Packet(5, "192.168.1.12", "192.168.1.25",
                4500, 443, "TCP", 1500));

        packets.add(new Packet(6, "192.168.1.18", "192.168.1.20",
                5500, 80, "TCP", 700));
    }

    private static void displayAllPackets() {

        if (packets.isEmpty()) {
            System.out.println("No packets available.");
            return;
        }

        printTableHeading();

        for (Packet packet : packets) {
            packet.displayPacket();
        }
    }

    private static void printTableHeading() {

        System.out.printf("%-5s %-16s %-16s %-8s %-8s %-8s %-10s%n",
                "ID", "Source IP", "Dest IP", "S.Port",
                "D.Port", "Proto", "Size (B)");

        System.out.println("--------------------------------------------------------------------------");
    }

    private static void showStatistics() {

        if (packets.isEmpty()) {
            System.out.println("No packets available for statistics.");
            return;
        }

        int tcpCount = 0;
        int udpCount = 0;
        int otherCount = 0;
        long totalBytes = 0;

        for (Packet packet : packets) {

            if (packet.protocol.equalsIgnoreCase("TCP")) {
                tcpCount++;

            } else if (packet.protocol.equalsIgnoreCase("UDP")) {
                udpCount++;

            } else {
                otherCount++;
            }

            totalBytes += packet.packetSize;
        }

        double averageSize = (double) totalBytes / packets.size();

        System.out.println("\n========== TRAFFIC STATISTICS ==========");
        System.out.println("Total packets       : " + packets.size());
        System.out.println("TCP packets         : " + tcpCount);
        System.out.println("UDP packets         : " + udpCount);
        System.out.println("Other protocol      : " + otherCount);
        System.out.println("Total traffic       : " + totalBytes + " bytes");

        System.out.printf("Average packet size : %.2f bytes%n", averageSize);
    }

    private static void detectAnomalies() {

        if (packets.isEmpty()) {
            System.out.println("No packets available for anomaly detection.");
            return;
        }

        int anomalyCount = 0;

        System.out.println("\n========== ANOMALY DETECTION ==========");

        for (Packet packet : packets) {

            boolean flagged = false;

            if (packet.packetSize > 1400) {
                System.out.println("\n[ALERT] Packet " + packet.id
                        + ": Large packet (" + packet.packetSize + " bytes).");

                flagged = true;
            }

            if (packet.destinationPort == 23) {
                System.out.println("\n[ALERT] Packet " + packet.id
                        + ": Telnet traffic detected (destination port 23).");

                flagged = true;
            }

            if (packet.sourcePort > 60000) {
                System.out.println("\n[ALERT] Packet " + packet.id
                        + ": High source port (" + packet.sourcePort + ").");

                flagged = true;
            }

            if (flagged) {
                anomalyCount++;
            }
        }

        if (anomalyCount == 0) {
            System.out.println("No anomalies detected.");

        } else {
            System.out.println("\nPackets with one or more alerts: " + anomalyCount);
        }
    }

    private static void searchByIP() {

        System.out.print("Enter IP address to search: ");

        String searchIP = scanner.nextLine().trim();

        boolean found = false;

        System.out.println("\nSearch results for " + searchIP + ":");

        printTableHeading();

        for (Packet packet : packets) {

            if (packet.sourceIP.equals(searchIP)
                    || packet.destinationIP.equals(searchIP)) {

                packet.displayPacket();
                found = true;
            }
        }

        if (!found) {
            System.out.println("No packets found for this IP address.");
        }
    }

    private static void addPacket() {

        if (packets.size() >= MAX_PACKETS) {
            System.out.println("Storage limit reached. Cannot add more packets.");
            return;
        }

        System.out.print("Enter source IP address: ");
        String sourceIP = scanner.nextLine().trim();

        System.out.print("Enter destination IP address: ");
        String destinationIP = scanner.nextLine().trim();

        int sourcePort = readInt("Enter source port: ");

        int destinationPort = readInt("Enter destination port: ");

        System.out.print("Enter protocol (TCP/UDP/Other): ");
        String protocol = scanner.nextLine().trim();

        int packetSize = readInt("Enter packet size in bytes: ");

        if (sourceIP.isEmpty() || destinationIP.isEmpty()
                || protocol.isEmpty()
                || sourcePort < 0 || sourcePort > 65535
                || destinationPort < 0 || destinationPort > 65535
                || packetSize < 0) {

            System.out.println("Invalid packet details. Packet was not added.");
            return;
        }

        int newId = packets.size() + 1;

        Packet newPacket = new Packet(newId, sourceIP, destinationIP,
                sourcePort, destinationPort, protocol, packetSize);

        packets.add(newPacket);

        System.out.println("Packet added successfully. Packet ID: " + newId);
    }

    private static int readInt(String message) {

        while (true) {

            System.out.print(message);

            String input = scanner.nextLine().trim();

            try {
                return Integer.parseInt(input);

            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a whole number.");
            }
        }
    }
}
