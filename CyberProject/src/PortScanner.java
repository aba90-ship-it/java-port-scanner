import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;


/**
 * PortScanner
 * -----------
 * A simple TCP port scanner that checks a target host across a range of
 * ports, reports which are open, and flags commonly risky services found
 * open (e.g. Telnet, FTP, RDP) as a basic ethical-hacking style
 * vulnerability report.
 *
 * Usage:
 *   java PortScanner <host> <startPort> <endPort>
 *   Example: java PortScanner scanme.nmap.org 1 1024
 *
 * NOTE ON ETHICS/LEGALITY:
 * Only scan hosts you own or are explicitly authorized to test.
 * scanme.nmap.org is a host the Nmap project provides specifically
 * for people to practice scanning against legally.
 */
public class PortScanner {

    // Known commonly-risky ports mapped to the service and why it matters
    private static final Map<Integer, String> RISKY_PORTS = new HashMap<>();
    static {
        RISKY_PORTS.put(21, "FTP - often unencrypted credentials");
        RISKY_PORTS.put(23, "Telnet - unencrypted remote access, deprecated");
        RISKY_PORTS.put(25, "SMTP - can be abused for spam relay if misconfigured");
        RISKY_PORTS.put(135, "MSRPC - historically targeted by worms");
        RISKY_PORTS.put(139, "NetBIOS - legacy Windows file sharing, often unnecessary");
        RISKY_PORTS.put(445, "SMB - target of major ransomware/exploits (e.g. EternalBlue)");
        RISKY_PORTS.put(3389, "RDP - frequent brute-force target if exposed to internet");
    }

    private final String host;
    private final int startPort;
    private final int endPort;
    private final int timeoutMs;
    private final List<Integer> openPorts = Collections.synchronizedList(new ArrayList<>());

    public PortScanner(String host, int startPort, int endPort, int timeoutMs) {
        this.host = host;
        this.startPort = startPort;
        this.endPort = endPort;
        this.timeoutMs = timeoutMs;
    }

    /** Scans a single port; returns true if open. */
    private boolean isPortOpen(InetAddress address, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(address, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Runs the scan across the configured port range using a thread pool. */
    public void scan() throws Exception {
        InetAddress address = InetAddress.getByName(host);
        System.out.println("Scanning " + host + " (" + address.getHostAddress() + ") "
                + "ports " + startPort + "-" + endPort + "...\n");

        ExecutorService pool = Executors.newFixedThreadPool(100);
        List<Future<?>> futures = new ArrayList<>();

        for (int port = startPort; port <= endPort; port++) {
            final int p = port;
            futures.add(pool.submit(() -> {
                if (isPortOpen(address, p)) {
                    openPorts.add(p);
                }
            }));
        }

        for (Future<?> f : futures) {
            f.get(); // wait for all scans to finish
        }
        pool.shutdown();

        Collections.sort(openPorts);
        printReport();
    }

    /** Prints a summary report of open ports and flags risky ones. */
    private void printReport() {
        System.out.println("=== Scan Results ===");
        if (openPorts.isEmpty()) {
            System.out.println("No open ports found in range.");
            return;
        }

        System.out.println("Open ports found: " + openPorts.size());
        for (int port : openPorts) {
            String note = RISKY_PORTS.getOrDefault(port, "No known common risk flagged");
            System.out.printf("  Port %-6d -> %s%n", port, note);
        }

        System.out.println("\n=== Risk Summary ===");
        long riskyCount = openPorts.stream().filter(RISKY_PORTS::containsKey).count();
        System.out.println(riskyCount + " of " + openPorts.size()
                + " open ports match commonly-risky services.");

        if (riskyCount > 0) {
            System.out.println("\nRecommendation: review whether these services need to be");
            System.out.println("publicly accessible, and ensure they are patched and firewalled");
            System.out.println("appropriately if they must remain open.");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: java PortScanner <host> <startPort> <endPort>");
            System.out.println("Example: java PortScanner scanme.nmap.org 1 1024");
            return;
        }

        String host = args[0];
        int start = Integer.parseInt(args[1]);
        int end = Integer.parseInt(args[2]);

        PortScanner scanner = new PortScanner(host, start, end, 300);
        scanner.scan();
    }
}
