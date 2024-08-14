> [!WARNING]
> ***This tool is ONLY for demonstrate how network systems and services may be stressed under load and to help with understanding network performance. Unauthorized or malicious use of this tool can lead to legal consequences, including criminal charges.***

# Prerequisites

| Requirement | Version |
|-------------|---------|
| Python      | 3.8 or higher |
| Windows / Linux | Any |
| [Scapy](https://scapy.net/)  | Latest |
| [AIOHTTP](https://docs.aiohttp.org/) | Latest |
| [Fake User Agent](https://fake-useragent.readthedocs.io/) | Latest |

## Avaliable Attacks (will add more soon)

**[TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) SYN Flood:** A TCP SYN flood attack exploits the TCP handshake process. It sends a barrage of SYN requests to the target, overwhelming its ability to respond and establish legitimate connections.

**[ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) Flood (Ping of Death):** An ICMP flood attack sends a high volume of ICMP Echo Request (ping) packets to the target, aiming to overwhelm its network bandwidth and processing power.

**[UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol) Flood:** A UDP flood attack involves sending a large number of UDP packets to random ports on the target system, causing it to become overwhelmed as it processes the packets and replies with ICMP Destination Unreachable messages.

**[HTTP](https://en.wikipedia.org/wiki/HTTP) Flood:** An HTTP flood attack aims to overload a server with HTTP requests, exhausting its resources and potentially leading to denial of service.

## How it works:

* Let's take UDP Flood as an example.

* A UDP flood attack can be initiated by sending a large number of **UDP packets** to random ports on a remote host. As a result, the distant host will:

    * Check for the application listening at that port;
    * See that no application listens at that port;
    * Reply with an ICMP Destination Unreachable packet.

* Thus, for a large number of UDP packets, the victimized system will be forced into sending many ICMP packets, eventually leading it to be unreachable by other clients. Net Strike can also spoof the IP address of the UDP packets, ensuring that the excessive ICMP return packets do not reach you, and anonymizing your network location.

* **However**, unlike other types of attacks, HTTP Flood works in a somewhat different manner.

* An HTTP flood attack aims to overload a server with **HTTP requests**. This type of attack can take various forms, such as GET or POST requests. As a result, the target server will:

   * Receive an overwhelming number of requests;
   * Attempt to process each request as a legitimate user;
   * Exhaust its resources (CPU, memory, bandwidth), potentially leading to slow responses or complete unavailability.
 
* For a large number of HTTP requests, the server may become unresponsive or crash. Net Strike can generate high volumes of HTTP requests, emulating the behavior of multiple clients and stressing the target server.

> [!NOTE]
> Including headers in the HTTP flood requests makes the requests appear more legitimate, as if they are coming from a real browser. This helps to avoid simple filtering mechanisms that may block requests without common headers. You can add more headers if you want.

# INSTALLATION

1. Clone the repository:

    ```bash
    git clone https://github.com/isPique/Net-Strike.git
    ```

2. Navigate to the project directory:

    ```bash
    cd Net-Strike
    ```

3. Install required libraries:

   ```bash
   pip install -r requirements.txt
   ```

# USAGE
```bash
sudo python3 NetStrike.py
```
> [!IMPORTANT]
> **You have to run the tool with admin privileges!**

![Screenshot-1](https://github.com/isPique/Net-Strike/blob/main/Images/Screenshot-1.png)
![Screenshot-2](https://github.com/isPique/Net-Strike/blob/main/Images/Screenshot-2.png)

* **1 Thread = 1 connection**
* The higher the number of threads you maintain, the stronger the attack will be.

* For example, ICMP Flood:

   ![Captured](https://github.com/isPique/Net-Strike/blob/main/Images/Captured.png)
