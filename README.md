> [!WARNING]
> ***This tool is ONLY for demonstrate how network systems and services may be stressed under load and to help with understanding network performance. Unauthorized or malicious use of this tool can lead to legal consequences, including criminal charges.***

## Avaliable Attacks (will add more soon)

**1. [TCP SYN](https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/) Flood**

**2. [ICMP](https://www.cloudflare.com/learning/ddos/ping-icmp-flood-ddos-attack/) Flood (Ping of Death)**

**3. [UDP](https://www.cloudflare.com/learning/ddos/udp-flood-ddos-attack/) Flood**

**4. [HTTP](https://www.cloudflare.com/learning/ddos/http-flood-ddos-attack/) Flood**

## How it works:

* Let's take udp flood as an example.

* A UDP flood attack can be initiated by sending a large number of UDP packets to random ports on a remote host. As a result, the distant host will:

    * Check for the application listening at that port;
    * See that no application listens at that port;
    * Reply with an ICMP Destination Unreachable packet.

* Thus, for a large number of UDP packets, the victimized system will be forced into sending many ICMP packets, eventually leading it to be unreachable by other clients. Net Strike can also spoof the IP address of the UDP packets, ensuring that the excessive ICMP return packets do not reach you, and anonymizing your network location.

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

4. Run the script:

    ```bash
    python NetStrike.py
    ```
> [!IMPORTANT]
> **You have to run the tool with admin privileges!**

![Screenshot-1](https://github.com/isPique/Net-Strike/blob/main/Screenshot-1.png)
![Screenshot-2](https://github.com/isPique/Net-Strike/blob/main/Screenshot-2.png)
