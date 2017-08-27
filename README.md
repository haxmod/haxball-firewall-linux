# HaxBall Firewall for Linux
Unfortunately, some people think it is funny to crash HaxBall rooms by using modified clients to flood game hosts.
These crashes are either induced by joining a room multiple times or by flooding the host with an amount of packets that is sufficient to overstress Flash.
Since these issues cannot be fixed at the Flash layer, this firewall aims to be an external helper to prevent these attacks from impacting the game performance.

## Installation
The firewall depends on the `libnetfilter-queue-dev` package. On Ubuntu or Debian, this package can be installed using `apt-get`.
After having installed the dependencies, clone the repository using `git clone https://github.com/haxmod/haxball-firewall-linux`.
Then `cd haxball-firewall-linux` and compile the program using `make`. You may need to install the `git` and `build-essential` packages in case these steps fail.

## Running the firewall
Run the script `filter.sh` as `root` before starting the actual firewall. It will create a new `iptables` rule delegating the decision of dropping UDP packets to the firewall program using NFQUEUE. The filter script should only be executed once per computer start. After restarting the computer, the script has to be run again because `iptables` rules are not persistent.

Finally, simply run the firewall as root using `./bin/firewall`. It will prevent multiport UDP denial of service attacks as well as packet flood attacks. If you would like to run the program in the background, you can make use of `nohup`.

## Support for blocking IP ranges from data centers
Use the `--block-data-centers` flag in order to block IP address ranges from data centers. This will ban most shady users that use proxies and VPN servers for playing HaxBall. They will not be able to connect to your room.
