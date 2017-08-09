# nettop

Utility to show network traffic (both TCP and UDP v4 and v6) split by process and remote host. You can find more info (albeit slightly outdated) [here](http://nettop.youlink.org/).

![nettop in action](http://i.imgur.com/m3xnAK8.png)

## Building

Download the repository and invoke `make` (`make release` for optimized build - *reccomended* when you want to use it properly and not degbugging/experimenting with it).
Please note you need to have some dependencies satisfied (see following).

### libpcap

nettop relies on *libpacap* to intercept all packets and deliver a copy to the application. On Ubuntu and Debian derivatives you should install the *-dev* version (i.e. `sudo apt install libpcap-dev`).

### ncurses

nettop relies on *ncurses* to facilitate the UI drawing on console; on Ubuntu-like systems please install ´libncurses5-dev´ or more recent to allow compiling.

## Running

### All commands

```
./nettop --help
Usage: ./nettop [options]
Executes nettop 0.3

-r, --refresh s			sets the refresh rate in 's' seconds (default 3)
-c, --capture (a|s|r)		Capture mode for 'a'll, 's'end and 'r'ecv only (default 'a')
-o, --order (a|d)		Ordering of results, 'a'scending, 'd'escending (default 'd')
    --filter-zero		Set to filter all zero results (default not set)
    --tcp-udp-split		Displays split of TCP and UDP traffic in % (default not set)
-a, --async-log-file (file)	Sets an output file where to store the packets attribued to the 'kernel' (default not set)
-l, --limit-hosts-rows		Limits maximum number of hosts rows per pid (default no limit)
    --help			prints this help and exit
```

### Sample usage

```
sudo ./nettop --tcp-udp-split --limit-hosts-rows 20
```
This will start nettop and split between TCP and UDP usage, limiting how many hosts to display by the topmost 20.

### *sudo* requirements

Please note nettop needs to have *root* privileges to intercept all packets incoming and outgoing from current computer. Without *root* access it's unlikely to run.

## F.A.Q.

### Why did you build this?

I wanted to have a simple utility to monitor the network usage of all my processes, especially trying to understand where my data was coming from and going to.
I couldn't find anything which would just do this out of the box, so I wrote a utility.

### Is it safe to run as *root*?

I would think so - anyhow, look at the sources. If you don't trust what I'm doing, download the repo, inspect the code, compile, play around and let me know!

### what are the *5* numbers between brackets on top left?

They do represent the following:
- Total packets intercepted by libpcap (not only TCP and UDP, but potentially other IP types and non IP - rare these days)
- Total packets which were not processed by nettop (i.e. all the non TCP nor UDP packets)
- Undetermined packets - i.e. packets sent *from* **and** *to* the local computer (i.e. not touching the network *card*s), or also when packets have got both remote sources and destinations (i.e. applications spoofing IP address?)
- Total unmapped received packets: nettop could not attribute these packets to any current *PID*, hence it will assing them to *PID* 0. This might be due to the fact that for current interval we took a *snapshot* of running processes after parsing the packets, hence we could not link the *PID*s - or also, when you use APIs such as *gethostbyname*, the kernel will resolve and use the network for you, hence PID 0.
- Total unmapped sent packets; as above but for sent packets

## Credits

Thanks to Linux for being open source and to:
- [libpcap](https://sourceforge.net/projects/libpcap/) For providing this awesome tool to intercept packets host wide
- [ncurses](https://en.wikipedia.org/wiki/Ncurses) Without whom I wouldn't be able to draw a single element on the screen without *pain and agony*!
