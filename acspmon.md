## Background
ACSP channel/power selection procedure is distributed and cooperated among many APs, and it's a complex process. There is no straight-forward way to check the detailed procedure of the ACSP algorithm convergence process and the final selection results. So it will be very helpful to evaluate, improve and verify the ACSP algorithm, if we could monitor the ACSP procedure of all involved APs in real-time, and especially graphically.
Currently HiveOS provide certain CLIs and debug logs to retrieve ACSP info, we could reuse these info and display or transform them into graphics in real-time. I'm planning to develop a GUI tool to achieve it.

## Design & Implementation
The functionality of the tool is broken up into the following sub-functionalities:
#### (1) Communication Interface between APs and the tool
Communication will be based on SSH, so that access speed is guaranteed(comparing to serial console). By using Python's Paramiko lib, CLIs could be remotely run on APs and results could be got.

To make the configuration as simple as possible, all APs to be monitored should be connected in a same subnet. By giving the subnet IP to the tool, it could automatically monitor all running APs. To find which AP could be SSHed to quickly, the tool could use Scapy to send TCP probe packet to port 22 of all IPs in the subnet, if an IP responses, then the tool knows it's a running AP and tries to ssh to it.

#### (2) Collect all AP's ACSP information 
Python is object-oriented language, to abstract AP's ACSP info and GUI info, it's natural to represent them as object

Class AP inherits from its parent class 'SSHNode', class AP is composed by a list of Radio objects 'radios', the Radio class inherits from class 'ACSP' and 'GUICircle', 'ACSP' again is composed by a list of ACSPNbr objects 'nbrs'.
To collect a ACSPNbr object's info, the following CLIs are used:

> show acsp neighbo

> show acsp _nbr' are used.

To collect a radio's ACSP info, the following CLIs are used:

> show acsp

To collect other info of a Radio object, the following CLIs are used:

> show interface | in <wifix>

> show interface <wifix>

To collect other info of an AP object, the following CLIs are used:

> show interface | in mgt0

> show version

Each AP object repeatedly updates its radios' ACSP info in background. Another thread that calculates GUI coordinates will use these info. For easy back reference, a Radio object has an 'ap' attribute to find its belonging AP, and an ACSPNbr object has a 'radio' attribute to find its corresponding neighbor radio.

#### (3) Display AP's channel and RF range graphically in real-time
From above section, we know that the 'Radio' class is subclass of 'GUICircle', class 'GUICircle' is generic class to draw a circle and possibly text block on the canvas of Tk, using Python's builtin Tkinter module. The circle's attribute like center point coordinates, radius length and fill color could be specified. To draw the specified circle, call its draw() function. After 'Radio' inherits from 'GUICircle', it overloads the draw() member function, so that radio's RF coverage range and channel are converted to the circle's radius and fill color, etc. The radio's name/mac/mode/phymode/ACSP/pwr info are also printed as text blocks. For example, the following figure shows an AP with two radios: one is 2.4G working on channel 11, and the other is 5G working on channel 157. Pay attention to the coverage range of these 2 different bands.

Each radio repeatedly update its mode/phymode/ACSP/pwr info in background, so that whenever something changes, it will reflect to the GUI displaying in several seconds.

#### (4) Display all involved APs in relatively correct location automatically
The tool could help to calculate each AP's relative coordinates automatically(command line option -c 'auto', or shortcut key 'ca').
RF transmission has loss along with distance, it meets the following formula in free space(no obstacles absorbing):
FSPL= 32.44 + 20log10(F) + 20log10(d)  
In which, FSPL is the free space path loss(unit is dB), F is the RF's frequency(unit is GHz), d is the transmission distance(unit is meters). If we know the path loss, and transmission frequency, we could get the transmission distance:
d = pow(10, (FSPL - 32.44 - 20*log10(F)) / 20)
This is the fundamental formula that we will use to estimation the distance between APs. Note that we only need to know the relative location among APs, we don't require the exact distance, so using the FSPL formula could work even if we don't consider obstacles absorbing.
 
Basically, APs could be relatively located based to the "3-point locating' method:
An AP could be located by other 3 neighbor APs. If consider the radio coverage as circle with center c and radius r, 2 of the 3 APs have 2 cross points and could locate the AP to 2 locations. The third neighbor AP finally choose the final appropriate location.

Suppose we need to know AP D's location, it has 3 neighbors AP A, B, and C that are already located(have location coordinates), whose wifi0 txpowr is PTa, PTb, and PTc correspondingly. After querying AP D's ACSP neighbor tables, we also know the wifi0 RSSI of A, B and C that detected by D are PRa, PRb, and PRc correspondingly. Now we could calculate:

1. The path loss from AP A to D is: PTa - TRa, according to FSPL formula, we could know the distance from A to D is r1 (D could be any point along the circle that with A as center point and r1 as radius)
2. The path loss from AP B to D is: PTb - TRa, according to FSPL formula, we could know the distance from B to D is r2 (D could be any point along the circle that with B as center point and r2 as radius)
3. To satisfy both 1, and 2 above, D could only be one of the two cross points of circle A and B: L1 and L2
4. The path loss from AP C to D is: PTc - TRa, according to FSPL formula, we could know the distance from C to D is r3
5. To finally determine which of L1 and L2 is D's location, we compare the distance of L1 to C(d1) and L2 to C(d2), the one that is close to r3 decides the final location of D. e.g. abs(d1-r3) < abs(d2-r3), then D is at point L1

To calculate each AP's coordinates as accurate as possible, we also need to use the following rules:

1. It's better to calculate the center of the AP cluster(high nbr score) first, and other APs are gradually calculated in the'from-center-to-outside' direction. Thus the final figure involving all APs is displayed at the center of the GUI canvas
2. To calculate an AP, its other 3 AP neighbors used to locate it must be as close as possible to this AP, so that the FSPL algorithm is more reliable(longer distance transmission is supposed to less accurate since there are more obstacles which absorbs the RF)
3. In case there are so many APs in the cluster and some AP's ACSP neighbor table is full, the 3 reference AP neighbors used to locate it might not be available, this AP could be bypassed temporarily in the current iteration, and could be calculated later when other APs complete calculation, which are in that AP's neighbor table
4. For APs with 2 radios, wifi0 has higher priority to be used for calculation, if wifi0 is not in the neighbor table, wifi1 could be tried.

Note that the first 3 APs are handled specially:

1. The 1st AP is put at the center of the GUI canvas
2. The 2nd AP is always put to the direct right of the 1st AP, with a distance that is calculated by the FSPL formula
3. Use the first 2 APs are reference neighbors A and B, the 3rd AP could only be at location L1 or L2, we force it to be L1. 
4. The exact direction of the GUI canvas figure might not match the real layout, this is not a problem, the whole canvus could be rotate/mirror to match it.

#### (5) Display all involved APs in relatively correct location manually
The tool also allows user to set AP's relative coordinates manually(command line option -c 'manual', or shortcut key 'cm'), by drag-and-drop APs on the GUI. Sometimes certain radios are not detected or displayed by other neighbors in their acsp neighbor table, so automatical coordinates calculation is not possible. In this case, these APs are put to the up-left corner of the GUI canvas, user could drag and drop them to the correct relative location.

(6) User control interface
To control the tool's behavior, especially displaying appearance, some options are provided. First user can set these options when starting the tool through command line arguments:
```
Usage: acspmon.py [options]
 
 
Aerohive AP ACSP monitor, type "h" in GUI for shortcut keys help
 
Options:
  -h, --help            show this help message and exit
  -a RADIO_DISPLAYED, --radio_displayed=RADIO_DISPLAYED
                        Set which radio of an AP is shown on the GUI, "0":
                        wifi0, "1": wifi1, "a": all
  -c COORD_METHOD, --coord_method=COORD_METHOD
                        Set the method by which APs relative location
                        coordinates are calculated, supported methods are
                        "auto", "random", and "manual"
  -d, --debug           Enable verbose debug log
  -e EXT_DELAY, --ext_delay=EXT_DELAY
                        Set the extra SSH command transaction delay time
  -f, --freeze_gui      Freeze GUI updating
  -m NFLOOR_MARGIN, --nfloor_margin=NFLOOR_MARGIN
                        Set the safe margin to noise floor, within which
                        signal is considered unusable
  -n SUBNET, --subnet=SUBNET
                        Set the subnet(x.y.z.n/mask, or x.y.z.0 for 24 mask
                        bits, or x.y.z.n:m for m consequential ips starting
                        from n) in which APs are monitored
  -p METERS_PER_DOT, --meters_per_dot=METERS_PER_DOT
                        Set how many radio RF coverage meters(radius) per dot
                        when drawn on canvas
  -r, --acsp_run_ts     Show the timestamp that radio ACSP state becomes RUN
  -s, --coord_nbrscore_order
                        Calculate APs location coordinates in the order of
                        their nbr scores(from large to small), by default,
                        occurrence order is used
  -t, --color-transparent
                        Don not fill radio circle color, make it transparent
  -u, --userpass        Set username and password(separated by ":") for all
                        APs to be monitored
  -w SMOOTH_WINDOW, --smooth_window=SMOOTH_WINDOW
                        Set the RF signal smooth window size(num of samples
                        which average is done on)
```

Second, to change these options dynamically when the GUI is running, the same named shortcut keys are provided. Press 'h' to show the shortcut key help in a popup window. 'd', 't' and 'f' keys toggles the corresponding switch; 'c' selects one of the 3 coordinates computing methods, it requires user to type one of 'a', 'm', or 'r' immediately after 'c' for 'auto', 'manual', and 'random' method; 'e', 'p', 'm', and 'w' requires user to type numbers(the period char '.' could be included) immediately after these shortcut keys, so that related value is recorded, after that, a 'Enter' key is required to close the number inputting and make the change take effect. Instead of input value directly for 'e', 'p', 'm', 'w', user also can use the -/+ key to decrease/increase these parameters.
In addition to passively monitor each APs, the tool also provides user the capability to control a specific AP or all APs by sending CLIs. Right clicking the mouse will bring up the menu, in which user could send existing saved CLIs or input new CLIs, if user choose input new CLIs, multiple CLIs could be concatenated by the ';' character. Pay attention that if the user right click the mouse on a specific AP's circle, the sent CLIs are only to that AP; if user right click the mouse on any white space area, the sent CLIs are to all APs. User could also select a list of APs to send CLIs to(the order to send CLIs is the same order as the APs that selected by user), by press shortcut key 'x' and select needed APs by mouse left-click on those APs, and then right-click on any white space area to bring up the menu. Press 'x' again cancel the selection.

#### (7) ACSP channel/power selection result automatically evaluation
TODO

## Code Architecture
To minimize latency, the code is arranged into several individual threads:
* main thread: started by user through command line, global initialization(cmdline options, key/mouse callbacks), starts the other threads, display GUI
* new AP detection thread: repeatedly detect new online APs in the subnet
* AP detection/updating thread: monitor when an exiting AP is online/offline, repeatedly update the AP's radio/ACSP/nbr statistics
* AP coordinates calculation thread: calculate each AP's location according to the '3-point-locating' algorithm

## Usage
The acspmon tool could be downloaded in the first item of the 'Reference' section.
#### Pre-required Python module
The tool requires several third-party python modules: paramiko, scapy, user must install them before using the tool. On Linux, normally they could be installed through:
$ sudo pip install paramiko scapy
#### Typical usage
To monitor all APs in a subnet a.b.c.0, start the tool as:
$ sudo ./acspmon.py -n a.b.c.0
Other parameters could be dynamically adjusted when the GUI window is shown. Type 'h' first to check the shortcut key help.

## References
* [Use Scapy to sniff & send 802.11 packets](http://hexbot.cn/article/20)
* [802.11射频和天线基础知识](http://hexbot.cn/article/21)
* [使用Python计算两圆交点坐标](http://hexbot.cn/article/24)
