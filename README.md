java cLab 3 : Network security using SNORT 
 
Introduction 
This Lab is a specialized virtual environment designed for the purpose of cybersecurity 
training and education. In today’s digital landscape, the importance of understanding and 
defending against cyber threats is paramount. This lab provides a practical, hands-on 
approach to learning various aspects of cybersecurity, including but not limited to 
penetration testing, network security, intrusion detection, and response strategies. 
 
Purpose 
The primary purpose of this Lab is to facilitate a comprehensive understanding and 
application of cybersecurity concepts and practices. 
 This lab environment allows users to: 
1. Provide a hands-on approach to learning offensive and defensive cybersecurity 
techniques using tools like Metasploitable, Kali Linux, and Ubuntu. 
2. Serve as an educational platform for aspiring cybersecurity professionals. 
3. Create a safe, controlled environment for experimentation. 
4. Enhance technical skills in network security and ethical hacking. 
Scope 
The scope of the Lab encompasses: 
1. Virtualization and Network Setup: Utilizing VMware for the creation and management 
of virtual machines, each hosting different operating systems (Metasploitable, Kali Linux, 
and Ubuntu) and configured in a host-only network to ensure isolation and safety. 
2. Tool Implementation and Configuration: Including Snort for intrusion detection. 
3. Learning Objectives: Focusing on providing hands-on experience in identifying 
vulnerabilities, conducting penetration tests, monitoring network traffic, and 
implementing defensive strategies. 
5. Resource Constraints: Designed to be efficient and functional within the constraints of 
8GB RAM, ensuring accessibility for users with limited hardware resources. Lab Requirements 
Hardware Requirements 
RAM: 8 GB of RAM. 
Storage: 30GB+ 
Operating Systems 
1. Metasploitable: This will act as the victim machine. Metasploitable is intentionally 
vulnerable to provide a training environment for security testing. 
https://sourceforge.net/projects/metasploitable/files/latest/download 
2. Kali Linux: This will be used as the attacker machine. Kali Linux comes with numerous 
pre-installed penetration testing tools. 
https://www.kali.org/get-kali/ 
3. Ubuntu: This will serve as the defense machine, where you’ll monitor the network and 
implement security measures. 
https://ubuntu.com/download/desktop 
Software Requirements 
1. Virtualization Software: VMWare. 
2. NIDSNIPS: Snort https://www.snort.org/downloads#snort3-downloads 
Network 
In my environment I have this network: 
Kali — 192.168.152.128/24 
Metasploitable — 192.168.152.129/24 
Ubuntu — 192.168.152.130/24  
Network Illustration 
Note: My Kali did not receive its IP from virtual DHCP. If you have such problem too, 
then: 
> ip addr show eth0 
2: eth0:  mtu 1500 qdisc noop state DOWN group default qlen 
1000 
link/ether 00:0c:29:14:1d:0c brd ff:ff:ff:ff:ff:ff 
> sudo ip link set eth0 up 
> sudo dhclient eth0 
> ip addr show eth0 
2: eth0:  mtu 1500 qdisc fq_codel state UP group 
default qlen 1000 
link/ether 00:0c:29:14:1d:0c brd ff:ff:ff:ff:ff:ff 
inet 192.168.152.128/24 brd 192.168.152.255 scope global dynamic eth0 valid_lft 1659sec preferred_lft 1659sec 
inet6 fe80::20c:29ff:fe14:1d0c/64 scope link proto kernel_ll 
valid_lft forever preferred_lft foreverb 
Setting Up Virtual Machines 
Setting Up Attacker Machine — Kali 
1. Download VMWare version for Kali. https://www.kali.org/get-kali/ 
2. Unpack 
3. Open file with `.wmx` extension 
Setting Up Victim Machine — Metasploitable 
1. Download https://sourceforge.net/projects/metasploitable/files/latest/download 
2. Unzip 
3. Open file with `.wmx` extension 
Setting Up Monitoring and Detection Machine — Ubuntu 
1. Download iso https://ubuntu.com/download/desktop 
2. Create a new Virtual Machine on VMWare 
3.  
4.  
5. choose ubuntu’s iso  
6.  
7.  
8.  
9.  
10.  
(then click next again 2 times) 
11.  
(then again) 
12. Finish 
13. Power On. Installation will be opened. 
14. Choose keyboard. (US) 
15.  
16.  
17. 
 
18. Choose Location 
19.  
20. 
 
Snort 
Snort is an open-source network intrusion prevention system (NIPS) and network intrusion 
detection system (NIDS) that is used for detecting and preventing network intrusions. It analyzes network traffic to identify malicious activity, logs packets, and can perform realtime
 traffic analysis and packet logging. 
 
Setting Up Snort 
sudo apt-get install snort -y 
2. Write their interface (you can learn it simply by running `ip a`. 
 
3. Network 
 
4. sudo ip link set ens33 promisc on 
5. 
vim /etc/snort/snort.conf 
6. change any to your ip range (mine is 192.168.152.0/24 ) 
 
7. Check the rules and other configurations 
snort -T -i ens33 -c /etc/snort/snort.conf 
You can see that snort is using prewritten rules:  
You can disable them by commenting these lines out: 
 
All rules besides $RULE_PATH/local.rules 
 
Now Snort is setup. Next thing to do is to write rules and detect them. Writing the First rule 
You can write them manually into `/etc/snort/rules/local.rules`. Or, in this 
website http://snorpy.cyb3rs3c.net/. Or, ChatGPT. 
 
Some notations here: 
1. choose action type 
2. choose protocol 
3. source ip/port 
4. destination ip/port 
5. id (every snort rule should have different id) 
6. revision number. Normally after each update of the rule this number increases by 
one 
7. Message you want to leave there 
8. Resulting rule. Copy it. 
alert icmp any any -> any any ( msg:"Someone is pinging"; sid:10000; rev:1; ) 
alert icmp any any -> $HOME_NET any ( msg:"Someone is pinging"; sid:10001; rev:1; ) 
Write the rules into /etc/snort/rules/local.rules file:  
This command will show alerts in real time: 
snort -q -l /var/log/snort/ -i ens33 -A console -c /etc/snort/snort.conf 
Ping to somewhere and get the alert. You also can try to ping from Kali to 
Metasploitable. 
 
Example of its application in unauthorized ssh connections 
alert tcp any any -> $HOME_NET 22 (msg:代 写program、Python
代做程序编程语言"Possible SSH Brute Force Attack"; flags:S; 
threshold:type both, track by_src, count 5, 
seconds 60; sid:10002; rev:1;) 
Explanation of the rule components:  alert tcp any any -> $HOME_NET 22: This part specifies that the rule is looking for 
TCP traffic from any source IP and port, going to any IP within your defined 
`HOME_NET` on port 22 (the default SSH port). 
 msg:”Possible SSH Brute Force Attack”: The message that will be logged when this 
rule is triggered. 
 flags:S: This looks for packets with the SYN flag set, which are used to initiate TCP 
connections. 
 threshold:type both, track by_src, count 5, seconds 60: This is a threshold condition. 
It tracks by source IP, and the rule triggers if there are 5 connection attempts (SYN 
packets) within 60 seconds. 
 sid:10002; rev:1: Every Snort rule needs a unique SID (Snort ID), and a revision 
number. 
Moreover, add this rule too. This is for checking single TCP connection: 
alert tcp any any -> $HOME_NET any (msg:"TCP Connection Attempt Detected"; flags:S; 
sid:10003; rev:1;) 
Write it to the file and run the command. 
Then, run Metasploitable and Kali. 
Check the rule TCP Connection Attempt Detected: 
  
You can see that we tried to connect to Metasploitable from Kali. 
Now let’s check Possible SSH Brute Force Attack. 
 
 
Drop 
Let’s now write a drop rule for getting rid of unwanted FTP connection. 
drop tcp any any -> $HOME_NET 21 (msg:"Possible FTP Brute Force Attack"; flags:S; 
threshold:type both, track by_src, count 5, seconds 20; sid:10004; rev:1;) 
Run ftp brute force with hydra in Kali: hydra -l "root" -P /usr/share/wordlists/rockyou.txt ftp://192.168.152.129 
 
Extract IPs that get detected: 
snort -q -l /var/log/snort/ -i ens33 -A console -c /etc/snort/snort.conf | grep "Possible FTP 
Brute Force Attack" | awk '{print $13}' | awk -F ":" '{print $1}' >> drops.txt 
 
Example of Snort’s Application in Detecting XSS 
alert tcp any any -> [Metasploitable_IP] 80 (msg:"XSS is Detected"; 
flow:to_server,established; content:""; http_uri; sid:10005; rev:1;) 
Add the rule to /etc/snort/rules/local.rules. 
Open deliberately vulnerable web 
application: http://192.168.152.129/dvwa/vulnerabilities/xss_r/ in my case. Write there 
the payload: alert(1).  
Press Enter and get: 
 
You will get the alert: 
 
Bonus: Visualizing logs with web interface 
Write the alerts into log file. 
snort -q -l /var/log/snort/ -i ens33 -A console -c /etc/snort/snort.conf > 
/var/log/snort/alerts.txt 
Change directory to the place where logs are stored and open python server here. cd /var/log/snort 
python3 -m http.server 
Write this simple nodeJS application into app.js. 
// Import the Express module to create a web server 
const express = require('express'); 
// Import the Axios module for making HTTP requests 
const axios = require('axios'); 
// Create an instance of an Express application 
const app = express(); 
// Define the port number on which the server will listen 
const port = 3000; 
// URL of the API from which log data will be fetched. 
:/log.file 
const api = 'http://192.168.152.130:8000/alerts.txt' 
 
// Define a function to convert log entries into HTML format 
const getLogsHtml = (logs) => { 
 return logs.map(log => 
 // Create an HTML structure for each log entry 
 ` 
 ${log.timestamp} 
 
${log.alert} 
 ` 
 ).join(''); 
}; 
 // Define a route for the root ('/') URL 
app.get('/', async (req, res) => { 
 try { 
 // Fetch log data from the API using Axios 
 const response = await axios.get(api); 
 // Split the data by new line and create an array of log entries 
 const logEntries = response.data.split('\n'); 
 // Process each log entry and split it into timestamp and alert parts 
 const formattedLogs = logEntries.map(entry => { 
 const parts = entry.split(' '); 
 return { timestamp: parts[0], alert: parts.slice(1).join(' ') }; 
 }); 
 // Convert the log entries into HTML format 
 const logsHtml = getLogsHtml(formattedLogs); 
 // HTML template for the page 
 const htmlTemplate = 'Log 
Viewerbody { font-family: Arial, sans-serif; margin: 0; padding: 20px; 
background-color: #f4f4f4; } .log-entry { background-color: #fff; border: 1px solid #ddd; 
padding: 10px; margin-bottom: 10px; border-radius: 4px; } .timestamp { color: 
 }Log Entries'; 
 // Insert the log entries HTML into the template 
 const finalHtml = htmlTemplate.replace('', 
logsHtml); 
 // Send the final HTML as the response 
 res.send(finalHtml); 
 } catch (error) { 
 // Handle any errors by sending a 500 error response  res.status(500).send('Error fetching logs'); 
 } 
}); 
 
// Start the server and listen on the specified port 
app.listen(port, () => { 
 console.log(`Server running on http://localhost:${port}`); 
}); 
Install required packages and run the web app: 
npm i express axios 
node app.js 
This code demonstrates a comprehensive setup for logging, serving, and displaying log 
data using a combination of Snort, Python, and Node.js. First, it configures Snort to write 
alerts to a log file and then starts a Python HTTP server in the directory where these logs 
are stored. Next, it outlines a Node.js application using Express and Axios to fetch and 
display these logs in a web browser, with a focus on converting log entries into an HTML 
format for easy viewing. Finally, it provides commands to install the necessary Node.js 
packages and run the web application, completing the end-to-end process of log 
management and visualization. 
You will have simple real-time Dashboard to see alerts. You may customize it for getting it 
more styled and add additional functionality to see other logs and actions.  
Submission: You need to submit a pdf report that show the implementation of the lab in 
your computer with a set of screenshots. For your deliverables, you should submit a PDF 
file with screen shots of your scans. Be sure to include the descriptions and analysis of 
your results. Also, include the reports from your scan. Your report should be wellorganized
and clearly written. 
Include your full name and id. 

         
加QQ：99515681  WX：codinghelp  Email: 99515681@qq.com
