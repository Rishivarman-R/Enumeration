# Enumeration
Enumeration Techniques

# Explore Google hacking and enumeration 

# AIM:

To use Google for gathering information and perform enumeration of targets

## STEPS:

### Step 1:

Install kali linux either in partition or virtual box or in live mode

### Step 2:

Investigate on the various Google hacking keywords and enumeration tools as follows:


### Step 3:
Open terminal and try execute some kali linux commands

## Pen Test Tools Categories:  

Following Categories of pen test tools are identified:
Information Gathering.

Google Hacking:

Google hacking, also known as Google dorking, is a technique that involves using advanced operators to perform targeted searches on Google. These operators can be used to search for specific types of information, such as sensitive data that may have been inadvertently exposed on the web. Here are some advanced operators that can be used for Google hacking:

site: This operator allows you to search for pages that are within a specific website or domain. For example, "site:example.com" would search for pages that are on the example.com domain.
Following searches for all the sites that is in the domain crunchyroll.com

filetype: This operator allows you to search for files of a specific type. For example, "filetype:pdf" would search for all PDF files.
Following searches for pdf file in the domain yahoo.com
![Screenshot 2025-03-14 145657](https://github.com/user-attachments/assets/e4693ed1-0fb9-4d3f-9546-a08e056500ee)



intext: This operator allows you to search for pages that contain specific text within the body of the page. For example, "intext:password" would search for pages that contain the word "password" within the body of the page.
![Screenshot 2025-03-14 174154](https://github.com/user-attachments/assets/dac64c76-93ef-40a8-b449-96d373e991a5)


inurl: This operator allows you to search for pages that contain specific text within the URL. For example, "inurl:admin" would search for pages that contain the word "admin" within the URL.
![Screenshot 2025-03-14 174342](https://github.com/user-attachments/assets/09eaacf5-6976-4c24-9d4d-3e6b9471c0a2)

intitle: This operator allows you to search for pages that contain specific text within the title tag. For example, "intitle:index of" would search for pages that contain "index of" within the title tag.
![Screenshot 2025-03-14 174536](https://github.com/user-attachments/assets/bf6fcb33-17b2-45dc-9008-a964175d1eae)

link: This operator allows you to search for pages that link to a specific URL. For example, "link:example.com" would search for pages that link to the example.com domain.
![Screenshot 2025-03-14 174802](https://github.com/user-attachments/assets/ad0c25f8-fab4-40a9-ab83-2c3d75913b15)

cache: This operator allows you to view the cached version of a page. For example, "cache:example.com" would show the cached version of the example.com website.
![Screenshot 2025-03-14 175028](https://github.com/user-attachments/assets/310e2095-7f53-471f-81f2-384de867fe6a)

 
# DNS Enumeration
![Screenshot 2025-03-14 175139](https://github.com/user-attachments/assets/3777f440-0893-44cf-bf38-edc94f38eb44)


## DNS Recon
provides the ability to perform:
Check all NS records for zone transfers
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF , TXT)
Perform common SRV Record Enumeration
Top level domain expansion
## OUTPUT:







## dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.


## smtp-user-enum
Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.


In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

select any username in the first column of the above file and check the same


#Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
  
 ## Output
  ![Screenshot 2025-03-14 134306](https://github.com/user-attachments/assets/63ed19ba-cb37-4b8d-b57c-0f2e0d256b50)
# dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.

  
![Screenshot 2025-03-14 090905](https://github.com/user-attachments/assets/46cec39d-d4d1-4cc3-92d9-859219abf24b)

## nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.
![Screenshot 2025-03-14 091223](https://github.com/user-attachments/assets/a0ef7ee3-7332-4f36-9bf2-3a0c1b1d190b)

![Screenshot 2025-03-14 091100](https://github.com/user-attachments/assets/dabfff3f-11c7-4e61-b5bc-5c8e4ddc1939)

## OUTPUT:
# Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
![Screenshot 2025-03-16 150434](https://github.com/user-attachments/assets/00a42e26-818c-4e70-a23c-cac21fbb6f34)
# nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.
![Screenshot 2025-03-16 152625](https://github.com/user-attachments/assets/b05d09fe-302c-4174-825d-f33a3a4660cf)


## RESULT:
The Google hacking keywords and enumeration tools were identified and executed successfully

