#### checkDNSZone

A small program to continously do DNS requests for zones from an input file and 
compare the returned data to a SHA1 checksum that has been calculcated before. Easy to install in a 
monitoring system like Icinga or Nagios. 

##### input file

checkDNSZone takes a file with colon-seperated data values. A new line represents 
a new hosts. The format look like this:

*Zone:Checksum:Subdomains**

Zone stands for the zone name, for example golem.de

Checksum is a SHA1 checksum, that is generated on the first run or by setting 
the -u flag.

Subdomains is a string with comma-seperated names of possible subdomains to also include in the checksum.

See the included example file as reference.

#### Limitations

##### Loadbalcing

checkDNSZone does not consider DNS based loadbalancing, currently it lacks an 
exception option for hostnames. It will only work on ***static zones***.

##### SOA

checkDNSzone does not consider the SOA-origin record currently.
   
##### Example calls

Shot and print out the zone and the checksum
        
    checkDNSZone -v
 
Shot with custom nameserver (nameserver will be expanded to :53 and UDP protocol)
        
    checkDNSZone -nameserver 8.8.8.8
   
Run on the input hostfile and update the checkSum values, print out zones with a checksum error.

    checkDNSZone -u 
    
Run on the input hostfile and print out all zones, either with an error or not.

    checkDNSZone -v
    
