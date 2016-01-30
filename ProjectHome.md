Updated June 7, 2013
Added test data. Fixed a few bugs.
Now just copy and paste files to test on your server.

The goal of this project is to provide a PHP script that can analyze pcap (packet capture) files and return useful information.

Currently supports HTTP GET, POST, and response parsing. JPEG and GIF HTTP responses are displayed inline. POST data is separated into one key=value pair per line. POST data is shown in red, GET data in green, and HTTP response data in blue.

Web Use:
  * Copy index.php and the test\_data folder (found in Source->Browse->/svn/trunk) to a folder (like /pcapa) in your web server's path.
  * Change $pcapdir in index.php to your .pcap file folder. Optionally skop this step to use test data.
  * The script will create output folders and files in the directory it resides. !Important: Make sure it has write permissions in that folder.
  * Goto (Example) yourserver/pcapa/index.php and select a pcap file from the list.
  * The script is a little slow. On an iPad (first generation) with lighttpd it takes about 20 - 30 seconds per megabyte.
  * I don't recommend using large pcap files until this is improved.

Command Line Use:
  * In progress...

Tested on:
  * iPad with lighttpd
  * Ubuntu with Apache

Plans:
  * Add incremental parsing of pcap files. In other words; when a pcap file is done being parsed, a record is made noting the position of the last record's ending position to allow a quick analyzer restart (from that position) when more packets are added. Any decoded stream results are saved to an output htm file.
  * Add more data filters.
  * Improve interface. AJAX would be nice.
  * Command line version.


Known Bugs:
  * No security is built into this script. Do not make this script available on a web facing server.

