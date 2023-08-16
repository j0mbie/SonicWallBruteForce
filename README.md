# SonicWallBruteForce (j0mbie's version)

Script to brute force credentials against a SonicWall HTTPS management page.

Forked from Hoodoer's work:  
https://github.com/hoodoer/sonicWallBruteForce

Based on a Gist by Vasuman to do autologins:  
https://gist.github.com/vasuman/fa750a6fe57fc8a73aff


SonicWall can be pretty IP blocking happy. Consider using the HTTP proxy feature to pass this through Burp, and use IPRotate extension to snag a new source IP for every request. See: https://portswigger.net/bappstore/2eb2b1cb1cf34cc79cda36f0f9019874

### Prerequisites:  

**Python 3**  
Windows installer: https://www.python.org/downloads/release/python-3114/

**"Requests" Python package**  
In Windows, from your Python directory, run:  
`Scripts\pip.exe install requests`

### Options:
```
-host          URL of the target. Example: https://somesonicwall.xyz (Required.)
-userlist      User list, in a text file. One entry per line.
-password      Single password to try. Useful for testing the script.
-passwordlist  Password list, in a text file. One entry per line.
-proxy         HTTP proxy.
-delay         How many seconds to wait before moving to the next password in the list.
-debug         Print a lot of extra stuff.
```
