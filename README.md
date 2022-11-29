# DigestCub-OpenCL

GPU-accelerated bruteforce tool for MD5 digests and only MD5 digests. Made primarily as an experiment and learning experience, so will likely fall several miles short of Hashcat's capabilities.

```
usage: md5.py [-h] [-s CHUNK_SIZE] digest wordlist

  _____  _                 _    _____      _
 |  __ \(_)               | |  / ____|    | |
 | |  | |_  __ _  ___  ___| |_| |    _   _| |__
 | |  | | |/ _` |/ _ \/ __| __| |   | | | | '_ \
 | |__| | | (_| |  __/\__ \ |_| |___| |_| | |_) |
 |_____/|_|\__, |\___||___/\__|\_____\__,_|_.__/
            __/ |
           |___/

GPU-bruteforce an MD5 password using a wordlist.


positional arguments:
  digest                hash to bruteforce (provided as a 32-character hexadecimal string)
  wordlist              wordlist file to use

options:
  -h, --help            show this help message and exit
  -s CHUNK_SIZE, --chunk_size CHUNK_SIZE
                        number of words to test at a time (defaults to 65_536)

Example usage:
python .\src\md5.py 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt
Match found - password

python .\src\md5.py 9a69ad706500bcd5c649bc5a51ea30a8 rockyou.txt
Match found - buddykey
```
