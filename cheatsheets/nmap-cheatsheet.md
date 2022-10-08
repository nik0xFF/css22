# NMAP Cheatsheet
## Example Syntaxes

`nmap -sP 192.162.0.0/24 > scan.txt` *-sP Ping and export to .txt*

*-sV Ports*

*-sO Protocol*

*-sL List scan*

### Using scripts

`nmap --script smb-os-discovery 000.000.000.000` *Comment*

`nmap --script smb-enum-users 000.000.000.000` *Comment*


## Use cases

`nmap --script rpcinfo 000.000.000.000` *RPC info*

`nmap --script=ldap-search 000.000.000.000` *LDAP Search*


