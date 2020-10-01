# NSE-HTTP-Probe
NMAP Script to generate httpx URLs from an scan :

Example usage  :

```nmap -Pn -v -n -p80,443,8080 --script=http-probe.nse --min-rate 500p --open example.com```
