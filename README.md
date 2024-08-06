# Logsign Unified SecOps Platform Multiple Vulnerabilities Scan and Exploitation

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
git clone https://github.com/j4nk3/CVE-2024-5716.git
cd CVE-2024-5716
```
### Scanning with Nuclei:

**Single Target:**
```sh
nuclei -u https://target.com -t CVE-2024-5716.yaml -nh
```
**Multiple Target:**
```sh
nuclei -l urls.txt -t CVE-2024-5716.yaml -nh
```

Many thanks to @mdisec (Mehmet Ince) for the security research and critical finding detections performed on this product.

## Contributing
Feel free to submit issues or pull requests if you find any bugs or have suggestions for improvements.

## License
This project is licensed under the MIT License.

## References
[Logsign Support](https://support.logsign.net/hc/en-us/articles/19316621924754-03-06-2024-Version-6-4-8-Release-Notes)<br>
[Zero Day Inititive](https://www.zerodayinitiative.com/blog/2024/7/1/getting-unauthenticated-remote-code-execution-on-the-logsign-unified-secops-platform)
