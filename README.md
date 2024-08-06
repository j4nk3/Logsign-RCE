# Logsign Unified SecOps Platform Multiple Vulnerabilities Detection Nuclei Template

This repository contains Nuclei templates for detecting multiple vulnerabilities in Logsign Unified SecOps Platform. The templates are designed to identify the following vulnerabilities:

- **ZDI-CAN-24164 > CVE-2024-5716**: Logsign Unified SecOps Platform Authentication Bypass Vulnerability
- **ZDI-CAN-24165 > CVE-2024-5717**: Logsign Unified SecOps Platform Command Injection Remote Code Execution Vulnerability
- **ZDI-CAN-24166 > CVE-2024-5718**: Logsign Unified SecOps Platform Missing Authentication Remote Code Execution Vulnerability
- **ZDI-CAN-24167 > CVE-2024-5719**: Logsign Unified SecOps Platform Command Injection Remote Code Execution Vulnerability
- **ZDI-CAN-24168 > CVE-2024-5720**: Logsign Unified SecOps Platform Command Injection Remote Code Execution Vulnerability
- **ZDI-CAN-24169 > CVE-2024-5721**: Logsign Unified SecOps Platform Missing Authentication Remote Code Execution Vulnerability
- **ZDI-CAN-24170 > CVE-2024-5722**: Logsign Unified SecOps Platform HTTP API Hard-coded Cryptographic Key Remote Code Execution Vulnerability

## Templates Included

The repository includes the following YAML templates:

There is one nuclei template yaml file that can detect the security vulnerability in the repo here. With Nuclei automation, you can detect logsign products with critical security vulnerabilities with a single template yaml file. The exploitation stages of the vulnerabilities here will be added with python scripts and descriptions over time.

- **CVE-2024-5716**: Detects the authentication bypass vulnerability.
- **CVE-2024-5717**: Detects the command injection vulnerability leading to remote code execution.
- **CVE-2024-5718**: Detects the missing authentication vulnerability leading to remote code execution.
- **CVE-2024-5719**: Detects another instance of command injection vulnerability leading to remote code execution.
- **CVE-2024-5720**: Detects yet another instance of command injection vulnerability leading to remote code execution.
- **CVE-2024-5721**: Detects another instance of missing authentication vulnerability leading to remote code execution.
- **CVE-2024-5722**: Detects the HTTP API hard-coded cryptographic key vulnerability leading to remote code execution.

## Usage

To use these templates with Nuclei, follow the steps below:

### Clone the repository:

```sh
git clone https://github.com/j4nk3/CVE-2024-5716.git
cd CVE-2024-5716
```

### References
[Logsign Support](https://support.logsign.net/hc/en-us/articles/19316621924754-03-06-2024-Version-6-4-8-Release-Notes)
[Zero Day Inititive](https://www.zerodayinitiative.com/blog/2024/7/1/getting-unauthenticated-remote-code-execution-on-the-logsign-unified-secops-platform)

Many thanks to @mdisec (Mehmet Ince) for the security research and critical finding detections performed on this product.

### Contributing
Feel free to submit issues or pull requests if you find any bugs or have suggestions for improvements.

### License
This project is licensed under the MIT License.
