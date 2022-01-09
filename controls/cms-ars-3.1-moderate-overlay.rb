# encoding: utf-8

include_controls "redhat-enterprise-linux-8-stig-baseline" do

  control 'SV-230223' do
    desc  'check', "
      Verify the operating system implements CMS-approved encryption to protect
  the confidentiality of remote access sessions.

      Check to see if FIPS mode is enabled with the following command:

      $ sudo fipscheck

      usage: fipscheck [-s <hmac-suffix>] <paths-to-files>

      fips mode is on

      If FIPS mode is \"on\", check to see if the kernel boot parameter is
  configured for FIPS mode with the following command:

      $ sudo grub2-editenv - list | grep fips

      kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto
  resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet
  fips=1 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

      If the kernel boot parameter is configured to use FIPS mode, check to see
  if the system is in FIPS mode with the following command:

      $ sudo cat /proc/sys/crypto/fips_enabled

      1

      If FIPS mode is not \"on\", the kernel boot parameter is not configured for
  FIPS mode, or the system does not have a value of \"1\" for \"fips_enabled\" in
  \"/proc/sys/crypto\", this is a finding.
    "
    desc 'fix', "
      Configure the operating system to implement CMS-approved encryption by
  following the steps below:

      To enable strict FIPS compliance, the fips=1 kernel option needs to be
  added to the kernel boot parameters during system installation so key
  generation is done with FIPS-approved algorithms and continuous monitoring
  tests in place.

      Enable FIPS mode after installation (not strict FIPS compliant) with the
  following command:

      $ sudo fips-mode-setup --enable

      Reboot the system for the changes to take effect.
    "
  end


  control 'SV-230225' do
    title "RHEL 8 must display the Standard Mandatory CMS Notice and Consent
  Banner before granting local or remote access to the system via a ssh logon."
    desc  "Display of a standardized and approved use notification before
  granting access to the operating system ensures privacy and security
  notification verbiage used is consistent with applicable federal laws,
  Executive Orders, directives, policies, regulations, standards, and guidance.

  The approved banner states:
  \"* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
  * This system is provided for Government authorized use only.
  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
  * By using this system, you understand and consent to the following:
  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose\""
    desc  'check', "
      Verify any publicly accessible connection to the operating system displays
  the Standard Mandatory CMS Notice and Consent Banner before granting access to
  the system.

      Check for the location of the banner file being used with the following
  command:

      $ sudo grep -i banner /etc/ssh/sshd_config

      banner /etc/issue

      This command will return the banner keyword and the name of the file that
  contains the ssh banner (in this case \"/etc/issue\").

      If the line is commented out, this is a finding.

      View the file specified by the banner keyword to check that it matches the
  text of the Standard Mandatory CMS Notice and Consent Banner:

      \"* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
  * This system is provided for Government authorized use only.
  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
  * By using this system, you understand and consent to the following:
  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose\"

      If the system does not display a graphical logon banner or the banner does
  not match the Standard Mandatory CMS Notice and Consent Banner, this is a
  finding.

      If the text in the file does not match the Standard Mandatory CMS Notice
  and Consent Banner, this is a finding.
    "
    desc 'fix', "
      Configure the operating system to display the Standard Mandatory CMS Notice
  and Consent Banner before granting access to the system via the ssh.

      Edit the \"/etc/ssh/sshd_config\" file to uncomment the banner keyword and
  configure it to point to a file that will contain the logon banner (this file
  may be named differently or be in a different location if using a version of
  SSH that is provided by a third-party vendor). An example configuration line is:

      banner /etc/issue

      Either create the file containing the banner or replace the text in the
  file with the Standard Mandatory CMS Notice and Consent Banner. The
  CMS-required text is:

      \"* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
  * This system is provided for Government authorized use only.
  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
  * By using this system, you understand and consent to the following:
  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose\"

      The SSH service must be restarted for changes to take effect.
    "
  end


  control 'SV-230226' do
    title "RHEL 8 must display the Standard Mandatory CMS Notice and Consent
  Banner before granting local or remote access to the system via a graphical
  user logon."
    desc  "Display of a standardized and approved use notification before
  granting access to the operating system ensures privacy and security
  notification verbiage used is consistent with applicable federal laws,
  Executive Orders, directives, policies, regulations, standards, and guidance.

  The approved banner states:
  \"* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
  * This system is provided for Government authorized use only.
  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
  * By using this system, you understand and consent to the following:
  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose\""
    desc  'rationale', ''
    desc  'check', "
      Verify RHEL 8 displays the Standard Mandatory CMS Notice and Consent Banner
  before granting access to the operating system via a graphical user logon.

      Note: This requirement assumes the use of the RHEL 8 default graphical user
  interface, Gnome Shell. If the system does not have any graphical user
  interface installed, this requirement is Not Applicable.

      Check that the operating system displays the exact Standard Mandatory CMS
  Notice and Consent Banner text with the command:

      $ sudo grep banner-message-text /etc/dconf/db/local.d/*

      banner-message-text=
      \"* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
  * This system is provided for Government authorized use only.
  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
  * By using this system, you understand and consent to the following:
  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose\"

      Note: The \"\
       \" characters are for formatting only. They will not be displayed on the
  graphical interface.

      If the banner does not match the Standard Mandatory CMS Notice and Consent
  Banner exactly, this is a finding.
    "
    desc  'fix', "
      Configure the operating system to display the Standard Mandatory CMS Notice
  and Consent Banner before granting access to the system.

      Note: If the system does not have a graphical user interface installed,
  this requirement is Not Applicable.

      Add the following lines to the [org/gnome/login-screen] section of the
  \"/etc/dconf/db/local.d/01-banner-message\":

      banner-message-text=\"* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
  * This system is provided for Government authorized use only.
  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
  * By using this system, you understand and consent to the following:
  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose\"

      Note: The \"\
       \" characters are for formatting only. They will not be displayed on the
  graphical interface.

      Run the following command to update the database:

      $ sudo dconf update
    "
  end


  control 'SV-230227' do
    title "RHEL 8 must display the Standard Mandatory CMS Notice and Consent
  Banner before granting local or remote access to the system via a command line
  user logon."
    desc  "Display of a standardized and approved use notification before
  granting access to the operating system ensures privacy and security
  notification verbiage used is consistent with applicable federal laws,
  Executive Orders, directives, policies, regulations, standards, and guidance.

  The approved banner states:
  \"* This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.
  * This system is provided for Government authorized use only.
  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.
  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.
  * By using this system, you understand and consent to the following:
  - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.
  - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purpose\""
    desc  'rationale', ''
    desc  'check', "
      Verify RHEL 8 displays the Standard Mandatory CMS Notice and Consent Banner
  before granting access to the operating system via a command line user logon.

      Check that RHEL 8 displays a banner at the command line login screen with
  the following command:

      $ sudo cat /etc/issue

      If the banner is set correctly it will return the following text:

      “You are accessing a U.S. Government (USG) Information System (IS) that is
  provided for USG-authorized use only.

      By using this IS (which includes any device attached to this IS), you
  consent to the following conditions:

      -The USG routinely intercepts and monitors communications on this IS for
  purposes including, but not limited to, penetration testing, COMSEC monitoring,
  network operations and defense, personnel misconduct (PM), law enforcement
  (LE), and counterintelligence (CI) investigations.

      -At any time, the USG may inspect and seize data stored on this IS.

      -Communications using, or data stored on, this IS are not private, are
  subject to routine monitoring, interception, and search, and may be disclosed
  or used for any USG-authorized purpose.

      -This IS includes security measures (e.g., authentication and access
  controls) to protect USG interests--not for your personal benefit or privacy.

      -Notwithstanding the above, using this IS does not constitute consent to
  PM, LE or CI investigative searching or monitoring of the content of privileged
  communications, or work product, related to personal representation or services
  by attorneys, psychotherapists, or clergy, and their assistants. Such
  communications and work product are private and confidential. See User
  Agreement for details.”

      If the banner text does not match the Standard Mandatory CMS Notice and
  Consent Banner exactly, this is a finding.
    "
    desc 'fix', "
      Configure RHEL 8 to display the Standard Mandatory CMS Notice and Consent
  Banner before granting access to the system via command line logon.

      Edit the \"/etc/issue\" file to replace the default text with the Standard
  Mandatory CMS Notice and Consent Banner. The CMS-required text is:

      \"You are accessing a U.S. Government (USG) Information System (IS) that is
  provided for USG-authorized use only.

      By using this IS (which includes any device attached to this IS), you
  consent to the following conditions:

      -The USG routinely intercepts and monitors communications on this IS for
  purposes including, but not limited to, penetration testing, COMSEC monitoring,
  network operations and defense, personnel misconduct (PM), law enforcement
  (LE), and counterintelligence (CI) investigations.

      -At any time, the USG may inspect and seize data stored on this IS.

      -Communications using, or data stored on, this IS are not private, are
  subject to routine monitoring, interception, and search, and may be disclosed
  or used for any USG-authorized purpose.

      -This IS includes security measures (e.g., authentication and access
  controls) to protect USG interests -- not for your personal benefit or privacy.

      -Notwithstanding the above, using this IS does not constitute consent to
  PM, LE or CI investigative searching or monitoring of the content of privileged
  communications, or work product, related to personal representation or services
  by attorneys, psychotherapists, or clergy, and their assistants. Such
  communications and work product are private and confidential. See User
  Agreement for details.\"
    "
  end


  control 'SV-230228' do
   desc  "Remote access services, such as those providing remote access to
  network devices and information systems, which lack automated monitoring
  capabilities, increase risk and make remote user access management difficult at
  best.

      Remote access is access to CMS nonpublic information systems by an
  authorized user (or an information system) communicating through an external,
  non-organization-controlled network. Remote access methods include, for
  example, dial-up, broadband, and wireless.

      Automated monitoring of remote access sessions allows organizations to
  detect cyber attacks and ensure ongoing compliance with remote access policies
  by auditing connection activities of remote access capabilities, such as Remote
  Desktop Protocol (RDP), on a variety of information system components (e.g.,
  servers, workstations, notebook computers, smartphones, and tablets).
    "
  end


  control 'SV-230229' do
    desc  'check', "
      Verify RHEL 8 for PKI-based authentication has valid certificates by
  constructing a certification path (which includes status information) to an
  accepted trust anchor.

      Check that the system has a valid CMS root CA installed with the following
  command:

      $ sudo openssl x509 -text -in /etc/sssd/pki/[certificate_name].pem

      If the root ca file is not a CMS-issued certificate with a valid date and
  installed in the /etc/sssd/pki/[certificate_name].pem location, this is a finding.
    "
    desc 'fix', "
      Configure RHEL 8, for PKI-based authentication, to validate certificates by
  constructing a certification path (which includes status information) to an
  accepted trust anchor.

      Obtain a valid copy of the CMS root CA file from a PKI CA certificate
  bundle and copy the CMS chain .pem into the following file:

      /etc/sssd/pki/[certificate_name].pem
    "
  end


  control 'SV-230231' do
    desc  "Passwords need to be protected at all times, and encryption is the
  standard method for protecting passwords. If passwords are not encrypted, they
  can be plainly read (i.e., clear text) and easily compromised.

      Unapproved mechanisms that are used for authentication to the cryptographic
  module are not verified and therefore cannot be relied upon to provide
  confidentiality or integrity, and CMS data may be compromised.

      FIPS 140-2 is the current standard for validating that mechanisms used to
  access cryptographic modules utilize authentication that meets CMS requirements.
    "
  end


  control 'SV-230237' do
     desc  "Unapproved mechanisms that are used for authentication to the
  cryptographic module are not verified and therefore cannot be relied upon to
  provide confidentiality or integrity, and CMS data may be compromised.

      RHEL 8 systems utilizing encryption are required to use FIPS-compliant
  mechanisms for authenticating to cryptographic modules.

      FIPS 140-2 is the current standard for validating that mechanisms used to
  access cryptographic modules utilize authentication that meets CMS
  requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
  general-purpose computing system.
    "
  end


  control 'SV-230238' do
    desc  "Unapproved mechanisms that are used for authentication to the
  cryptographic module are not verified and therefore cannot be relied upon to
  provide confidentiality or integrity, and CMS data may be compromised.

      RHEL 8 systems utilizing encryption are required to use FIPS-compliant
  mechanisms for authenticating to cryptographic modules.

      The key derivation function (KDF) in Kerberos is not FIPS compatible.
  Ensuring the system does not have any keytab files present prevents system
  daemons from using Kerberos for authentication.  A keytab is a file containing
  pairs of Kerberos principals and encrypted keys.

      FIPS 140-2 is the current standard for validating that mechanisms used to
  access cryptographic modules utilize authentication that meets CMS
  requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
  general-purpose computing system.
    "
  end


  control 'SV-230239' do
    desc  "Unapproved mechanisms that are used for authentication to the
  cryptographic module are not verified and therefore cannot be relied upon to
  provide confidentiality or integrity, and CMS data may be compromised.

      RHEL 8 systems utilizing encryption are required to use FIPS-compliant
  mechanisms for authenticating to cryptographic modules.

      Currently, Kerberos does not utilize FIPS 140-2 cryptography.

      FIPS 140-2 is the current standard for validating that mechanisms used to
  access cryptographic modules utilize authentication that meets CMS
  requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
  general-purpose computing system.
    "
  end

  
  control "SV-230240" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (SC-3) is not applied to this system categorization in CMS ARS 3.1'
  end

  control "SV-230241" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (SC-3) is not applied to this system categorization in CMS ARS 3.1'
  end


  control 'SV-230243' do
    desc  "Preventing unauthorized information transfers mitigates the risk of
  information, including encrypted representations of information, produced by
  the actions of prior users/roles (or the actions of processes acting on behalf
  of prior users/roles) from being available to any current users/roles (or
  current processes) that obtain access to shared system resources (e.g.,
  registers, main memory, hard disks) after those resources have been released
  back to information systems. The control of information in shared resources is
  also commonly referred to as object reuse and residual information protection.

      This requirement generally applies to the design of an information
  technology product, but it can also apply to the configuration of particular
  information system components that are, or use, such products. This can be
  verified by acceptance/validation processes in CMS or other government agencies.

      There may be shared resources with configurable protections (e.g., files in
  storage) that may be assessed on specific information system components.
    "
  end


  control 'SV-230251' do
    desc  "Without cryptographic integrity protections, information can be
  altered by unauthorized users without detection.

      Remote access (e.g., RDP) is access to CMS nonpublic information systems by
  an authorized user (or an information system) communicating through an
  external, non-organization-controlled network. Remote access methods include,
  for example, dial-up, broadband, and wireless.

      Cryptographic mechanisms used for protecting the integrity of information
  include, for example, signed hash functions using asymmetric cryptography
  enabling distribution of the public key to verify the hash information while
  maintaining the confidentiality of the secret key used to generate the hash.

      RHEL 8 incorporates system-wide crypto policies by default. The SSH
  configuration file has no effect on the ciphers, MACs, or algorithms unless
  specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
  can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

      The system will attempt to use the first hash presented by the client that
  matches the server list. Listing the values \"strongest to weakest\" is a
  method to ensure the use of the strongest hash available to secure the SSH
  connection.
    "
  end


  control 'SV-230252' do
    title "The RHEL 8 operating system must implement CMS-approved encryption to
  protect the confidentiality of SSH server connections."
    desc  "Without cryptographic integrity protections, information can be
  altered by unauthorized users without detection.

      Remote access (e.g., RDP) is access to CMS nonpublic information systems by
  an authorized user (or an information system) communicating through an
  external, non-organization-controlled network. Remote access methods include,
  for example, dial-up, broadband, and wireless.

      Cryptographic mechanisms used for protecting the integrity of information
  include, for example, signed hash functions using asymmetric cryptography
  enabling distribution of the public key to verify the hash information while
  maintaining the confidentiality of the secret key used to generate the hash.

      RHEL 8 incorporates system-wide crypto policies by default. The SSH
  configuration file has no effect on the ciphers, MACs, or algorithms unless
  specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
  can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

      The system will attempt to use the first hash presented by the client that
  matches the server list. Listing the values \"strongest to weakest\" is a
  method to ensure the use of the strongest hash available to secure the SSH
  connection.


    "
  end



  control 'SV-230254' do
    title "The RHEL 8 operating system must implement CMS-approved encryption in
  the OpenSSL package."
    desc  "Without cryptographic integrity protections, information can be
  altered by unauthorized users without detection.

      Remote access (e.g., RDP) is access to CMS nonpublic information systems by
  an authorized user (or an information system) communicating through an
  external, non-organization-controlled network. Remote access methods include,
  for example, dial-up, broadband, and wireless.

      Cryptographic mechanisms used for protecting the integrity of information
  include, for example, signed hash functions using asymmetric cryptography
  enabling distribution of the public key to verify the hash information while
  maintaining the confidentiality of the secret key used to generate the hash.

      RHEL 8 incorporates system-wide crypto policies by default.  The employed
  algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config
  file.


    "
  end


  control 'SV-230255' do
    title "The RHEL 8 operating system must implement CMS-approved TLS encryption
  in the OpenSSL package."
    desc  "Without cryptographic integrity protections, information can be
  altered by unauthorized users without detection.

      Remote access (e.g., RDP) is access to CMS nonpublic information systems by
  an authorized user (or an information system) communicating through an
  external, non-organization-controlled network. Remote access methods include,
  for example, dial-up, broadband, and wireless.

      Cryptographic mechanisms used for protecting the integrity of information
  include, for example, signed hash functions using asymmetric cryptography
  enabling distribution of the public key to verify the hash information while
  maintaining the confidentiality of the secret key used to generate the hash.

      RHEL 8 incorporates system-wide crypto policies by default.  The employed
  algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config
  file.


    "
    desc  'check', "
      Verify the OpenSSL library is configured to use only CMS-approved TLS
  encryption:

      $ sudo grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

      MinProtocol = TLSv1.2

      If the \"MinProtocol\" is set to anything older than \"TLSv1.2\", this is a
  finding.
    "
    desc 'fix', "
      Configure the RHEL 8 OpenSSL library to use only CMS-approved TLS
  encryption by editing the following line in the
  \"/etc/crypto-policies/back-ends/opensslcnf.config\" file:

      MinProtocol = TLSv1.2

      A reboot is required for the changes to take effect.
    "
  end


  control 'SV-230256' do
    title "The RHEL 8 operating system must implement CMS-approved TLS encryption
  in the GnuTLS package."
    desc  'check', "
      Verify the GnuTLS library is configured to only allow CMS-approved SSL/TLS
  Versions:

      $ sudo grep -io +vers.*  /etc/crypto-policies/back-ends/gnutls.config


  +VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:+COMP-NULL:%PROFILE_MEDIUM

      If the \"gnutls.config\" does not list
  \"-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:VERS-DTLS1.0\" to
  disable unapproved SSL/TLS versions, this is a finding.
    "
    desc 'fix', "
      Configure the RHEL 8 GnuTLS library to use only CMS-approved encryption by
  adding the following line to \"/etc/crypto-policies/back-ends/gnutls.config\":

      +VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0

      A reboot is required for the changes to take effect.
    "
  end

  control "SV-230257" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (6)) is not included in CMS ARS 3.1'
  end

  control "SV-230258" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (6)) is not included in CMS ARS 3.1'
  end

  control "SV-230259" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (6)) is not included in CMS ARS 3.1'
  end

  control "SV-230260" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (6)) is not included in CMS ARS 3.1'
  end

  control "SV-230261" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (6)) is not included in CMS ARS 3.1'
  end

  control "SV-230262" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (6)) is not included in CMS ARS 3.1'
  end

  control "SV-230263" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-3 (5)) is not included in CMS ARS 3.1'
  end

  control "SV-230264" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (3)) is not applied to this system categorization in CMS ARS 3.1'
  end
  
  control "SV-230265" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (3)) is not applied to this system categorization in CMS ARS 3.1'
  end
  
  control "SV-230266" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (CM-5 (3)) is not applied to this system categorization in CMS ARS 3.1'
  end

  control "SV-230267" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AC-3 (4)) is not included in CMS ARS 3.1'
  end

  control "SV-230268" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AC-3 (4)) is not included in CMS ARS 3.1'
  end


  control 'SV-230269' do
    desc  "Preventing unauthorized information transfers mitigates the risk of
  information, including encrypted representations of information, produced by
  the actions of prior users/roles (or the actions of processes acting on behalf
  of prior users/roles) from being available to any current users/roles (or
  current processes) that obtain access to shared system resources (e.g.,
  registers, main memory, hard disks) after those resources have been released
  back to information systems. The control of information in shared resources is
  also commonly referred to as object reuse and residual information protection.

      This requirement generally applies to the design of an information
  technology product, but it can also apply to the configuration of particular
  information system components that are, or use, such products. This can be
  verified by acceptance/validation processes in CMS or other government agencies.

      There may be shared resources with configurable protections (e.g., files in
  storage) that may be assessed on specific information system components.

      Restricting access to the kernel message buffer limits access to only root.
   This prevents attackers from gaining additional system information as a
  non-privileged user.
    "
  end


  control 'SV-230270' do
    desc  "Preventing unauthorized information transfers mitigates the risk of
  information, including encrypted representations of information, produced by
  the actions of prior users/roles (or the actions of processes acting on behalf
  of prior users/roles) from being available to any current users/roles (or
  current processes) that obtain access to shared system resources (e.g.,
  registers, main memory, hard disks) after those resources have been released
  back to information systems. The control of information in shared resources is
  also commonly referred to as object reuse and residual information protection.

      This requirement generally applies to the design of an information
  technology product, but it can also apply to the configuration of particular
  information system components that are, or use, such products. This can be
  verified by acceptance/validation processes in CMS or other government agencies.

      There may be shared resources with configurable protections (e.g., files in
  storage) that may be assessed on specific information system components.

      Setting the kernel.perf_event_paranoid kernel parameter to \"2\" prevents
  attackers from gaining additional system information as a non-privileged user.
    "
  end
  
  control "SV-230271" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (IA-11) is not included in CMS ARS 3.1'
  end

  control "SV-230272" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (IA-11) is not included in CMS ARS 3.1'
  end

  control 'SV-230273' do
   desc  "Using an authentication device, such as a CMS PIV
  or token that is separate from the information system, ensures that even if the
  information system is compromised, credentials stored on the authentication
  device will not be affected.

      Multifactor solutions that require devices separate from information
  systems gaining access include, for example, hardware tokens providing
  time-based or challenge-response authenticators and smart cards such as the
  U.S. Government Personal Identity Verification (PIV) card and the CMS PIV.

      A privileged account is defined as an information system account with
  authorizations of a privileged user.

      Remote access is access to CMS nonpublic information systems by an
  authorized user (or an information system) communicating through an external,
  non-organization-controlled network. Remote access methods include, for
  example, dial-up, broadband, and wireless.

      This requirement only applies to components where this is specific to the
  function of the device or has the concept of an organizational user (e.g., VPN,
  proxy capability). This does not apply to authentication for the purpose of
  configuring the device itself (management).
    "
  end


  control 'SV-230274' do
    desc  "Using an authentication device, such as a CMS PIV
  or token that is separate from the information system, ensures that even if the
  information system is compromised, credentials stored on the authentication
  device will not be affected.

      Multifactor solutions that require devices separate from information
  systems gaining access include, for example, hardware tokens providing
  time-based or challenge-response authenticators and smart cards such as the
  U.S. Government Personal Identity Verification (PIV) card and the CMS PIV.

      RHEL 8 includes multiple options for configuring certificate status
  checking, but for this requirement focuses on the System Security Services
  Daemon (SSSD). By default, sssd performs Online Certificate Status Protocol
  (OCSP) checking and certificate verification using a sha256 digest function.


    "
  end


  control 'SV-230275' do
    desc  "The use of PIV credentials facilitates standardization and reduces the
  risk of unauthorized access.

      The CMS has mandated the use of the CMS PIV to support
  identity management and personal authentication for systems covered under
  Homeland Security Presidential Directive (HSPD) 12, as well as making the PIV a
  primary component of layered protection for national security systems.
    "
  end


  control "SV-230277" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (SC-3) is not applied to this system categorization in CMS ARS 3.1'
  end

  control "SV-230278" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (SC-3) is not applied to this system categorization in CMS ARS 3.1'
  end

  control "SV-230279" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (SC-3) is not applied to this system categorization in CMS ARS 3.1'
  end

  control "SV-230281" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (SI-2 (6)) is not included in CMS ARS 3.1'
  end

  control "SV-230282" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (SI-6 a) is not applied to this system categorization in CMS ARS 3.1'
  end

  control "SV-230296" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (IA-2 (5)) is not included in CMS ARS 3.1'
  end

  control 'SV-230297' do
    desc  "Configuring RHEL 8 to implement organization-wide security
  implementation guides and security checklists ensures compliance with federal
  standards and establishes a common security baseline across the CMS that
  reflects the most restrictive security posture consistent with operational
  requirements.

      Configuration settings are the set of parameters that can be changed in
  hardware, software, or firmware components of the system that affect the
  security posture and/or functionality of the system. Security-related
  parameters are those parameters impacting the security state of the system,
  including the parameters required to satisfy other security control
  requirements. Security-related parameters include, for example: registry
  settings; account, file, directory permission settings; and settings for
  functions, ports, protocols, services, and remote connections.
    "
  end


  control 'SV-230298' do
    desc  "Configuring RHEL 8 to implement organization-wide security
  implementation guides and security checklists ensures compliance with federal
  standards and establishes a common security baseline across the CMS that
  reflects the most restrictive security posture consistent with operational
  requirements.

      Configuration settings are the set of parameters that can be changed in
  hardware, software, or firmware components of the system that affect the
  security posture and/or functionality of the system. Security-related
  parameters are those parameters impacting the security state of the system,
  including the parameters required to satisfy other security control
  requirements. Security-related parameters include, for example: registry
  settings; account, file, directory permission settings; and settings for
  functions, ports, protocols, services, and remote connections.
    "
  end


  control 'SV-230331' do
    title "RHEL 8 temporary user accounts must be provisioned with an expiration
  time of 24 hours or less."
    desc  "If temporary user accounts remain active when no longer needed or for
  an excessive period, these accounts may be used to gain unauthorized access. To
  mitigate this risk, automated termination of all temporary accounts must be set
  upon account creation.

      Temporary accounts are established as part of normal account activation
  procedures when there is a need for short-term accounts without the demand for
  immediacy in account activation.

      If temporary accounts are used, RHEL 8 must be configured to automatically
  terminate these types of accounts after a CMS-defined time period of 24 hours.

      To address access requirements, many RHEL 8 operating systems may be
  integrated with enterprise-level authentication/access mechanisms that meet or
  exceed access control policy requirements.
    "
    desc  'check', "
      Verify that temporary accounts have been provisioned with an expiration
  date of 24 hours.

      For every existing temporary account, run the following command to obtain
  its account expiration information.

      $ sudo chage -l system_account_name

      Verify each of these accounts has an expiration date set within 24 hours.

      If any temporary accounts have no expiration date set or do not expire
  within 24 hours, this is a finding.
    "
    desc 'fix', "
      If a temporary account must be created configure the system to terminate
  the account after a 24 hour time period with the following command to set an
  expiration date on it. Substitute \"system_account_name\" with the account to
  be created.

      $ sudo chage -E `date -d \"+1 days\" +%Y-%m-%d` system_account_name
    "


    temporary_accounts = input('temporary_accounts')

    if temporary_accounts.empty?
      describe 'Temporary accounts' do
        subject { temporary_accounts }
        it { should be_empty }
      end
    else
      temporary_accounts.each do |acct|
        describe user(acct.to_s) do
          its('maxdays') { should cmp <= 1 }
          its('maxdays') { should cmp > 0 }
        end
      end
    end
  end


  control 'SV-230332' do
    title "RHEL 8 must automatically lock an account when five unsuccessful
  logon attempts occur."
    desc  'check', "
      Check that the system locks an account after five unsuccessful logon
  attempts with the following commands:

      Note: If the System Administrator demonstrates the use of an approved
  centralized account management method that locks an account after five
  unsuccessful logon attempts within a period of 120 minutes, this requirement is
  not applicable.

      Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
  RHEL version 8.2 or newer, this check is not applicable.

      $ sudo grep pam_faillock.so /etc/pam.d/password-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"deny\" option is not set to \"5\" or less (but not \"0\") on the
  \"preauth\" line with the \"pam_faillock.so\" module, or is missing from this
  line, this is a finding.

      If any line referencing the \"pam_faillock.so\" module is commented out,
  this is a finding.

      $ sudo grep pam_faillock.so /etc/pam.d/system-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"deny\" option is not set to \"5\" or less (but not \"0\") on the
  \"preauth\" line with the \"pam_faillock.so\" module, or is missing from this
  line, this is a finding.

      If any line referencing the \"pam_faillock.so\" module is commented out,
  this is a finding.
    "
    desc 'fix', "
      Configure the operating system to lock an account when five unsuccessful
  logon attempts occur.

      Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
  \"/etc/pam.d/password-auth\" files to match the following lines:

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      The \"sssd\" service must be restarted for the changes to take effect. To
  restart the \"sssd\" service, run the following command:

      $ sudo systemctl restart sssd.service
    "
  end


  control 'SV-230333' do
    title "RHEL 8 must automatically lock an account when five unsuccessful
  logon attempts occur."
    desc  'check', "
      Note: This check applies to RHEL versions 8.2 or newer, if the system is
  RHEL version 8.0 or 8.1, this check is not applicable.

      Verify the \"/etc/security/faillock.conf\" file is configured to lock an
  account after five unsuccessful logon attempts:

      $ sudo grep 'deny =' /etc/security/faillock.conf

      deny = 5

      If the \"deny\" option is not set to \"5\" or less (but not \"0\"), is
  missing or commented out, this is a finding.
    "
    desc  'fix', "
      Configure the operating system to lock an account when five unsuccessful
  logon attempts occur.

      Add/Modify the \"/etc/security/faillock.conf\" file to match the following
  line:

      deny = 5
    "
  end


  control 'SV-230334' do
    title "RHEL 8 must automatically lock an account when five unsuccessful
  logon attempts occur during a 120-minute time period."
    desc  'check', "
      Check that the system locks an account after five unsuccessful logon
  attempts within a period of 120 minutes with the following commands:

      Note: If the System Administrator demonstrates the use of an approved
  centralized account management method that locks an account after five
  unsuccessful logon attempts within a period of 120 minutes, this requirement is
  not applicable.

      Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
  RHEL version 8.2 or newer, this check is not applicable.

      $ sudo grep pam_faillock.so /etc/pam.d/password-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"fail_interval\" option is not set to \"7200\" or less (but not
  \"0\") on the \"preauth\" lines with the \"pam_faillock.so\" module, or is
  missing from this line, this is a finding.

      $ sudo grep pam_faillock.so /etc/pam.d/system-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"fail_interval\" option is not set to \"7200\" or less (but not
  \"0\") on the \"preauth\" lines with the \"pam_faillock.so\" module, or is
  missing from this line, this is a finding.
    "
    desc 'fix', "
      Configure the operating system to lock an account when five unsuccessful
  logon attempts occur in 60 minutes.

      Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
  \"/etc/pam.d/password-auth\" files to match the following lines:

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      The \"sssd\" service must be restarted for the changes to take effect. To
  restart the \"sssd\" service, run the following command:

      $ sudo systemctl restart sssd.service
    "
  end


  control 'SV-230335' do
    title "RHEL 8 must automatically lock an account when five unsuccessful
  logon attempts occur during a 120-minute time period."
    desc  'check', "
      Note: This check applies to RHEL versions 8.2 or newer, if the system is
  RHEL version 8.0 or 8.1, this check is not applicable.

      Verify the \"/etc/security/faillock.conf\" file is configured to lock an
  account after five unsuccessful logon attempts within 120 minutes:

      $ sudo grep 'fail_interval =' /etc/security/faillock.conf

      fail_interval = 7200

      If the \"fail_interval\" option is not set to \"7200\" or more, is missing
  or commented out, this is a finding.
    "
    desc  'fix', "
      Configure the operating system to lock an account when five unsuccessful
  logon attempts occur in 120 minutes.

      Add/Modify the \"/etc/security/faillock.conf\" file to match the following
  line:

      fail_interval = 7200
    "
  end


  control 'SV-230336' do
    title "RHEL 8 must automatically lock an account for 60 minutes when five unsuccessful logon attempts occur
  during a 120-minute time period."
    desc  'check', "
      Check that the system locks an account for 60 minutes after five unsuccessful logon
  attempts within a period of 120 minutes with
  the following commands:

      Note: If the System Administrator demonstrates the use of an approved
  centralized account management method that locks an account for 60 minutes after five unsuccessful logon attempts within a period of 120 minutes, this requirement is
  not applicable.

      Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
  RHEL version 8.2 or newer, this check is not applicable.

      $ sudo grep pam_faillock.so /etc/pam.d/password-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"unlock_time\" option is not set to \"3600\" on the \"preauth\" and
  \"authfail\" lines with the \"pam_faillock.so\" module, or is missing from
  these lines, this is a finding.

      $ sudo grep pam_faillock.so /etc/pam.d/system-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"unlock_time\" option is not set to \"3600\" on the \"preauth\" and
  \"authfail\" lines with the \"pam_faillock.so\" module, or is missing from
  these lines, this is a finding.
    "
    desc 'fix', "
      Configure the operating system to lock an account for 60 minutes when five unsuccessful logon attempts occur in 120 minutes.

      Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
  \"/etc/pam.d/password-auth\" files to match the following lines:

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      The \"sssd\" service must be restarted for the changes to take effect. To
  restart the \"sssd\" service, run the following command:

      $ sudo systemctl restart sssd.service
    "
  end


  control 'SV-230337' do
    title "RHEL 8 must automatically lock an account for 60 minutes when five unsuccessful logon attempts occur
  during a 120-minute time period."
    desc  'check', "
      Note: This check applies to RHEL versions 8.2 or newer, if the system is
  RHEL version 8.0 or 8.1, this check is not applicable.

      Verify the \"/etc/security/faillock.conf\" file is configured to lock an
  account for 60 minutes after five unsuccessful logon
  attempts:

      $ sudo grep 'unlock_time =' /etc/security/faillock.conf

      unlock_time = 3600

      If the \"unlock_time\" option is not set to \"3600\", is missing or commented
  out, this is a finding.
    "
    desc 'fix', "
      Configure the operating system to lock an account for 60 minutes when five unsuccessful logon attempts occur in 120 minutes.

      Add/Modify the \"/etc/security/faillock.conf\" file to match the following
  line:

      unlock_time = 3600
    "
  end

  control 'SV-230338' do
    desc  'check', "
      Check that the faillock directory contents persists after a reboot with the
  following commands:

      Note: If the System Administrator demonstrates the use of an approved
  centralized account management method that locks an account after five
  unsuccessful logon attempts within a period of 120 minutes, this requirement is
  not applicable.

      Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
  RHEL version 8.2 or newer, this check is not applicable.

      $ sudo grep pam_faillock.so /etc/pam.d/password-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"dir\" option is not set to a non-default documented tally log
  directory on the \"preauth\" and \"authfail\" lines with the
  \"pam_faillock.so\" module, or is missing from these lines, this is a finding.

      $ sudo grep pam_faillock.so /etc/pam.d/system-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"dir\" option is not set to a non-default documented tally log
  directory on the \"preauth\" and \"authfail\" lines with the
  \"pam_faillock.so\" module, or is missing from these lines, this is a finding.
    "
    desc 'fix', "
      Configure the operating system maintain the contents of the faillock
  directory after a reboot.

      Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
  \"/etc/pam.d/password-auth\" files to match the following lines:

      Note: Using the default faillock directory of /var/run/faillock will result
  in the contents being cleared in the event of a reboot.

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      The \"sssd\" service must be restarted for the changes to take effect. To
  restart the \"sssd\" service, run the following command:

      $ sudo systemctl restart sssd.service
    "
  end
  

  control 'SV-230340' do
    title "RHEL 8 must prevent system messages from being presented when five unsuccessful logon attempts occur."
    desc  'check', "
      Check that the system prevents informative messages from being presented to
  the user pertaining to logon information with the following commands:

      Note: If the System Administrator demonstrates the use of an approved
  centralized account management method that locks an account after five unsuccessful logon attempts within a period of 120 minutes, this requirement is
  not applicable.

      Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
  RHEL version 8.2 or newer, this check is not applicable.

      $ sudo grep pam_faillock.so /etc/pam.d/password-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"silent\" option is missing from the \"preauth\" line with the
  \"pam_faillock.so\" module, this is a finding.

      $ sudo grep pam_faillock.so /etc/pam.d/system-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"silent\" option is missing from the \"preauth\" line with the
  \"pam_faillock.so\" module, this is a finding.
    "
    desc 'fix', "
      Configure the operating system to prevent informative messages from being
  presented at logon attempts.

      Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
  \"/etc/pam.d/password-auth\" files to match the following lines:

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      The \"sssd\" service must be restarted for the changes to take effect. To
  restart the \"sssd\" service, run the following command:

      $ sudo systemctl restart sssd.service
    "
  end


  control 'SV-230341' do
    title "RHEL 8 must prevent system messages from being presented when five unsuccessful logon attempts occur."
  end

  control 'SV-230342' do
    desc  'check', "
      Check that the system logs user name information when unsuccessful logon
  attempts occur with the following commands:

      If the system is RHEL version 8.2 or newer, this check is not applicable.

      Note: If the System Administrator demonstrates the use of an approved
  centralized account management method that locks an account after five
  unsuccessful logon attempts within a period of 120 minutes, this requirement is
  not applicable.

      $ sudo grep pam_faillock.so /etc/pam.d/password-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"audit\" option is missing from the \"preauth\" line with the
  \"pam_faillock.so\" module, this is a finding.

      $ sudo grep pam_faillock.so /etc/pam.d/system-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"audit\" option is missing from the \"preauth\" line with the
  \"pam_faillock.so\" module, this is a finding.
    "
    desc 'fix', "
      Configure the operating system to log user name information when
  unsuccessful logon attempts occur.

      Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
  \"/etc/pam.d/password-auth\" files to match the following lines:

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      The \"sssd\" service must be restarted for the changes to take effect. To
  restart the \"sssd\" service, run the following command:

      $ sudo systemctl restart sssd.service
    "
  end


  control 'SV-230344' do
    title "RHEL 8 must include root when automatically locking an account for 60 minutes when five unsuccessful
  logon attempts occur during a 120-minute time period."
    desc  'check', "
      Check that the system includes the root account when locking an account
  after five unsuccessful logon attempts within a period of 120 minutes with the
  following commands:

      If the system is RHEL version 8.2 or newer, this check is not applicable.

      Note: If the System Administrator demonstrates the use of an approved
  centralized account management method that locks an account after five unsuccessful logon attempts within a period of 120 minutes, this requirement is
  not applicable.

      $ sudo grep pam_faillock.so /etc/pam.d/password-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"even_deny_root\" option is missing from the \"preauth\" line with
  the \"pam_faillock.so\" module, this is a finding.

      $ sudo grep pam_faillock.so /etc/pam.d/system-auth

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      If the \"even_deny_root\" option is missing from the \"preauth\" line with
  the \"pam_faillock.so\" module, this is a finding.
    "
    desc 'fix', "
      Configure the operating system to include root when locking an account
  after five unsuccessful logon attempts occur in 120 minutes.

      Add/Modify the appropriate sections of the \"/etc/pam.d/system-auth\" and
  \"/etc/pam.d/password-auth\" files to match the following lines:

      auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
  deny=5 even_deny_root fail_interval=7200 unlock_time=3600
      auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=3600
      account required pam_faillock.so

      The \"sssd\" service must be restarted for the changes to take effect. To
  restart the \"sssd\" service, run the following command:

      $ sudo systemctl restart sssd.service
    "
  end


  control 'SV-230345' do
    title "RHEL 8 must include root when automatically locking an account for 60 minutes when five unsuccessful
  logon attempts occur during a 120-minute time period."
    desc 'fix', "
      Configure the operating system to include root when locking an account
  after five unsuccessful logon attempts occur in 120 minutes.

      Add/Modify the \"/etc/security/faillock.conf\" file to match the following
  line:

      even_deny_root
    "
  end

  control "SV-230346" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AC-10) is not applied to this system categorization in CMS ARS 3.1'
  end

  control 'SV-230353' do
    title "RHEL 8 must automatically lock command line user sessions after 30
  minutes of inactivity."
    desc  'check', "
      Verify the operating system initiates a session lock after 30 minutes of
  inactivity.

      Check the value of the system inactivity timeout with the following command:

      $ sudo grep -i lock-after-time /etc/tmux.conf

      set -g lock-after-time 1800

      If \"lock-after-time\" is not set to \"1800\" or less in the global tmux
  configuration file to enforce session lock after inactivity, this is a finding.
    "
    desc 'fix', "
      Configure the operating system to enforce session lock after a period of 30
  minutes of inactivity by adding the following line to the \"/etc/tmux.conf\"
  global configuration file:

      set -g lock-after-time 1800
    "
  end


  control "SV-230360" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related requirement is not included in IA-5(1) in CMS ARS 3.1'
  end
  
  control "SV-230361" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related requirement is not included in IA-5(1) in CMS ARS 3.1'
  end
  
  control "SV-230362" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related requirement is not included in IA-5(1) in CMS ARS 3.1'
  end
  

  control 'SV-230363' do
    title "RHEL 8 must require the change of at least 6 characters when passwords
  are changed."
    desc  'check', "
      Verify the value of the \"difok\" option in
  \"/etc/security/pwquality.conf\" with the following command:

      $ sudo grep difok /etc/security/pwquality.conf

      difok = 6

      If the value of \"difok\" is set to less than \"6\" or is commented out,
  this is a finding.
    "
    desc 'fix', "
      Configure the operating system to require the change of at least six of
  the total number of characters when passwords are changed by setting the
  \"difok\" option.

      Add the following line to \"/etc/security/pwquality.conf\" (or modify the
  line to have the required value):

      difok = 6
    "
  end


  control 'SV-230368' do
    title "RHEL 8 passwords must be prohibited from reuse for a minimum of six
  generations."
    desc  'check', "
      Verify the operating system prohibits password reuse for a minimum of six
  generations.

      Check for the value of the \"remember\" argument in
  \"/etc/pam.d/system-auth\" and \"/etc/pam.d/password-auth\" with the following
  command:

      $ sudo grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth

      password required pam_pwhistory.so use_authtok remember=6 retry=3

      If the line containing \"pam_pwhistory.so\" does not have the \"remember\"
  module argument set, is commented out, or the value of the \"remember\" module
  argument is set to less than \"6\", this is a finding.
    "
    desc 'fix', "
      Configure the operating system to prohibit password reuse for a minimum of
  six generations.

      Add the following line in \"/etc/pam.d/system-auth\" and
  \"/etc/pam.d/password-auth\" (or modify the line to have the required value):

      password required pam_pwhistory.so use_authtok remember=6 retry=3
    "
  end


  control 'SV-230369' do
    desc  "The shorter the password, the lower the number of possible
  combinations that need to be tested before the password is compromised.

      Password complexity, or strength, is a measure of the effectiveness of a
  password in resisting attempts at guessing and brute-force attacks. Password
  length is one factor of several that helps to determine strength and how long
  it takes to crack a password. Use of more characters in a password helps to
  increase exponentially the time and/or resources required to compromise the
  password.

      RHEL 8 utilizes \"pwquality\" as a mechanism to enforce password
  complexity. Configurations are set in the \"etc/security/pwquality.conf\" file.

      The \"minlen\", sometimes noted as minimum length, acts as a \"score\" of
  complexity based on the credit components of the \"pwquality\" module. By
  setting the credit components to a negative value, not only will those
  components be required, they will not count towards the total \"score\" of
  \"minlen\". This will enable \"minlen\" to require a 15-character minimum.

      The CMS minimum password requirement is 15 characters.
    "
  end


  control 'SV-230370' do
    desc  "The shorter the password, the lower the number of possible
  combinations that need to be tested before the password is compromised.

      Password complexity, or strength, is a measure of the effectiveness of a
  password in resisting attempts at guessing and brute-force attacks. Password
  length is one factor of several that helps to determine strength and how long
  it takes to crack a password. Use of more characters in a password helps to
  increase exponentially the time and/or resources required to compromise the
  password.

      The CMS minimum password requirement is 15 characters.
    "
  end


  control 'SV-230372' do
    desc  "Using an authentication device, such as a PIV or
  token that is separate from the information system, ensures that even if the
  information system is compromised, that compromise will not affect credentials
  stored on the authentication device.

      Multifactor solutions that require devices separate from information
  systems gaining access include, for example, hardware tokens providing
  time-based or challenge-response authenticators and smart cards such as the
  U.S. Government Personal Identity Verification card and the CMS PIV.

      There are various methods of implementing multifactor authentication for
  RHEL 8. Some methods include a local system multifactor account mapping or
  joining the system to a domain and utilizing a Red Hat idM server or Microsoft
  Windows Active Directory server. Any of these methods will require that the
  client operating system handle the multifactor authentication correctly.


    "
  end


  control 'SV-230373' do
    title "RHEL 8 account identifiers (individuals, groups, roles, and devices)
  must be disabled after 60 days of inactivity."
    desc  "Inactive identifiers pose a risk to systems and applications because
  attackers may exploit an inactive identifier and potentially obtain undetected
  access to the system. Owners of inactive accounts will not notice if
  unauthorized access to their user account has been obtained.

      RHEL 8 needs to track periods of inactivity and disable application
  identifiers after 60 days of inactivity.
    "
    desc  'check', "
      Verify the account identifiers (individuals, groups, roles, and devices)
  are disabled after 60 days of inactivity with the following command:

      Check the account inactivity value by performing the following command:

      $ sudo grep -i inactive /etc/default/useradd

      INACTIVE=60

      If \"INACTIVE\" is set to \"-1\", a value greater than \"60\", or is
  commented out, this is a finding.
    "
    desc 'fix', "
      Configure RHEL 8 to disable account identifiers after 60 days of inactivity
  after the password expiration.

      Run the following command to change the configuration for useradd:

      $ sudo useradd -D -f 60

      CMS recommendation is 60 days, but a lower value is acceptable. The value
  \"-1\" will disable this feature, and \"0\" will disable the account
  immediately after the password expires.
    "
  end


  control 'SV-230374' do
    title "RHEL 8 emergency accounts must be automatically removed or disabled
  after the crisis is resolved or within 24 hours."
    desc  'check', "
      Verify emergency accounts have been provisioned with an expiration date of
  24 hours.

      For every existing emergency account, run the following command to obtain
  its account expiration information.

      $ sudo chage -l system_account_name

      Verify each of these accounts has an expiration date set within 24 hours.
      If any emergency accounts have no expiration date set or do not expire
  within 24 hours, this is a finding.
    "
    desc 'fix', "
      If an emergency account must be created, configure the system to terminate
  the account after 24 hours with the following command to set an expiration date
  for the account. Substitute \"system_account_name\" with the account to be
  created.

      $ sudo chage -E `date -d \"+1 days\" +%Y-%m-%d` system_account_name

      The automatic expiration or disabling time period may be extended as needed
  until the crisis is resolved.
    "


    temporary_accounts = input('temporary_accounts')

    if temporary_accounts.empty?
      describe 'Temporary accounts' do
        subject { temporary_accounts }
        it { should be_empty }
      end
    else
      temporary_accounts.each do |acct|
        describe user(acct.to_s) do
          its('maxdays') { should cmp <= 1 }
          its('maxdays') { should cmp > 0 }
        end
      end
    end
  end


  control "SV-230376" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (IA-5 (13)) is not included in CMS ARS 3.1'
  end


  control 'SV-230378' do
    desc  "Configuring the operating system to implement organization-wide
  security implementation guides and security checklists verifies compliance with
  federal standards and establishes a common security baseline across the CMS
  that reflects the most restrictive security posture consistent with operational
  requirements.

      Configuration settings are the set of parameters that can be changed in
  hardware, software, or firmware components of the system that affect the
  security posture and/or functionality of the system. Security-related
  parameters are those parameters impacting the security state of the system,
  including the parameters required to satisfy other security control
  requirements. Security-related parameters include, for example, registry
  settings; account, file, and directory permission settings; and settings for
  functions, ports, protocols, services, and remote connections.
    "
  end

  control "SV-230386" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AC-6 (8)) is not included in CMS ARS 3.1'
  end

  control "SV-230394" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AU-4 (1)) is not included in CMS ARS 3.1'
  end

  control "SV-230475" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AU-9 (3)) is not applied to this system categorization in CMS ARS 3.1'
  end

  control "SV-230479" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AU-4 (1)) is not included in CMS ARS 3.1'
  end

  control "SV-230480" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AU-4 (1)) is not included in CMS ARS 3.1'
  end

  control "SV-230481" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AU-4 (1)) is not included in CMS ARS 3.1'
  end

  control "SV-230482" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AU-4 (1)) is not included in CMS ARS 3.1'
  end

  control "SV-230483" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AU-5 (1)) is not applied to this system categorization in CMS ARS 3.1'
  end

  control 'SV-230484' do
    title "RHEL 8 must securely compare internal information system clocks at
  least every 24 hours with a server synchronized to an authoritative time
  source, such as the United States Naval Observatory (USNO) time servers, or a
  time server designated for the appropriate CMS network."
    desc  'check', "
      Verify RHEL 8 is securely comparing internal information system clocks at
  least every 24 hours with an NTP server with the following commands:

      $ sudo grep maxpoll /etc/chrony.conf

      server 0.us.pool.ntp.mil iburst maxpoll 16

      If the \"maxpoll\" option is set to a number greater than 16 or the line is
  commented out, this is a finding.

      Verify the \"chrony.conf\" file is configured to an authoritative CMS time
  source by running the following command:

      $ sudo grep -i server /etc/chrony.conf
      server 0.us.pool.ntp.mil

      If the parameter \"server\" is not set or is not set to an authoritative
  CMS time source, this is a finding.
    "
  end


  control 'SV-230504' do
    desc  "Failure to restrict network connectivity only to authorized systems
  permits inbound connections from malicious systems. It also permits outbound
  connections that may facilitate exfiltration of CMS data.

      RHEL 8 incorporates the \"firewalld\" daemon, which allows for many
  different configurations. One of these configurations is zones. Zones can be
  utilized to a deny-all, allow-by-exception approach. The default \"drop\" zone
  will drop all incoming network packets unless it is explicitly allowed by the
  configuration file or is related to an outgoing network connection.
    "
  end


  control 'SV-230505' do
    desc  "\"Firewalld\" provides an easy and effective way to block/limit remote
  access to the system via ports, services, and protocols.

      Remote access services, such as those providing remote access to network
  devices and information systems, which lack automated control capabilities,
  increase risk and make remote user access management difficult at best.

      Remote access is access to CMS nonpublic information systems by an
  authorized user (or an information system) communicating through an external,
  non-organization-controlled network. Remote access methods include, for
  example, dial-up, broadband, and wireless.

      RHEL 8 functionality (e.g., RDP) must be capable of taking enforcement
  action if the audit reveals unauthorized activity. Automated control of remote
  access sessions allows organizations to ensure ongoing compliance with remote
  access policies by enforcing connection rules of remote access applications on
  a variety of information system components (e.g., servers, workstations,
  notebook computers, smartphones, and tablets).
    "
  end


  control 'SV-230506' do
    desc  "Without protection of communications with wireless peripherals,
  confidentiality and integrity may be compromised because unprotected
  communications can be intercepted and either read, altered, or used to
  compromise the RHEL 8 operating system.

      This requirement applies to wireless peripheral technologies (e.g.,
  wireless mice, keyboards, displays, etc.) used with RHEL 8 systems. Wireless
  peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and
  Near Field Communications [NFC]) present a unique challenge by creating an
  open, unsecured port on a computer. Wireless peripherals must meet CMS
  requirements for wireless data transmission and be approved for use by the
  Authorizing Official (AO). Even though some wireless peripherals, such as mice
  and pointing devices, do not ordinarily carry information that need to be
  protected, modification of communications with these wireless peripherals may
  be used to compromise the RHEL 8 operating system. Communication paths outside
  the physical protection of a controlled boundary are exposed to the possibility
  of interception and modification.

      Protecting the confidentiality and integrity of communications with
  wireless peripherals can be accomplished by physical means (e.g., employing
  physical barriers to wireless radio frequencies) or by logical means (e.g.,
  employing cryptographic techniques). If physical means of protection are
  employed, then logical means (cryptography) do not have to be employed, and
  vice versa. If the wireless peripheral is only passing telemetry data,
  encryption of the data may not be required.


    "
  end


  control 'SV-230507' do
    desc  "Without protection of communications with wireless peripherals,
  confidentiality and integrity may be compromised because unprotected
  communications can be intercepted and either read, altered, or used to
  compromise the RHEL 8 operating system.

      This requirement applies to wireless peripheral technologies (e.g.,
  wireless mice, keyboards, displays, etc.) used with RHEL 8 systems. Wireless
  peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and
  Near Field Communications [NFC]) present a unique challenge by creating an
  open, unsecured port on a computer. Wireless peripherals must meet CMS
  requirements for wireless data transmission and be approved for use by the
  Authorizing Official (AO). Even though some wireless peripherals, such as mice
  and pointing devices, do not ordinarily carry information that need to be
  protected, modification of communications with these wireless peripherals may
  be used to compromise the RHEL 8 operating system. Communication paths outside
  the physical protection of a controlled boundary are exposed to the possibility
  of interception and modification.

      Protecting the confidentiality and integrity of communications with
  wireless peripherals can be accomplished by physical means (e.g., employing
  physical barriers to wireless radio frequencies) or by logical means (e.g.,
  employing cryptographic techniques). If physical means of protection are
  employed, then logical means (cryptography) do not have to be employed, and
  vice versa. If the wireless peripheral is only passing telemetry data,
  encryption of the data may not be required.
    "
  end


  control 'SV-237640' do
    desc  "Unapproved mechanisms that are used for authentication to the
  cryptographic module are not verified and therefore cannot be relied upon to
  provide confidentiality or integrity, and CMS data may be compromised.

      RHEL 8 systems utilizing encryption are required to use FIPS-compliant
  mechanisms for authenticating to cryptographic modules.

      Currently, Kerberos does not utilize FIPS 140-2 cryptography.

      FIPS 140-2 is the current standard for validating that mechanisms used to
  access cryptographic modules utilize authentication that meets CMS
  requirements. 
    "
  end


  control "SV-237643" do
      impact 0.0
      desc 'caveat', 'This is Not Applicable since the related security control (IA-11) is not included in CMS ARS 3.1'
  end

  control 'SV-244524' do
    desc  "Unapproved mechanisms that are used for authentication to the
  cryptographic module are not verified and therefore cannot be relied upon to
  provide confidentiality or integrity, and CMS data may be compromised.

      RHEL 8 systems utilizing encryption are required to use FIPS-compliant
  mechanisms for authenticating to cryptographic modules.

      FIPS 140-2 is the current standard for validating that mechanisms used to
  access cryptographic modules utilize authentication that meets CMS
  requirements.
    "
  end



  control 'SV-244525' do
    desc  'check', "
      Verify all network connections associated with SSH traffic are
  automatically terminated at the end of the session or after 30 minutes of
  inactivity.

      Check that the \"ClientAliveInterval\" variable is set to a value of
  \"1800\" or less by performing the following command:

      $ sudo grep -i clientalive /etc/ssh/sshd_config

      ClientAliveInterval 1800
      ClientAliveCountMax 0

      If \"ClientAliveInterval\" does not exist, does not have a value of \"1800\"
  or less in \"/etc/ssh/sshd_config\", or is commented out, this is a finding.
    "
    desc  'fix', "
      Configure RHEL 8 to automatically terminate all network connections
  associated with SSH traffic at the end of a session or after 30 minutes of
  inactivity.

      Modify or append the following lines in the \"/etc/ssh/sshd_config\" file:

      ClientAliveInterval 1800

      In order for the changes to take effect, the SSH daemon must be restarted.

      $ sudo systemctl restart sshd.service
    "


    if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
      impact 0.0
      describe "Control not applicable - SSH is not installed within containerized RHEL" do
        skip "Control not applicable - SSH is not installed within containerized RHEL"
      end
    else
      describe sshd_config do
        its('ClientAliveInterval') { should cmp <= '1800' }
      end
    end
  end



  control 'SV-244526' do
    desc  "Without cryptographic integrity protections, information can be
  altered by unauthorized users without detection.

      Remote access (e.g., RDP) is access to CMS nonpublic information systems by
  an authorized user (or an information system) communicating through an
  external, non-organization-controlled network. Remote access methods include,
  for example, dial-up, broadband, and wireless.

      Cryptographic mechanisms used for protecting the integrity of information
  include, for example, signed hash functions using asymmetric cryptography
  enabling distribution of the public key to verify the hash information while
  maintaining the confidentiality of the secret key used to generate the hash.

      RHEL 8 incorporates system-wide crypto policies by default. The SSH
  configuration file has no effect on the ciphers, MACs, or algorithms unless
  specifically defined in the /etc/sysconfig/sshd file. The employed algorithms
  can be viewed in the /etc/crypto-policies/back-ends/ directory.


    "
  end

  control "SV-244543" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable since the related security control (AU-5 (1)) is not applied to this system categorization in CMS ARS 3.1'
  end


  control 'SV-244544' do
    desc  "\"Firewalld\" provides an easy and effective way to block/limit remote
  access to the system via ports, services, and protocols.

      Remote access services, such as those providing remote access to network
  devices and information systems, which lack automated control capabilities,
  increase risk and make remote user access management difficult at best.

      Remote access is access to CMS nonpublic information systems by an
  authorized user (or an information system) communicating through an external,
  non-organization-controlled network. Remote access methods include, for
  example, dial-up, broadband, and wireless.
      RHEL 8 functionality (e.g., RDP) must be capable of taking enforcement
  action if the audit reveals unauthorized activity. Automated control of remote
  access sessions allows organizations to ensure ongoing compliance with remote
  access policies by enforcing connection rules of remote access applications on
  a variety of information system components (e.g., servers, workstations,
  notebook computers, smartphones, and tablets).
    "
  end

end
