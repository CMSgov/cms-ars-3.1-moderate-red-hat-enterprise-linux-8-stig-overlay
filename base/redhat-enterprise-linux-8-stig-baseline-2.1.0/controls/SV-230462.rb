control 'SV-230462' do
  title "Successful/unsuccessful uses of the sudo command in RHEL 8 must
generate an audit record."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The \"sudo\" command allows
a permitted user to execute a command as the superuser or another user, as
specified by the security policy.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
\"-1\". The AUID representation is an unsigned 32-bit integer, which equals
\"4294967295\". The audit system interprets \"-1\", \"4294967295\", and
\"unset\" in the same way.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify that an audit event is generated for any successful/unsuccessful use
of the \"sudo\" command by performing the following command to check the file
system rules in \"/etc/audit/audit.rules\":

    $ sudo grep -w sudo /etc/audit/audit.rules

    -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset
-k priv_cmd

    If the command does not return a line, or the line is commented out, this
is a finding.
  "
  desc 'fix', "
    Configure the audit system to generate an audit event for any
successful/unsuccessful use of the \"sudo\" command by adding or updating the
following rule in the \"/etc/audit/rules.d/audit.rules\" file:

    -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset
-k priv_cmd

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: %w(SRG-OS-000062-GPOS-00031 SRG-OS-000037-GPOS-00015
                    SRG-OS-000042-GPOS-00020 SRG-OS-000062-GPOS-00031
                    SRG-OS-000392-GPOS-00172 SRG-OS-000462-GPOS-00206
                    SRG-OS-000471-GPOS-00215 SRG-OS-000466-GPOS-00210)
  tag gid: 'V-230462'
  tag rid: 'SV-230462r627750_rule'
  tag stig_id: 'RHEL-08-030550'
  tag fix_id: 'F-33106r568133_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  audit_file = '/usr/bin/sudo'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe auditd.file(audit_file) do
      its('permissions.flatten') { should include 'x' }
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('fields.flatten') { should include 'auid>=1000' }
      its('fields.flatten') { should include 'auid!=-1' }
      its('key.uniq') { should cmp 'priv_cmd' }
    end
  end
end