control 'AODH001' do
  impact 1.0
  title 'aodh conf files should have correct ownership, group, and mode'
  desc 'The aodh conf files should have correct ownership, group, and modes'
  tag 'controller', 'ceilometer', 'aodh'
  tag remediation: 'ursula <env> site.yml --tags=aodh'
  files = ['aodh.conf', 'api_paste.ini', 'policy.json']
  files.each each do |file|
    describe file("/etc/aodh/#{file}") do
      its('mode') { should cmp '0640' }
      its('owner') { should eq 'aodh' }
      its('group') { should eq 'aodh' }
    end
  end
end

control "AODH002" do
  impact 1.0
  tag 'controller', 'ceilometer', 'aodh'
  title "aodh log files should have correct mode and ownership"
  desc 'The aodh log files should have the correct mode and ownership'
  tag remediation: 'ursula <env> site.yml --tags=aodh'
  files = ['aodh-api.log', 'aodh-evaluator.log', 'aodh-listener.log', 'aodh-notifier.log']
  files.each do |file|
    describe file("/var/log/aodh/#{file}") do
      its('mode') { should cmp '0644' }
      its('owner') { should eq 'aodh' }
    end
  end
end

control "AODH003" do
  impact 1.0
  title "aodh process should be running under the aodh user"
  desc "aodh process should be running under the aodh user"
  tag 'controller', 'ceilometer', 'aodh'
  tag remediation: 'ursula <env> site.yml --tags=aodh'
  processes = ['aodh-api',
    'aodh-evaluator',
    'aodh-listener',
    'aodh-notifier']
  processes.each do |process|
    describe processes(process) do
      its('users') { should eq ['rabbitmq'] }
    end
  end
end

control "AODH004" do
  impact 1.0
  title "aodh conf variables compliance"
  desc "aodh conf variables should be secure"
  tag 'controller', 'ceilometer', 'aodh'
  tag remediation: 'ursula <env> site.yml --tags=aodh'
  describe ini('/etc/aodh/aodh.conf') do
    its('debug') { should be_nil.or cmp "False" }
    its('log_dir') { should cmp "/var/log/aodh" }
  end
end
