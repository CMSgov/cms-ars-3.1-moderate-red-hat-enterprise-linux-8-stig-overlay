# cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay
**CMS’ ISPG (Information Security and Privacy Group) decided to discontinue funding the customization of MITRE’s Security Automation Framework (SAF) for CMS after September 2023. This repo is now in archive mode, but still accessible. For more information about SAF with current links, see https://security.cms.gov/learn/security-automation-framework-saf**

InSpec profile overlay to validate the secure configuration of Red Hat Enterprise Linux 8 against [DISA's](https://public.cyber.mil/stigs/) Red Hat Enterprise Linux 8 STIG Version 1 Release 3 tailored for [CMS ARS 3.1](https://www.cms.gov/Research-Statistics-Data-and-Systems/CMS-Information-Technology/InformationSecurity/Info-Security-Library-Items/ARS-31-Publication.html) for CMS systems categorized as Moderate.

## Getting Started  
### InSpec (CINC-auditor) setup
For maximum flexibility/accessibility, we’re moving to “cinc-auditor”, the open-source packaged binary version of Chef InSpec, compiled by the CINC (CINC Is Not Chef) project in coordination with Chef using Chef’s always-open-source InSpec source code. For more information: https://cinc.sh/

It is intended and recommended that CINC-auditor and this profile overlay be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.

__For the best security of the runner, always install on the runner the _latest version_ of CINC-auditor.__ 

__The simplest way to install CINC-auditor is to use this command for a UNIX/Linux/MacOS runner platform:__
```
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
```

__or this command for Windows runner platform (Powershell):__
```
. { iwr -useb https://omnitruck.cinc.sh/install.ps1 } | iex; install -project cinc-auditor
```
To confirm successful install of cinc-auditor:
```
cinc-auditor -v
```
> sample output:  _4.24.32_

Latest versions and other installation options are available at https://cinc.sh/start/auditor/.

## Tailoring to Your Environment

The following inputs may be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
# Used by InSpec checks 
# InSpec Tests that are known to consistently have long run times can be disabled with this attribute
# Acceptable values: false, true
# (default: false)
disable_slow_controls: 

# Used by InSpec check 
# list of system files that should be allowed to change from an rpm verify point of view
rpm_verify_perms_except: []

# Used by InSpec check 
# list of system files that should be allowed to change from an rpm verify point of view
rpm_verify_integrity_except: []

# Used by InSpec check (default: false)
# Do NOT set to 'true' UNLESS the server is documented as being used as a log aggregation server. 
log_aggregation_server: false

# Used by InSpec check  (default: [])
# Known application groups that are allowed to have world-writeable files or directories
application_groups: []

# Used by InSpec check (default: false)
# Do NOT set to 'true' UNLESS use of X Windows System is documented and approved. 
x11_enabled: false

# Accounts of known managed users (Array)
user_accounts: []

# System accounts that support approved system activities. (Array) (defaults shown below)
known_system_accounts:
  [
    "root",
    "bin",
    "daemon",
    "adm",
    "lp",
    "sync",
    "shutdown",
    "halt",
    "mail",
    "operator",
    "nobody",
    "systemd-bus-proxy",
  ]

# 
# (enabled or disabled)
smart_card_status: "enabled"

# 
# The path to the logging package
log_pkg_path: "/etc/rsyslog.conf"

# 
# 
# Users exempt from home directory-based controls in array
# format
exempt_home_users: []

# 
# main grub boot config file
grub_main_cfg: "/boot/grub2/grub.cfg"

# superusers for grub boot ( array )
grub_superusers: ["root"]

# grub boot config files
grub_user_boot_files: ["/boot/grub2/user.cfg"]

# 
# superusers for efi boot ( array )
efi_superusers: ["root"]

# efi boot config files
efi_user_boot_files: ["/boot/efi/EFI/redhat/user.cfg"]

# main efi boot config file
efi_main_cfg: "/boot/efi/EFI/redhat/grub.cfg"

# 
# system accounts that support approved system activities
admin_logins: []

# 
# should dconf have smart card authentication (e.g., true or false <- no quotes!)
multifactor_enabled: true

# 
# approved configured tunnels prepended with word 'conn'
# Example: ['conn myTunnel']
approved_tunnels: []

# 
# Is the target expected to be a virtual machine
virtual_machine: false

```

## Running This Overlay Directly from Github

Against a remote target using ssh with escalated privileges (i.e., cinc-auditor installed on a separate runner host)
```bash
cinc-auditor exec https://github.com/CMSgov/cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay/archive/<Release version # or Development "main" branch>.tar.gz -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --sudo --sudo-password=<SUDO_PASSWORD_IF_REQUIRED> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```

Against a remote target using a pem key with escalated privileges (i.e., cinc-auditor installed on a separate runner host)
```bash
cinc-auditor exec https://github.com/CMSgov/cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay/archive/<Release version # or Development "main" branch>.tar.gz -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json>  
```

Against a local Red Hat host with escalated privileges (i.e., cinc-auditor installed on the target)
```bash
sudo cinc-auditor exec https://github.com/CMSgov/cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay/archive/<Release version # or Development "main" branch>.tar.gz --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```
### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Overlay from a local Archive copy
If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.) 

```
mkdir profiles
cd profiles
git clone -b <Release version # or Development "main" branch> https://github.com/CMSgov/cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay.git
cinc-auditor archive cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay
sudo cinc-auditor exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay
git pull
cd ..
cinc-auditor archive cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay --overwrite
sudo cinc-auditor exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.cms.gov/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall2)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Eugene Aronne
* Aaron Lippold

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/CMSgov/cms-ars-3.1-moderate-red-hat-enterprise-linux-8-stig-overlay/issues/new).

### NOTICE

© 2021 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE
DISA STIGs are published by DISA IASE, see: https://public.cyber.mil/stigs/ 
