# PowerShell Core

<!-- TOC -->

- [PowerShell Core](#powershell-core)
    - [VMs](#vms)
    - [Demo](#demo)
        - [Windows (Server 2016 VM)](#windows-server-2016-vm)
            - [Install Windows Server](#install-windows-server)
            - [Setting up WinRM for PS Remoting](#setting-up-winrm-for-ps-remoting)
            - [WindowsCompatibility Module for Missing Commands](#windowscompatibility-module-for-missing-commands)
            - [Setting up OpenSSH for PS Remoting (Windows)](#setting-up-openssh-for-ps-remoting-windows)
            - [Markdown and Web Cmdlets](#markdown-and-web-cmdlets)
            - [Extras Not in This Demo (Windows)](#extras-not-in-this-demo-windows)
        - [Linux (Ubuntu VM)](#linux-ubuntu-vm)
            - [Install Ubuntu](#install-ubuntu)
            - [Setting up OpenSSH for PS Remoting (Linux)](#setting-up-openssh-for-ps-remoting-linux)
            - [Extras Not in This Demo (Linux)](#extras-not-in-this-demo-linux)
    - [Links and Resources](#links-and-resources)

<!-- /TOC -->

## VMs

Prerequisites.

| Machine | Username | Password | OS |
| --- | --- | --- | --- |
| ubuntu | rjp | Password1 | Ubuntu Server 18.04.1 |
| windows | rjp | Password1 | Windows Server 2016 , Semi Annual 1803 |

## Demo

Before I start.

```powershell
# When running through the demo and rolling back snapshots the local_hosts will be aware of the pre snapshot key
# If you get "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" This will fix it.
Remove-Item -Path $env:USERPROFILE\.ssh\known_hosts
```

### Windows (Server 2016 VM)

#### Install Windows Server

Currently there is no way built into Windows to install PowerShell Core.  Your options are manual install or... that's it, just manuall install.  You can install by downloading the MSI and running through the GUI install, or installing via the command line.

This example is on Windows Server and assumes there is no GUI installed.

First we'll open a PSSession to Windows PowerShell on the remote server.

```powershell
Enter-PSSession -ComputerName windows -Credential (Get-Credential)
```

Now that we're on the remote system we'll download and install PowerShell Core.

```powershell
# Download the file.
Invoke-WebRequest -Uri 'https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x64.msi' -OutFile 'PowerShell-6.1.0-win-x64.msi' #Will throw a TLS error.

# Github requires TLS1.2, however Windows PowerShell 5.1 Invoke-WebRequest and Invoke-RestMethod use TLS1.0, you need to force the session to use TLS1.2, this only lasts the one session.
# +1 point for PowerShell Core, it uses TLS1.2 by default!
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Download the file for real this time.
Invoke-WebRequest -Uri 'https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/PowerShell-6.1.0-win-x64.msi' -OutFile 'PowerShell-6.1.0-win-x64.msi'

# Verify download integrity 64 Bit MSI (E67A1460C3D24C52B1DE30DAECBCE7ED7BAAC62DCEF8A862D2FCADC31A9B4239)
Get-FileHash -Path '.\PowerShell-6.1.0-win-x64.msi' -Algorithm SHA256 | Tee-Object -Variable pwshCheckSum
$pwshCheckSum.Hash -eq 'E67A1460C3D24C52B1DE30DAECBCE7ED7BAAC62DCEF8A862D2FCADC31A9B4239'

# Install PowerShell Core (could call msiexec and arguments with Start-Process if you want)
Start-Process -FilePath 'msiexec.exe' -NoNewWindow -ArgumentList @('/i', 'PowerShell-6.1.0-win-x64.msi', '/qn', '/L*e', '.\pwsh.log') -Wait

# Exit
exit
```

**NOTE**: Due to pwsh being added to the path it won't be avialable until you restart your PowerShell session!
We'll open a new session with the update PATH environment variable.

```powershell
Enter-PSSession -ComputerName windows -Credential (Get-Credential)
```

#### Setting up WinRM for PS Remoting

Now PowerShell Core is installed, but there are some catches.  First and foremost being WsMan PS Remoting.

```powershell
# PSSession still defaults to powershell.exe / Windows PowerShell 5.1
pwsh
$PSVersionTable

# We can see that PowerShell core installed
pwsh -c {$PSVersiontable}

# To be able to PSSession into PowerShell core via WinRM we need to run Install-PowerShellRemoting.ps1 in $PSHome
# You could do login and switch to pwsh as your shell to run this but I like to be lazy so we'll run it through our Windows PowerShell PSSession.
# https://docs.microsoft.com/en-us/powershell/scripting/core-powershell/wsman-remoting-in-powershell-core?view=powershell-6
Push-Location -Path 'C:\Program Files\PowerShell\6\'
.\Install-PowerShellRemoting.ps1 -PowerShellHome "C:\Program Files\PowerShell\6\"

# NOTE: This throws an error when running it remote, it still creates the new endpoints though.  If you run it locally it will not throw an error when creating new endpoints.
# This happens because the WinRM service is restarted.
```

Enter PS Session again to the server to confirm the 2 new endpoints exist.

```powershell
Enter-PSSession -ComputerName windows -Credential (Get-Credential)
```

Check for the new endpoints.

```powershell
# We now have 2 new session configurations.
Get-PSSessionConfiguration

# Exit
exit
```

#### WindowsCompatibility Module for Missing Commands

PS Remote via WinRM into PowerShell Core

```powershell
Enter-PSSession -ComputerName windows -Credential (Get-Credential) -ConfigurationName 'PowerShell.6.1.0'
```

Now in PS Core on the remote server.  Windows compatibility to fill the gaps.

```powershell
# Should be in PS Core 6.1.0
$PSVersionTable

# Notice the missing commands
# Current Windows Server 2016 Cmdlet count out-of-the-box
Get-Command -Module (Get-Module -ListAvailable) | Measure-Object
# vs...
powershell -c {Get-Command -Module (Get-Module -ListAvailable) | Measure-Object}

# Install the WindowsCompatibility module - This module uses implicit remoting to create a session to call the older commands from.
Find-Module -Name WindowsCompatibility | Install-Module -Scope CurrentUser -Force

# Check out its available commands
Get-Command -Module WindowsCompatibility

# We can now see all the Windows specific modules that exist on the system.
Get-WinModule

# Get-Disk doesn't work as its in a module specific to Windows PowerShell (Storage)
Get-Disk

# Import the Storage module
Import-WinModule -Name Storage

# Get-Disk now should work
Get-Disk
```

#### Setting up OpenSSH for PS Remoting (Windows)

PS Remote via WinRM into PowerShell Core

```powershell
Enter-PSSession -ComputerName windows -Credential (Get-Credential) -ConfigurationName 'PowerShell.6.1.0'
```

```powershell
# NOTE: Capabilities cannot be added or interfaced with via a PS Session.
# You can see the latest OpenSSH capabilities.
Get-WindowsCapability -Online | Where-Object {$_.Name -like 'OpenSSH*'} | Add-WindowsCapability

# We're going to get the latest release from Github for this demo.
Invoke-WebRequest -Uri 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/v7.7.2.0p1-Beta/OpenSSH-Win64.zip' -OutFile 'OpenSSH-Win64.zip'

# Extract the files and go into the directory.
# Expand this where you want, as of now this is basically the directory it is installed to.  The services point to this location unless you change it.
Expand-Archive -Path .\OpenSSH-Win64.zip -DestinationPath C:\
Set-Location -Path C:\OpenSSH-Win64

# Run the install
.\install-sshd.ps1

# Note, the services install stopped, more important not that in this method the are registered to the location you epxanded the archive to.
Get-Service -Name ssh* | Select-Object -Property Status,Name,DisplayName,BinaryPathName

# We need to setup an ssh Subsystem, but before we do, one very important note.
# Because of a bug, we need to create a symbolic link to the PowerShell Core install directory, OpenSSH can't handle a path with spaces.
New-Item -ItemType SymbolicLink -Path C:\pwsh -Value $pshome
Get-Item C:\pwsh\ | Select-Object -Property Name,LinkType,Target

# Edit the sshd_config_default file (Will need to be local to use notepad)
notepad sshd_config_default
# Uncomment:    PasswordAuthentication yes
# Add:          Subsystem   powershell  C:\pwsh\pwsh.exe -sshs -NoLogo -NoProfile

# Restart the 'sshd' service.
Restart-Service -Name sshd
Get-Service -Name sshd

# Make sure it is allowed through the firewall
New-NetFirewallRule
Import-WinModule -Name NetSecurity #(Using WindowsCompatibility again!)
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Exit
exit
```

Remote into the system using SSH as the transport.

```powershell
Enter-PSSession -HostName windows -UserName rjp -SSHTransport
```

#### Markdown and Web Cmdlets

Let's look some of the new Markdown Cmdlets in PowerShell Core. (On my machine)  This is an example that outlines a couple of features that are added in PowerShell Core but likely won't get backported to Windows PowerShell.

- New Markdown Cmdlet functionality.
- Web Cmdlets running in TLS1.2 by default.

```powershell
# We'll download the latest change log for PowerShell Core from Github for our example.
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/PowerShell/PowerShell/master/CHANGELOG.md' -OutFile 'PowerShellCore_ChangeLog.md'
# Note how we didn't run into any TLS errors???!!! Cool!

# We have always been able to parse text files, but markdown renders a lot nicer.  We can use the new commands to give it a little syntax highlighting as well.
Get-Content -Path .\PowerShellCore_ChangeLog.md

# Let's have a better experience reading the file.
Show-Markdown -Path .\PowerShellCore_ChangeLog.md
Get-MarkdownOption
Set-MarkdownOption -Header2Color '[4;32m'
Show-Markdown -Path .\PowerShellCore_ChangeLog.md

Show-Markdown -Path .\PowerShellCore_ChangeLog.md -UseBrowser
```

#### Extras Not in This Demo (Windows)

These items are not covered in this demo, reference code below.
Uninstall PowerShell Core from the command line.

```powershell
# Uninstalling PowerShell Core
$uninstall = Get-ChildItem -Path '.\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' | Get-ItemProperty | Where-Object {$_.Displayname -like 'PowerShell 6*'} | Select-Object -ExpandProperty UninstallString

$uninstall
```

### Linux (Ubuntu VM)

#### Install Ubuntu

This example is going to use Ubuntu 18.04.1 Server Linux distribution.  This varies a lot between each distribution, read the [official documentation](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-powershell-core-on-linux?view=powershell-6) for your distribution.

I've picked Ubuntu as it tends to be one of the most common Linux distributions and the easiest to use as well.

This is from the official Microsoft documentation that can be found [here](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-powershell-core-on-linux?view=powershell-6#ubuntu-1804).

```bash
# Check distribution version (may not work on all distributions)
sudo lsb_release -a
sudo uname -a

# Get the deb package containting the install for the Microsoft repository and GPG keys (for anyone unfamiliar with wget, it is a Linux CLI tool for downloading content from a URL)
wget https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb

# Use dpkg to register the Microsoft repository and GPG keys. (dpkg is a low level pacakge tool for Debian and Debian based distributions)
sudo ls /etc/apt/sources.list.d/ # Microsoft repository not yet present
sudo dpkg -i packages-microsoft-prod.deb
sudo cat /etc/apt/sources.list.d/microsoft-prod.list # Microsoft repository should now be present

# NOTE: CURRENT BUG with Ubuntu 18.04.1 - https://github.com/dotnet/core/issues/1822
sudo add-apt-repository universe

# Update the list of products
sudo apt-get update

# Install PowerShell
sudo apt-get install -y powershell
```

Alternatively you can direct download.

```bash
wget https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.ubuntu.18.04_amd64.deb
sudo dpkg -i powershell_6.1.0-1.ubuntu.18.04_amd64.deb
sudo apt-get install -f
```

Now PowerShell Core is installed, we can see what it looks like on a Linux OS.

```powershell
# Start PowerShell
pwsh

# Commands available
Get-Command -Module (Get-Module -ListAvailable) | Measure-Object

# Check out processes
Get-Process
```

#### Setting up OpenSSH for PS Remoting (Linux)

PS Remoting into PowerShell Core on Linux requires a little setup like we had to do on Windows.  This actually tends to be a little easier as Linux OS's are better equipped to handle command line text editing.

```powershell
Enter-PSSession -HostName ubuntu -UserName rjp -SSHTransport
```

This will fail, there is no subsystem setup.  To setup the Subsystem we'll walk through the following.

```powershell
# Install OpenSSH client and server if not done already
sudo apt install openssh-client
sudo apt install openssh-server

# Edit the sshd_config file in /etc/ssh
sudo vim /etc/ssh/sshd_config
# Uncomment:    PasswordAuthentication yes
# Add:          Subsystem   powershell  /usr/bin/pwsh -sshs -NoLogo -NoProfile

# Restart sshd
sudo systemctl restart sshd
```

Now we can remote!

```powershell
Enter-PSSession -HostName ubuntu -UserName rjp -SSHTransport
```

#### Extras Not in This Demo (Linux)

These items are not covered in this demo, reference code below.
Direct install, upgrade, and removal (not covered in this demo).  This example uses Ubuntu 18.04.

```bash
# Upgrade PowerShell
sudo apt-get upgrade powershell

# Direct install of PowerShell
wget -q https://github.com/PowerShell/PowerShell/releases/download/v6.1.0/powershell_6.1.0-1.ubuntu.18.04_amd64.deb #Download the pacakge from the Github releases
sudo dpkg -i powershell_6.1.0-1.ubuntu.18.04_amd64.deb #Install the pacakge (It will fail with unmet dependencies the next command will resolve it)
sudo apt-get install -f #Run apt-get install and fix broken dependencies with -f switch

# Uninstall / Remove PowerShell
sudo apt-get remove powershell
```

## Links and Resources

- [Whats New in PowerShell Core 6.0](https://docs.microsoft.com/en-us/powershell/scripting/whats-new/what-s-new-in-powershell-core-60?view=powershell-6)
- [Whats New in PowerShell Core 6.1](https://docs.microsoft.com/en-us/powershell/scripting/whats-new/what-s-new-in-powershell-core-61?view=powershell-6)
- [Installing PowerShell Core on Windows](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-powershell-core-on-windows?view=powershell-6)
- [Installing PowerShell Core on Linux](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-powershell-core-on-linux?view=powershell-6)
- [Installing PowerShell Core on macOS](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-powershell-core-on-macos?view=powershell-6)
- [WSMAN Remoting with PowerShell Core](https://docs.microsoft.com/en-us/powershell/scripting/core-powershell/wsman-remoting-in-powershell-core?view=powershell-6)
- [OpenSSH Remoting with PowerShell Core](https://docs.microsoft.com/en-us/powershell/scripting/core-powershell/ssh-remoting-in-powershell-core?view=powershell-6)
- [PowerShell Core Support Timeline](https://docs.microsoft.com/en-us/powershell/scripting/powershell-core-support?view=powershell-6)
- [Don Jones "Can We Talk About PowerShell Core 6.0?"](https://powershell.org/2018/01/15/can-we-talk-about-powershell-core-6-0/)
- [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/releases)
- [WinRM on Linux with PSL OMI](https://github.com/PowerShell/psl-omi-provider)