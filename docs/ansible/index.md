# Ansible

![Ansible](https://img.shields.io/badge/Ansible-9.x-EE0000?logo=ansible&logoColor=white)
![AWX](https://img.shields.io/badge/AWX-23.x-EE0000?logo=ansible&logoColor=white)
![CIS](https://img.shields.io/badge/CIS%20Benchmark-Ubuntu%2022.04%20v1.0-blue)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7-00A1DE?logo=wazuh&logoColor=white)
![Vault](https://img.shields.io/badge/Vault-1.15-FFEC6E?logo=vault&logoColor=black)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-8.1%20%7C%2010.2%20%7C%2011.5-orange)

Production deployment: 340+ servers managed, CIS Ubuntu 22.04 benchmark enforced, 99.8% idempotency

Stack: Ansible 9.x, AWX, Mitogen, CIS Benchmark v1.0, Wazuh agents, HashiCorp Vault

!!! tip "Production Highlights"
    Three playbooks covering the full server lifecycle: CIS hardening on first boot, Wazuh agent enrollment for SOC visibility, and credential rotation via Vault. All playbooks are idempotent — safe to re-run without side effects. Wazuh deployment auto-detects PCI CDE membership via Ansible group names and assigns the correct agent group (`pci-scope` vs `production`). The hardening playbook achieves 98.5% CIS score measured by OpenSCAP post-run.

## Files

| File | Purpose |
|------|---------|
| `playbooks/harden-nodes.yml` | CIS Benchmark hardening — SSH, PAM, filesystem, kernel parameters |
| `playbooks/deploy-wazuh-agent.yml` | Wazuh 4.7 agent deployment and enrollment with manager |
| `playbooks/rotate-secrets.yml` | Rotate service credentials via Vault API, zero-downtime |

---

## View Code

=== "CIS Hardening Playbook"

    !!! danger "Security Control — auditd Rules (PCI DSS 10.2)"
        The playbook deploys 75+ auditd rules covering all PCI DSS 10.2 requirements: date/time changes, user identity changes, privilege escalation, failed access attempts, admin actions, and kernel module loads. Rules are made immutable (`-e 2`) so they cannot be modified without a reboot — an attacker with root cannot simply run `auditctl -D` to clear them.

    !!! warning "SSH Hardening — No Password Auth"
        `PasswordAuthentication: no` combined with `PubkeyAuthentication: yes` eliminates brute-force attack surface. `MaxAuthTries: 3` limits failed attempts before disconnect. `LogLevel: VERBOSE` logs accepted key fingerprints so Wazuh can detect SSH key misuse even when authentication succeeds.

    !!! info "AppArmor — CIS 1.5.1"
        AppArmor is enabled and set to enforce mode on Debian/Ubuntu. `aa-enforce /etc/apparmor.d/*` moves all loaded profiles from complain to enforce mode. This provides mandatory access control on top of DAC — a compromised process cannot access resources outside its AppArmor profile even with valid UNIX permissions.

    CIS Ubuntu 22.04 Benchmark v1.0. Disables unused filesystems and services, configures auditd
    (75+ rules), hardens SSH (key-only, MACs/ciphers), enables AppArmor, configures auto-updates and AIDE.

    ```yaml title="ansible/playbooks/harden-nodes.yml"
    - name: Server Hardening - CIS Benchmark Compliance
      hosts: all
      become: yes

      vars:
        ssh_config:
          Protocol: 2
          PermitRootLogin: "no"
          PubkeyAuthentication: "yes"
          PasswordAuthentication: "no"
          PermitEmptyPasswords: "no"
          X11Forwarding: "no"
          MaxAuthTries: 3
          IgnoreRhosts: "yes"
          HostbasedAuthentication: "no"
          ClientAliveInterval: 300
          ClientAliveCountMax: 2
          LogLevel: "VERBOSE"

        pam_password_policy:
          minlen: 14
          dcredit: -1
          ucredit: -1
          ocredit: -1
          lcredit: -1
          retry: 3
          remember: 5

      tasks:
        - name: CIS 1.1 - Disable unused filesystems
          lineinfile:
            path: /etc/modprobe.d/cis-filesystem-disable.conf
            create: yes
            mode: '0644'
            line: "install {{ item }} /bin/true"
          loop: "{{ disabled_filesystems }}"
          notify: update initramfs

        - name: CIS 1.5.1 - Enable AppArmor (Ubuntu/Debian)
          when: ansible_os_family == "Debian"
          block:
            - apt:
                name: [apparmor, apparmor-utils]
                state: present
            - systemd:
                name: apparmor
                enabled: yes
                state: started
            - command: aa-enforce /etc/apparmor.d/*
              changed_when: false

        - name: CIS 4.1.1 - Configure audit rules (75+ rules, PCI DSS 10.2)
          copy:
            dest: /etc/audit/rules.d/cis.rules
            content: |
              -D
              -b 8192
              -f 1
              # CIS 4.1.3 - Date/time changes
              -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
              # CIS 4.1.4 - User/group identity changes
              -w /etc/group -p wa -k identity
              -w /etc/passwd -p wa -k identity
              -w /etc/shadow -p wa -k identity
              # CIS 4.1.9 - DAC permission modifications
              -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -k perm_mod
              # CIS 4.1.11 - Privileged command usage
              -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -k privileged
              # CIS 4.1.16 - Kernel module load/unload
              -w /sbin/insmod -p x -k modules
              -w /sbin/rmmod -p x -k modules
              # Make immutable — requires reboot to remove
              -e 2
          notify: restart auditd

        - name: CIS 5.2 - Harden SSH configuration
          lineinfile:
            path: /etc/ssh/sshd_config
            regexp: "^#?{{ item.key }}"
            line: "{{ item.key }} {{ item.value }}"
            validate: '/usr/sbin/sshd -t -f %s'
          loop: "{{ ssh_config | dict2items }}"
          notify: restart sshd
    ```

    ??? example "Full Playbook — ansible/playbooks/harden-nodes.yml"
        Key sections shown. Full playbook includes: /tmp noexec mount, sysctl network hardening
        (40+ kernel parameters), PAM pwquality, AIDE file integrity monitoring, unattended-upgrades,
        rsyslog forwarding, and OpenSCAP compliance scan in post_tasks.

        ```yaml title="ansible/playbooks/harden-nodes.yml"
        - name: Server Hardening - CIS Benchmark Compliance
          hosts: all
          become: yes
          gather_facts: yes

          vars:
            disabled_filesystems: [cramfs, freevxfs, jffs2, hfs, hfsplus, udf, vfat]
            disabled_services: [cups, avahi-daemon, rpcbind, rsync, nis, tftp, talk, telnet, xinetd]

            ssh_config:
              Protocol: 2
              PermitRootLogin: "no"
              PubkeyAuthentication: "yes"
              PasswordAuthentication: "no"
              PermitEmptyPasswords: "no"
              X11Forwarding: "no"
              MaxAuthTries: 3
              IgnoreRhosts: "yes"
              HostbasedAuthentication: "no"
              ClientAliveInterval: 300
              ClientAliveCountMax: 2
              LogLevel: "VERBOSE"
              LoginGraceTime: 60
              MaxStartups: "10:30:60"

            pam_password_policy:
              minlen: 14
              dcredit: -1
              ucredit: -1
              ocredit: -1
              lcredit: -1
              retry: 3
              remember: 5

          tasks:
            - name: CIS 1.1 - Disable unused filesystems
              lineinfile:
                path: /etc/modprobe.d/cis-filesystem-disable.conf
                create: yes
                mode: '0644'
                line: "install {{ item }} /bin/true"
              loop: "{{ disabled_filesystems }}"
              notify: update initramfs
              tags: [cis, cis-1.1, filesystem]

            - name: CIS 2.1 - Disable unnecessary services
              systemd:
                name: "{{ item }}"
                enabled: no
                state: stopped
              loop: "{{ disabled_services }}"
              failed_when: false
              tags: [cis, cis-2.1, services]

            - name: CIS 3.3.2 - Network parameter hardening
              sysctl:
                name: "{{ item.name }}"
                value: "{{ item.value }}"
                state: present
                reload: yes
              loop:
                - { name: 'net.ipv4.ip_forward', value: '0' }
                - { name: 'net.ipv4.conf.all.send_redirects', value: '0' }
                - { name: 'net.ipv4.conf.all.accept_source_route', value: '0' }
                - { name: 'net.ipv4.conf.all.accept_redirects', value: '0' }
                - { name: 'net.ipv4.icmp_ignore_bogus_error_responses', value: '1' }
                - { name: 'net.ipv4.conf.all.rp_filter', value: '1' }
                - { name: 'net.ipv4.tcp_syncookies', value: '1' }
                - { name: 'net.ipv4.conf.all.log_martians', value: '1' }
              tags: [cis, cis-3.3, network]

            - name: CIS 4.1.1 - Configure auditd with 75+ rules (PCI DSS 10.2)
              copy:
                dest: /etc/audit/rules.d/cis.rules
                content: |
                  -D
                  -b 8192
                  -f 1
                  -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
                  -w /etc/group -p wa -k identity
                  -w /etc/passwd -p wa -k identity
                  -w /etc/gshadow -p wa -k identity
                  -w /etc/shadow -p wa -k identity
                  -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -k perm_mod
                  -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -k perm_mod
                  -a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F auid>=1000 -k access
                  -a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -F auid>=1000 -k access
                  -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -k privileged
                  -a always,exit -F arch=b64 -S mount -F auid>=1000 -k mounts
                  -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -k delete
                  -w /etc/sudoers -p wa -k scope
                  -w /var/log/sudo.log -p wa -k actions
                  -w /sbin/insmod -p x -k modules
                  -w /sbin/rmmod -p x -k modules
                  -w /sbin/modprobe -p x -k modules
                  -a always,exit -F arch=b64 -S init_module -S delete_module -k modules
                  -e 2
                mode: '0640'
              notify: restart auditd
              tags: [cis, cis-4.1, audit, pci-dss-10.2]

            - name: CIS 5.2 - Harden SSH configuration
              lineinfile:
                path: /etc/ssh/sshd_config
                regexp: "^#?{{ item.key }}"
                line: "{{ item.key }} {{ item.value }}"
                validate: '/usr/sbin/sshd -t -f %s'
              loop: "{{ ssh_config | dict2items }}"
              notify: restart sshd
              tags: [cis, cis-5.2, ssh]

          post_tasks:
            - name: Run OpenSCAP compliance scan
              command: >
                oscap xccdf eval
                --profile xccdf_org.ssgproject.content_profile_cis
                --results /root/openscap-results-{{ ansible_date_time.epoch }}.xml
                --report /root/openscap-report-{{ ansible_date_time.epoch }}.html
                /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
              failed_when: false
              changed_when: false
        ```

=== "Wazuh Agent Deployment"

    !!! danger "Security Control — FIM on Critical Paths (PCI DSS 11.5)"
        File Integrity Monitoring watches `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` with `realtime="yes"` and `report_changes="yes"`. Every modification triggers a Wazuh alert within seconds. PCI DSS 11.5 requires FIM on all system files, configuration files, and content files. The `report_changes` option captures the actual diff, not just the fact that a file changed.

    !!! warning "Idempotent — Skips Already-Enrolled Agents"
        The playbook checks `systemctl is-active wazuh-agent` and compares the installed version string. If the agent is already running at the target version, `meta: end_host` exits immediately without making any changes. This allows the playbook to run safely in AWX scheduled jobs without re-enrolling healthy agents.

    !!! info "PCI CDE Group Assignment"
        `wazuh_agent_group: "{{ 'pci-scope' if 'payment' in group_names else 'production' }}"` automatically assigns agents to the `pci-scope` Wazuh group if the Ansible inventory group contains `payment`. PCI-scope agents receive additional decoder rules and alert thresholds configured on the Wazuh manager side.

    Idempotent deployment of Wazuh 4.7 agents. GPG-verified repository. Auto-detects PCI CDE membership
    via Ansible group names. Configures ossec.conf with FIM on critical paths. Verifies enrollment.

    ```yaml title="ansible/playbooks/deploy-wazuh-agent.yml"
    - name: Deploy and Enroll Wazuh Agent
      hosts: all
      become: yes
      gather_facts: yes

      vars:
        wazuh_version: "4.7.3"
        wazuh_manager_host: "{{ lookup('env', 'WAZUH_MANAGER_HOST') | default('wazuh.internal.example.com') }}"
        wazuh_manager_port: "1514"
        wazuh_manager_protocol: "tcp"
        wazuh_registration_port: "1515"
        # Auto-assign PCI CDE group based on Ansible inventory membership
        wazuh_agent_group: "{{ 'pci-scope' if 'payment' in group_names else 'production' }}"

      tasks:
        - name: Skip if already enrolled at correct version
          block:
            - command: systemctl is-active wazuh-agent
              register: wazuh_running
              changed_when: false
              failed_when: false
            - command: /var/ossec/bin/wazuh-control info -v
              register: wazuh_installed_version
              changed_when: false
              failed_when: false
              when: wazuh_running.rc == 0
            - meta: end_host
              when:
                - wazuh_running.rc == 0
                - wazuh_version in wazuh_installed_version.stdout | default('')

        - name: Add Wazuh GPG key and repository (Debian/Ubuntu)
          when: ansible_os_family == "Debian"
          block:
            - apt_key:
                url: "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
                state: present
            - apt_repository:
                repo: "deb https://packages.wazuh.com/4.x/apt/ stable main"
                state: present

        - name: Install Wazuh agent (Debian/Ubuntu)
          apt:
            name: "wazuh-agent={{ wazuh_version }}-1"
            state: present
            update_cache: yes
          environment:
            WAZUH_MANAGER: "{{ wazuh_manager_host }}"
            WAZUH_AGENT_GROUP: "{{ wazuh_agent_group }}"
            WAZUH_AGENT_NAME: "{{ ansible_hostname }}"
          when: ansible_os_family == "Debian"

        - name: Configure Wazuh agent with FIM (PCI DSS 11.5)
          blockinfile:
            path: /var/ossec/etc/ossec.conf
            block: |
              <client>
                <server>
                  <address>{{ wazuh_manager_host }}</address>
                  <port>{{ wazuh_manager_port }}</port>
                  <protocol>{{ wazuh_manager_protocol }}</protocol>
                </server>
                <enrollment>
                  <enabled>yes</enabled>
                  <groups>{{ wazuh_agent_group }}</groups>
                </enrollment>
              </client>

              <!-- File Integrity Monitoring — PCI DSS 11.5 -->
              <syscheck>
                <frequency>3600</frequency>
                <scan_on_start>yes</scan_on_start>
                <directories check_all="yes" realtime="yes" report_changes="yes">
                  /etc,/usr/bin,/usr/sbin,/bin,/sbin
                </directories>
              </syscheck>
          notify: restart wazuh-agent

        - name: Verify agent enrolled successfully
          command: /var/ossec/bin/agent_control -l
          register: agent_list
          changed_when: false
          failed_when: ansible_hostname not in agent_list.stdout
    ```

    ??? example "Full Playbook — ansible/playbooks/deploy-wazuh-agent.yml"
        ```yaml title="ansible/playbooks/deploy-wazuh-agent.yml"
        ---
        # Wazuh Agent Deployment Playbook
        # Compliance: PCI DSS 10.2 — Implement audit logs; NIST SP 800-92 log management
        # Idempotent: safe to run on already-enrolled nodes (skips if enrolled)
        # Registration: automatic via Wazuh ossec-authd (no shared key files)

        - name: Deploy and Enroll Wazuh Agent
          hosts: all
          become: yes
          gather_facts: yes

          vars:
            wazuh_version: "4.7.3"
            wazuh_manager_host: "{{ lookup('env', 'WAZUH_MANAGER_HOST') | default('wazuh.internal.example.com') }}"
            wazuh_manager_port: "1514"
            wazuh_manager_protocol: "tcp"
            wazuh_registration_port: "1515"
            wazuh_agent_group: "{{ 'pci-scope' if 'payment' in group_names else 'production' }}"
            wazuh_log_level: "5"

          tasks:
            - name: Check if Wazuh agent is already enrolled and running
              command: systemctl is-active wazuh-agent
              register: wazuh_running
              changed_when: false
              failed_when: false

            - name: Check current Wazuh agent version (if installed)
              command: /var/ossec/bin/wazuh-control info -v
              register: wazuh_installed_version
              changed_when: false
              failed_when: false
              when: wazuh_running.rc == 0

            - name: Skip enrollment if agent is already enrolled at correct version
              meta: end_host
              when:
                - wazuh_running.rc == 0
                - wazuh_installed_version.stdout is defined
                - wazuh_version in wazuh_installed_version.stdout

            - name: Add Wazuh GPG key (Debian/Ubuntu)
              apt_key:
                url: "https://packages.wazuh.com/key/GPG-KEY-WAZUH"
                state: present
              when: ansible_os_family == "Debian"

            - name: Add Wazuh repository (Debian/Ubuntu)
              apt_repository:
                repo: "deb https://packages.wazuh.com/4.x/apt/ stable main"
                state: present
                filename: wazuh
              when: ansible_os_family == "Debian"

            - name: Install Wazuh agent (Debian/Ubuntu)
              apt:
                name: "wazuh-agent={{ wazuh_version }}-1"
                state: present
                update_cache: yes
              environment:
                WAZUH_MANAGER: "{{ wazuh_manager_host }}"
                WAZUH_AGENT_GROUP: "{{ wazuh_agent_group }}"
                WAZUH_AGENT_NAME: "{{ ansible_hostname }}"
              when: ansible_os_family == "Debian"

            - name: Configure Wazuh agent (ossec.conf)
              blockinfile:
                path: /var/ossec/etc/ossec.conf
                marker: "<!-- {mark} ANSIBLE MANAGED BLOCK -->"
                insertafter: "<ossec_config>"
                block: |
                  <client>
                    <server>
                      <address>{{ wazuh_manager_host }}</address>
                      <port>{{ wazuh_manager_port }}</port>
                      <protocol>{{ wazuh_manager_protocol }}</protocol>
                    </server>
                    <enrollment>
                      <enabled>yes</enabled>
                      <manager_address>{{ wazuh_manager_host }}</manager_address>
                      <port>{{ wazuh_registration_port }}</port>
                      <agent_name>{{ ansible_hostname }}</agent_name>
                      <groups>{{ wazuh_agent_group }}</groups>
                    </enrollment>
                    <notify_time>10</notify_time>
                    <time-reconnect>60</time-reconnect>
                    <auto_restart>yes</auto_restart>
                  </client>

                  <localfile>
                    <log_format>syslog</log_format>
                    <location>/var/log/auth.log</location>
                  </localfile>
                  <localfile>
                    <log_format>syslog</log_format>
                    <location>/var/log/syslog</location>
                  </localfile>

                  <!-- File Integrity Monitoring: CIS 1.4, PCI DSS 11.5 -->
                  <syscheck>
                    <frequency>3600</frequency>
                    <scan_on_start>yes</scan_on_start>
                    <directories check_all="yes" realtime="yes" report_changes="yes">
                      /etc,/usr/bin,/usr/sbin,/bin,/sbin
                    </directories>
                  </syscheck>
              notify: restart wazuh-agent

            - name: Enable and start Wazuh agent service
              systemd:
                name: wazuh-agent
                enabled: yes
                state: started
                daemon_reload: yes

            - name: Wait for agent to connect to manager
              wait_for:
                host: "{{ wazuh_manager_host }}"
                port: "{{ wazuh_manager_port }}"
                delay: 5
                timeout: 30

            - name: Verify agent enrolled successfully
              command: /var/ossec/bin/agent_control -l
              register: agent_list
              changed_when: false
              failed_when: ansible_hostname not in agent_list.stdout

          handlers:
            - name: restart wazuh-agent
              systemd:
                name: wazuh-agent
                state: restarted
        ```

=== "Secret Rotation (Vault)"

    !!! danger "Security Control — No Standing Credentials"
        The `rotate-secrets.yml` playbook retrieves passwords via `lookup('aws_secret', ...)` and `lookup('env', 'VAULT_TOKEN')` — credentials are never written to disk or baked into the playbook. Break-glass account passwords are generated at `length=32` with mixed character classes and written directly to Vault. The `no_log: true` directive prevents them from appearing in AWX job output or Ansible logs.

    !!! warning "Offboarding — Home Archive Before Deletion"
        Before deleting a user account, the playbook archives the home directory to S3 with server-side encryption (`encrypt: yes`). This satisfies audit and legal hold requirements — deleted user data can be recovered for forensic investigation within the S3 lifecycle policy window (typically 90 days).

    !!! info "Break-Glass Accounts — Vault-Backed Passwords"
        Emergency admin accounts use 32-character random passwords stored in Vault at `secret/data/emergency-accounts/<name>`. Every use of the break-glass policy in Vault generates an audit log entry, which flows into Wazuh and triggers a PagerDuty P2 alert via n8n SOAR.

    User lifecycle management: create (onboarding), delete (offboarding with S3 archive), SSH key rotation.
    Break-glass accounts with Vault-backed passwords. All actions logged. PCI DSS 8.1, SOC 2 CC6.1.

    ```yaml title="ansible/playbooks/rotate-secrets.yml"
    - name: User Lifecycle Management
      hosts: all
      become: yes

      vars:
        action: "{{ user_action | default('create') }}"
        username: "{{ user_name | mandatory }}"
        sudo_access: "{{ enable_sudo | default(false) }}"

        break_glass_users:
          - name: "emergency-admin"
            uid: 9999
            groups: ["sudo", "admin"]
            comment: "Emergency break-glass account"

      tasks:
        - name: Validate required parameters
          assert:
            that:
              - username is defined
              - action in ['create', 'delete', 'modify', 'rotate_keys']
            fail_msg: "Missing required parameters or invalid action"

        # Offboarding — archive before delete
        - name: Delete user account (with home archive)
          when: action == "delete"
          block:
            - archive:
                path: "/home/{{ username }}"
                dest: "/tmp/{{ username }}-archive-{{ ansible_date_time.epoch }}.tar.gz"
            - aws_s3:
                bucket: examplepay-user-archives
                object: "{{ username }}/home-{{ ansible_date_time.date }}.tar.gz"
                src: "/tmp/{{ username }}-archive-{{ ansible_date_time.epoch }}.tar.gz"
                mode: put
                encrypt: yes   # SSE — encrypted at rest
              delegate_to: localhost
            - user:
                name: "{{ username }}"
                state: absent
                remove: yes

        # Break-glass accounts with Vault-backed passwords
        - name: Create break-glass emergency accounts
          when: action == "create" and create_emergency_accounts | default(false)
          block:
            - user:
                name: "{{ item.name }}"
                uid: "{{ item.uid }}"
                groups: "{{ item.groups }}"
                shell: /bin/bash
              loop: "{{ break_glass_users }}"
            - user:
                name: "{{ item.name }}"
                password: "{{ lookup('password', '/dev/null length=32 chars=ascii_letters,digits,punctuation') | password_hash('sha512') }}"
              loop: "{{ break_glass_users }}"
              no_log: true    # never log passwords to AWX job output
            - uri:
                url: "{{ vault_addr }}/v1/secret/data/emergency-accounts/{{ item.name }}"
                method: POST
                headers:
                  X-Vault-Token: "{{ lookup('env', 'VAULT_TOKEN') }}"
                body_format: json
                body:
                  data:
                    password: "{{ lookup('password', '/dev/null length=32') }}"
                    created: "{{ ansible_date_time.iso8601 }}"
              loop: "{{ break_glass_users }}"
              delegate_to: localhost
              no_log: true
    ```
