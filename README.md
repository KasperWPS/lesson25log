# Домашнее задание № 16 по теме: "Сбор и анализ логов". К курсу Administrator Linux. Professional

## Задание

- В Vagrant развернуть 2 виртуальные машины: log и web
  - На web установить и настроить nginx
  - На log настроить центральный лог сервер rsyslog
  - Настроить auditd на сервере web следящий за изменением настроек nginx и отправкой сообщений на сервер log
- Задание со звёздочкой. Развернуть сервер со стэком ELK
  - В ELK должны уходить логи nginx

Для выполнения задания описаны виртуальные машины 'log', 'web' и 'elk':

- config.json
```json
[

        {
                "name": "log",
                "cpus": 2,
                "gui": false,
                "box": "centos/7",
                "ip_addr": "192.168.56.15",
                "memory": 1024,
                "no_share": true
        },
        {
                "name": "web",
                "cpus": 2,
                "gui": false,
                "box": "centos/7",
                "ip_addr": "192.168.56.10",
                "memory": "1024",
                "no_share": true
        },
        {
                "name": "elk",
                "cpus": 2,
                "gui": false,
                "box": "generic/ubuntu1804",
                "ip_addr": "192.168.56.20",
                "memory": "8096",
                "no_share": true,
                "forward_port": "5601"
        }
]
```

*Пояснение к параметрам виртуальной машины: т.к., в моем случае, машина на которой выполняется задание - удаленная, чтобы была возможность обращаться к Kibana - настроен проброс портов (5601:5601) на виртуальном интерфейсе*

- Vagrantfile:
```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby : vsa
Vagrant.require_version ">= 2.0.0"

require 'json'

f = JSON.parse(File.read(File.join(File.dirname(__FILE__), 'config.json')))
# Локальная переменная PATH_SRC для монтирования
$PathSrc = ENV['PATH_SRC'] || "."

Vagrant.configure(2) do |config|
  if Vagrant.has_plugin?("vagrant-vbguest")
    config.vbguest.auto_update = false
  end

  # включить переадресацию агента ssh
  config.ssh.forward_agent = true
  # использовать стандартный для vagrant ключ ssh
  config.ssh.insert_key = false

  f.each do |g|
    config.vm.define g['name'] do |s|
      s.vm.box = g['box']
      s.vm.hostname = g['name']
      s.vm.network 'private_network', ip: g['ip_addr']

      if g['forward_port']
        s.vm.network 'forwarded_port', guest: g['forward_port'], host: g['forward_port']
      end

      s.vm.synced_folder $PathSrc, "/vagrant", disabled: g['no_share']

      s.vm.provider :virtualbox do |virtualbox|
        virtualbox.customize ["modifyvm", :id,
          "--audio", "none",
          "--cpus", g['cpus'],
          "--memory", g['memory'],
          "--graphicscontroller", "VMSVGA",
          "--vram", "64"
        ]
        virtualbox.gui = g['gui']
        virtualbox.name = g['name']
      end
      s.vm.provision "ansible" do |ansible|
        ansible.playbook = "provisioning/playbook.yml"
        ansible.become = "true"
      end
      if g['freboot']
        s.vm.provision "shell", inline: <<-SHELL
          reboot
        SHELL
      end
    end
  end
end
```

Для описания конфигурации виртуальных машин использован provisioner ansible

*На территории РФ требуется подключение VPN*

```bash
vagrant up
```

## Задание 1.

- Настроить часовой пояс

CentOS (log, web)
```bash
cp /usr/share/zoneinfo/Europe/Moscow /etc/localtime
systemctl restart chronyd
```

Ubuntu (ELK)
```bash
timedatectl set-timezone Europe/Moscow
```

- Установить:

CentOS (log, web)
```bash
yum install epel-release -y
yum install mc vim -y
```

CentOS (web):
```bash
yum install nginx -y
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
```

/etc/yum.repos.d/elastic-8.x.repo:
```
[elastic-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
```

```bash
yum install filebeat -y
```

- Конфигурация filebeat (web)

/etc/filebeat/filebeat.yml
```yaml
filebeat.inputs:
- type: log
  id: nginx15-accept
  enabled: true
  paths:
    - /var/log/nginx/*access.log
  fields:
    type: nginx_access
  fields_under_root: true
  scan_frequency: 5s

- type: log
  id: nginx15-error
  enabled: true
  paths:
    - /var/log/nginx/*error.log
  fields:
    type: nginx_error
  fields_under_root: true
  scan_frequency: 5s

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1

output.logstash:
  hosts: ["192.168.56.20:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
```

- Конфигурация nginx:

/etc/nginx/nginx.conf
```
# For more information on configuration, see:
#   * Official English Documentation: http://nginx.org/en/docs/
#   * Official Russian Documentation: http://nginx.org/ru/docs/

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
error_log syslog:server=192.168.56.15:514,tag=nginx_error;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    access_log syslog:server=192.168.56.15:514,tag=nginx_access,severity=info combined;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 4096;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;

    server {
        listen       80;
        listen       [::]:80;
        server_name  _;
        root         /usr/share/nginx/html;

        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;

        error_page 404 /404.html;
        location = /404.html {
        }

        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
        }
    }

# Settings for a TLS enabled server.
#
#    server {
#        listen       443 ssl http2;
#        listen       [::]:443 ssl http2;
#        server_name  _;
#        root         /usr/share/nginx/html;
#
#        ssl_certificate "/etc/pki/nginx/server.crt";
#        ssl_certificate_key "/etc/pki/nginx/private/server.key";
#        ssl_session_cache shared:SSL:1m;
#        ssl_session_timeout  10m;
#        ssl_ciphers HIGH:!aNULL:!MD5;
#        ssl_prefer_server_ciphers on;
#
#        # Load configuration files for the default server block.
#        include /etc/nginx/default.d/*.conf;
#
#        error_page 404 /404.html;
#            location = /40x.html {
#        }
#
#        error_page 500 502 503 504 /50x.html;
#            location = /50x.html {
#        }
#    }

}
```

- Проверить nginx:

```bash
nginx -t
```

```bash
systemctl restart nginx
```

```bash
curl http://192.168.50.10
```

- Настроить auditd (web)

/etc/audit/rules.d/nginx.rules
```
-w /etc/nginx/nginx.conf -p wa -k nginx_conf
-w /etc/nginx/default.d/ -p wa -k nginx_conf
```

- Установить **audispd-plugins** на виртуальной машине **web** для пересылки сообщений на центральный сервер логов

```
yum -y install audispd-plugins
```

- Настроить пересылку

/etc/audit/auditd.conf
```
#
# This file controls the configuration of the audit daemon
#

local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
##name = mydomain
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
##tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
```

/etc/audisp/plugins.d/au-remote.conf
```

# This file controls the audispd data path to the
# remote event logger. This plugin will send events to
# a remote machine (Central Logger).

active = yes
direction = out
path = /sbin/audisp-remote
type = always
#args =
format = string
```

/etc/audisp/audisp-remote.conf
```

# This file controls the audispd data path to the
# remote event logger. This plugin will send events to
# a remote machine (Central Logger).

active = yes
direction = out
path = /sbin/audisp-remote
type = always
#args =
format = string

[root@web vagrant]# cat /etc/audisp/audisp-remote.conf
#
# This file controls the configuration of the audit remote
# logging subsystem, audisp-remote.
#

remote_server = 192.168.56.15
port = 60
##local_port =
transport = tcp
queue_file = /var/spool/audit/remote.log
mode = immediate
queue_depth = 10240
format = managed
network_retry_time = 1
max_tries_per_record = 3
max_time_per_record = 5
heartbeat_timeout = 0

network_failure_action = stop
disk_low_action = ignore
disk_full_action = warn_once
disk_error_action = warn_once
remote_ending_action = reconnect
generic_error_action = syslog
generic_warning_action = syslog
queue_error_action = stop
overflow_action = syslog

##enable_krb5 = no
##krb5_principal =
##krb5_client_name = auditd
##krb5_key_file = /etc/audisp/audisp-remote.key
```

```bash
service auditd restart
```

- Настройка центрального сервера сбора логов

/etc/rsyslog.conf
```
# rsyslog configuration file

# For more information see /usr/share/doc/rsyslog-*/rsyslog_conf.html
# If you experience problems, see http://www.rsyslog.com/doc/troubleshoot.html

#### MODULES ####

# The imjournal module bellow is now used as a message source instead of imuxsock.
$ModLoad imuxsock # provides support for local system logging (e.g. via logger command)
$ModLoad imjournal # provides access to the systemd journal
#$ModLoad imklog # reads kernel messages (the same are read from journald)
#$ModLoad immark  # provides --MARK-- message capability

# Provides UDP syslog reception
$ModLoad imudp
$UDPServerRun 514

# Provides TCP syslog reception
$ModLoad imtcp
$InputTCPServerRun 514


#### GLOBAL DIRECTIVES ####

# Where to place auxiliary files
$WorkDirectory /var/lib/rsyslog

# Use default timestamp format
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# File syncing capability is disabled by default. This feature is usually not required,
# not useful and an extreme performance hit
#$ActionFileEnableSync on

# Include all config files in /etc/rsyslog.d/
$IncludeConfig /etc/rsyslog.d/*.conf

# Turn off message reception via local log socket;
# local messages are retrieved through imjournal now.
$OmitLocalLogging on

# File to store the position in the journal
$IMJournalStateFile imjournal.state


#### RULES ####

# Log all kernel messages to the console.
# Logging much else clutters up the screen.
#kern.*                                                 /dev/console

# Log anything (except mail) of level info or higher.
# Don't log private authentication messages!
*.info;mail.none;authpriv.none;cron.none                /var/log/messages

# The authpriv file has restricted access.
authpriv.*                                              /var/log/secure

# Log all the mail messages in one place.
mail.*                                                  -/var/log/maillog


# Log cron stuff
cron.*                                                  /var/log/cron

# Everybody gets emergency messages
*.emerg                                                 :omusrmsg:*

# Save news errors of level crit and higher in a special file.
uucp,news.crit                                          /var/log/spooler

# Save boot messages also to boot.log
local7.*                                                /var/log/boot.log


# ### begin forwarding rule ###
# The statement between the begin ... end define a SINGLE forwarding
# rule. They belong together, do NOT split them. If you create multiple
# forwarding rules, duplicate the whole block!
# Remote Logging (we use TCP for reliable delivery)
#
# An on-disk queue is created for this action. If the remote host is
# down, messages are spooled to disk and sent when it is up again.
#$ActionQueueFileName fwdRule1 # unique name prefix for spool files
#$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)
#$ActionQueueSaveOnShutdown on # save messages to disk on shutdown
#$ActionQueueType LinkedList   # run asynchronously
#$ActionResumeRetryCount -1    # infinite retries if host is down
# remote host is: name/ip:port, e.g. 192.168.0.1:514, port optional
#*.* @@remote-host:514


#Add remote logs
$template RemoteLogs,"/var/log/rsyslog/%HOSTNAME%/%PROGRAMNAME%.log"
*.* -?RemoteLogs
```

/etc/audit/auditd.conf
```
#
# This file controls the configuration of the audit daemon
#

local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
```

```bash
service auditd restart
```

### Проверка первой части

- Открыть консоль log-сервера

```bash
vagrant ssh log
```

```bash
tail -f /var/log/rsyslog/web/nginx_access.log
```

- Во второй консоли:

```bash
curl 192.168.56.10
curl 192.168.56.10/123.html
```

Пример вывода tail -f

```
# tail -f /var/log/rsyslog/web/nginx_access.log

Feb 24 17:41:43 web nginx_access: 192.168.56.101 - - [24/Feb/2024:17:41:43 +0300] "GET / HTTP/1.1" 200 4833 "-" "curl/8.5.0"
Feb 24 17:41:51 web nginx_access: 192.168.56.101 - - [24/Feb/2024:17:41:51 +0300] "GET /123.html HTTP/1.1" 404 3650 "-" "curl/8.5.0"
^C
```

```
[root@log vagrant]# tail -f /var/log/rsyslog/web/nginx_error.log
Feb 24 17:41:51 web nginx_error: 2024/02/24 17:41:51 [error] 5379#5379: *3 open() "/usr/share/nginx/html/123.html" failed (2: No such file or directory), client: 192.168.56.101, server: _, request: "GET /123.html HTTP/1.1", host: "192.168.56.10"
^C
```

- Для проверки auditd

```bash
vagrant ssh log
```

```bash
tail -f /var/log/audit/audit.log
```

Во второй консоли

```bash
vagrant ssh web
```

```bash
chmod u+x /etc/nginx/nginx.conf
```

```bash
chmod u-x /etc/nginx/nginx.conf
```

В это время на машине log

```
tail -f /var/log/audit/audit.log

node=web type=SYSCALL msg=audit(1708786200.697:1836): arch=c000003e syscall=268 success=yes exit=0 a0=ffffffffffffff9c a1=160a0f0 a2=1e4 a3=7ffe826e8ea0 items=1 ppid=26629 pid=26650 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=6 comm="chmod" exe="/usr/bin/chmod" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="nginx_conf"
node=web type=CWD msg=audit(1708786200.697:1836):  cwd="/home/vagrant"
node=web type=PATH msg=audit(1708786200.697:1836): item=0 name="/etc/nginx/nginx.conf" inode=67521899 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:httpd_config_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
node=web type=PROCTITLE msg=audit(1708786200.697:1836): proctitle=63686D6F6400752B78002F6574632F6E67696E782F6E67696E782E636F6E66
node=web type=SYSCALL msg=audit(1708786204.906:1837): arch=c000003e syscall=268 success=yes exit=0 a0=ffffffffffffff9c a1=18190f0 a2=1a4 a3=7fff0181f6a0 items=1 ppid=26629 pid=26651 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=6 comm="chmod" exe="/usr/bin/chmod" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="nginx_conf"
node=web type=CWD msg=audit(1708786204.906:1837):  cwd="/home/vagrant"
node=web type=PATH msg=audit(1708786204.906:1837): item=0 name="/etc/nginx/nginx.conf" inode=67521899 dev=08:01 mode=0100744 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:httpd_config_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
node=web type=PROCTITLE msg=audit(1708786204.906:1837): proctitle=63686D6F6400752D78002F6574632F6E67696E782F6E67696E782E636F6E66
^C
```

## Часть 2. **ELK**

- После **vagrant up** разворачивается виртуальная машина на Ubuntu с настроенным ELK. Необходимо только войти в Kibana - для этого:

- Посмотреть пароль пользователя elastic:

```bash
vagrant ssh elk
```

```bash
sudo -s
```

```bash
cat /etc/logstash/conf.d/output.conf | grep password | awk '{ print $3 }' | tr -d \"
```

Вывод команды - это пароль (пример):
```
V4S2SV1mRdAdHC5S5qfg
```

- Далее получить token:

```bash
/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```

Пример вывода:
```
eyJ2ZXIiOiI4LjEwLjMiLCJhZHIiOlsiMTAuMC4yLjE1OjkyMDAiXSwiZmdyIjoiOTU3ZmFhM2U5ZTExOGM1NjBlNGQxNTg1Y2Y1NTJhY2Q5NGQxYjczYzE2NjFkOGFjMTU2Y2MzMWNjNzM4NmFlMCIsImtleSI6InJpNnEyNDBCT3R4RUFfaVNVY0V6Ok1hOHNLNlhSVEFXS3RvZnlCVTdFZHcifQ==
```

- Ввести token по адресу http://192.168.56.20:5601/

- Получить код подтверждения:

```bash
/usr/share/kibana/bin/kibana-verification-code
```

Пример вывода:
```
Your verification code is:  469 620
```

- Обновить страницу и ввести учетные данные
  - login: elastic
  - password: V4S2SV1mRdAdHC5S5qfg (тот, что получили вначале)

- Добавить data view в разделе Discover
  - Index patter: filebeat-*
  - Name: Nginx


## Playbook (для удобства проерки ДЗ):

```yaml
---
- hosts: web log
  become: true
  gather_facts: false

  tasks:
  - name: Accept login with password from sshd
    ansible.builtin.lineinfile:
      path: /etc/ssh/sshd_config
      regexp: '^PasswordAuthentication no$'
      line: 'PasswordAuthentication yes'
      state: present
    notify:
      - Restart sshd

  - name: Install vim
    ansible.builtin.yum:
      name:
        - vim
        - mc
        - tcpdump
      state: present

  - name: Set timezone
    community.general.timezone:
      name: Europe/Moscow
    notify:
      - Restart Chrony service


  handlers:

  - name: Restart Chrony service
    ansible.builtin.service:
      name: chronyd
      state: restarted

  - name: Restart sshd
    service:
      name: sshd
      state: restarted

- hosts: web
  become: true
  gather_facts: false

  vars:
    ip_log: 192.168.56.15

  tasks:

  - name: Install epel-release
    ansible.builtin.yum:
      name: epel-release
      state: present

  - name: Install nginx
    ansible.builtin.yum:
      name: nginx
      state: present
    notify:
      - Restart nginx service

  - name: Install audispd-plugins
    ansible.builtin.yum:
      name: audispd-plugins
      state: present

  - name: Copy audit rules for nginx
    ansible.builtin.copy:
      src: ./files/nginx.rules
      dest: /etc/audit/rules.d/nginx.rules
      owner: root
      group: root
      mode: '0600'
    notify:
      - Restart auditd service

  - name: Change auditd name format to HOSTNAME
    ansible.builtin.lineinfile:
      dest: /etc/audit/auditd.conf
      line: 'name_format = HOSTNAME'
      regexp: '^name_format = NONE$'
      state: present
    notify:
      - Restart auditd service

  - name: Change auditd remote server
    ansible.builtin.lineinfile:
      dest: /etc/audisp/audisp-remote.conf
      line: 'remote_server = {{ ip_log }}'
      regexp: '^remote_server = $'
      state: present
    notify:
      - Restart auditd service

  - name: Activate remote options auditd
    ansible.builtin.lineinfile:
      dest: /etc/audisp/plugins.d/au-remote.conf
      line: 'active = yes'
      regexp: '^active = no$'
      state: present
    notify:
      - Restart auditd service

  - name: Edit nginx config. Add error_log
    ansible.builtin.lineinfile:
      dest: /etc/nginx/nginx.conf
      line: 'error_log syslog:server={{ ip_log }}:514,tag=nginx_error;'
      insertafter: 'error_log /var/log/nginx/error.log;'
      state: present
    notify:
      - Restart nginx service

  - name: Edit nginx config. Add access_log
    ansible.builtin.lineinfile:
      dest: /etc/nginx/nginx.conf
      line: '    access_log syslog:server={{ ip_log }}:514,tag=nginx_access,severity=info combined;'
      insertafter: '    access_log  /var/log/nginx/access.log  main;'
      state: present
    notify:
      - Restart nginx service

  - name: Add Elasticsearch GPG key.
    rpm_key:
      key: https://artifacts.elastic.co/GPG-KEY-elasticsearch
      state: present

  - name: Add Filebeat repository.
    ansible.builtin.copy:
      src: ./files/filebeat/elastic-8.x.repo
      dest: /etc/yum.repos.d/elastic-8.x.repo
      mode: 0644

  - name: Install filebeat (ELK)
    ansible.builtin.yum:
      name: filebeat
      state: present
    notify:
      - Restart filebeat service

  - name: Copy filebeat config
    ansible.builtin.copy:
      src: ./files/filebeat/filebeat.yml
      dest: /etc/filebeat/filebeat.yml
      mode: 0644
    notify:
      - Restart filebeat service

  handlers:

  - name: Restart nginx service
    ansible.builtin.service:
      name: nginx
      enabled: true
      state: restarted

    # auditd модулем ansible.builtin.service корректно не перезапускается
  - name: Restart auditd service
    ansible.builtin.command: service auditd restart

  - name: Restart filebeat service
    ansible.builtin.service:
      name: filebeat
      enabled: true
      state: restarted
      use: service

- hosts: log
  become: true
  gather_facts: false

  tasks:

  - name: Uncomment module imtcp
    ansible.builtin.lineinfile:
      backrefs: true
      path: /etc/rsyslog.conf
      regexp: '^#\$ModLoad imtcp$'
      line: '$ModLoad imtcp'
    notify:
      - Restart rsyslog service

  - name: Uncomment tcp port 514
    ansible.builtin.lineinfile:
      backrefs: true
      path: /etc/rsyslog.conf
      regexp: '^#\$InputTCPServerRun 514$'
      line: '$InputTCPServerRun 514'
    notify:
      - Restart rsyslog service

  - name: Uncomment module imudp
    ansible.builtin.lineinfile:
      backrefs: true
      path: /etc/rsyslog.conf
      regexp: '^#\$ModLoad imudp$'
      line: '$ModLoad imudp'
    notify:
      - Restart rsyslog service

  - name: Uncomment udp port 514
    ansible.builtin.lineinfile:
      backrefs: true
      path: /etc/rsyslog.conf
      regexp: '^#\$UDPServerRun 514$'
      line: '$UDPServerRun 514'
    notify:
      - Restart rsyslog service

  - name: Add template remote logs
    ansible.builtin.lineinfile:
      backrefs: true
      path: /etc/rsyslog.conf
      regexp: '# ### end of the forwarding rule ###'
      line: '\n\n#Add remote logs\n$template RemoteLogs,"/var/log/rsyslog/%HOSTNAME%/%PROGRAMNAME%.log"\n*.* -?RemoteLogs'
    notify:
      - Restart rsyslog service

  - name: Uncomment module imtcp
    ansible.builtin.lineinfile:
      backrefs: true
      path: /etc/audit/auditd.conf
      regexp: '^##tcp_listen_port = 60$'
      line: 'tcp_listen_port = 60'
    notify:
      - Restart auditd service

  handlers:

  - name: Restart rsyslog service
    ansible.builtin.command: service rsyslog restart

  - name: Restart auditd service
    ansible.builtin.command: service auditd restart

- hosts: elk
  become: true
  gather_facts: false

  vars:
    passwd_elastic: "dha(&dya8sd*.SIdfhsk"

  tasks:

  - name: Set timezone to Europe/Moscow
    ansible.builtin.command: timedatectl set-timezone Europe/Moscow

  - name: Add Elasticsearch apt key
    ansible.builtin.apt_key:
      url: https://artifacts.elastic.co/GPG-KEY-elasticsearch
      state: present

  - name: Adding Elasticsearch repo
    ansible.builtin.apt_repository:
      repo: deb https://mirror.yandex.ru/mirrors/elastic/8 stable main
      state: present

  - name: Update and upgrade apt packages
    ansible.builtin.apt:
      upgrade: yes
      update_cache: yes
      cache_valid_time: 86400

  - name: Install JDK
    ansible.builtin.apt:
      name: default-jdk
      update_cache: yes

  - name: Install Midnight Commander
    ansible.builtin.apt:
      name: mc
      update_cache: yes

  - name: Install Elasticsearch
    ansible.builtin.apt:
      name: elasticsearch
      update_cache: yes
    notify:
      - Starting Elasticsearch

  - name: Install Kibana
    ansible.builtin.apt:
      name: kibana
      update_cache: yes
    notify:
      - Starting Kibana

  - name: Change host address kibana
    ansible.builtin.lineinfile:
      destfile: /etc/kibana/kibana.yml
      regexp: 'server.host:'
      line: 'server.host: "0.0.0.0"'
    notify:
      - Starting Kibana

  - name: Change port kibana
    ansible.builtin.lineinfile:
      destfile: /etc/kibana/kibana.yml
      regexp: 'server.port:'
      line: 'server.port: 5601'
    notify:
      - Starting Kibana

  - name: Install Logstash
    ansible.builtin.apt:
      name: logstash
      update_cache: yes
    notify:
      - Copy logstash configs

  handlers:

  - name: Starting Elasticsearch
    ansible.builtin.systemd_service:
      name: elasticsearch
      daemon_reload: true
      enabled: true
      state: restarted

  - name: Starting Kibana
    ansible.builtin.systemd_service:
      name: kibana
      daemon_reload: true
      enabled: true
      state: restarted

  - name: Copy logstash configs
    ansible.builtin.copy:
      src: ./files/logstash/
      dest: /etc/logstash/conf.d/
      owner: root
      group: logstash
      mode: '0640'
    notify:
      - Copy script for generate elastic password

  - name: Copy script for generate elastic password
    ansible.builtin.copy:
      src: ./files/elasticsearch/set_pass.sh
      dest: /root/set_pass.sh
      owner: root
      group: root
      mode: '0700'
    notify:
      - Generate password elastic user

  - name: Generate password elastic user
    ansible.builtin.command: /root/set_pass.sh
    register: elastic_password
    notify:
      - Set elastic password in logstash output config

  - name: Set elastic password in logstash output config
    ansible.builtin.lineinfile:
      destfile: /etc/logstash/conf.d/output.conf
      regexp: '    password => ""'
      line: '    password => "{{ elastic_password.stdout }}"'
    notify:
      - Starting Logstash

  - name: Starting Logstash
    ansible.builtin.systemd_service:
      name: logstash
      daemon_reload: true
      enabled: true
      state: restarted

```

