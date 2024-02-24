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
