# Known-good environment for Bastion: Ubuntu 22.04 with a 5.15+ kernel,
# CONFIG_DEBUG_INFO_BTF=y (Ubuntu default), clang/llvm, libbpf, bpftool, Go.
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "bastion"
  config.vm.synced_folder ".", "/home/vagrant/bastion"

  # Control plane API + Prometheus metrics reachable from the host,
  # so the frontend can be used from a host browser.
  config.vm.network "forwarded_port", guest: 8080, host: 8080
  config.vm.network "forwarded_port", guest: 9090, host: 9090

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 4096
    vb.cpus = 4
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -eux
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y \
      clang llvm libbpf-dev libelf-dev zlib1g-dev \
      linux-tools-common "linux-tools-$(uname -r)" \
      make gcc git curl jq \
      iproute2 iputils-ping netcat-openbsd trafgen \
      nftables iptables sysstat

    # Go (jammy's packaged Go is too old)
    GO_VERSION=1.22.5
    ARCH=$(dpkg --print-architecture)
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" | tar -C /usr/local -xz
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh

    # Sanity checks the spec's Phase 0 acceptance depends on
    test -f /sys/kernel/btf/vmlinux
    bpftool feature probe | grep -i xdp || true
  SHELL
end
