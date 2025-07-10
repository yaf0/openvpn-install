#!/bin/bash
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora, Oracle Linux 8, Arch Linux, Rocky Linux and AlmaLinux.
# https://github.com/angristan/openvpn-install

# 预定义文件路径，用于手动下载的文件
EASY_RSA_VERSION="3.1.2"
EASY_RSA_FILE="/opt/EasyRSA-${EASY_RSA_VERSION}.tgz"
EASY_RSA_URL="https://github.com/OpenVPN/easy-rsa/releases/download/v${EASY_RSA_VERSION}/EasyRSA-${EASY_RSA_VERSION}.tgz"

function isRoot() {
        if [ "$EUID" -ne 0 ]; then
                return 1
        fi
}

function tunAvailable() {
        if [ ! -e /dev/net/tun ]; then
                return 1
        fi
}

function checkOS() {
        if [[ -e /etc/debian_version ]]; then
                OS="debian"
                source /etc/os-release

                if [[ $ID == "debian" || $ID == "raspbian" ]]; then
                        if [[ $VERSION_ID -lt 9 ]]; then
                                echo "⚠️ 您的Debian版本不受支持。"
                                echo ""
                                echo "但是，如果您使用的是Debian >= 9或不稳定/测试版本，您可以自行承担风险继续。"
                                echo ""
                                until [[ $CONTINUE =~ (y|n) ]]; do
                                        read -rp "继续？[y/n]: " -e CONTINUE
                                done
                                if [[ $CONTINUE == "n" ]]; then
                                        exit 1
                                fi
                        fi
                elif [[ $ID == "ubuntu" ]]; then
                        OS="ubuntu"
                        MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
                        if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
                                echo "⚠️ 您的Ubuntu版本不受支持。"
                                echo ""
                                echo "但是，如果您使用的是Ubuntu >= 16.04或测试版，您可以自行承担风险继续。"
                                echo ""
                                until [[ $CONTINUE =~ (y|n) ]]; do
                                        read -rp "继续？[y/n]: " -e CONTINUE
                                done
                                if [[ $CONTINUE == "n" ]]; then
                                        exit 1
                                fi
                        fi
                fi
        elif [[ -e /etc/system-release ]]; then
                source /etc/os-release
                if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
                        OS="fedora"
                fi
                if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
                        OS="centos"
                        if [[ ${VERSION_ID%.*} -lt 7 ]]; then
                                echo "⚠️ 您的CentOS版本不受支持。"
                                echo ""
                                echo "脚本仅支持CentOS 7和CentOS 8。"
                                echo ""
                                exit 1
                        fi
                fi
                if [[ $ID == "ol" ]]; then
                        OS="oracle"
                        if [[ ! $VERSION_ID =~ (8) ]]; then
                                echo "您的Oracle Linux版本不受支持。"
                                echo ""
                                echo "脚本仅支持Oracle Linux 8。"
                                exit 1
                        fi
                fi
                if [[ $ID == "amzn" ]]; then
                        if [[ $VERSION_ID == "2" ]]; then
                                OS="amzn"
                        elif [[ "$(echo "$PRETTY_NAME" | cut -c 1-18)" == "Amazon Linux 2023." ]] && [[ "$(echo "$PRETTY_NAME" | cut -c 19)" -ge 6 ]]; then
                                OS="amzn2023"
                        else
                                echo "⚠️ 您的Amazon Linux版本不受支持。"
                                echo ""
                                echo "脚本仅支持Amazon Linux 2或Amazon Linux 2023.6+"
                                echo ""
                                exit 1
                        fi
                fi
        elif [[ -e /etc/arch-release ]]; then
                OS=arch
        else
                echo "看起来您不是在Debian、Ubuntu、Fedora、CentOS、Amazon Linux 2、Oracle Linux 8或Arch Linux系统上运行此安装程序。"
                exit 1
        fi
}

function initialCheck() {
        if ! isRoot; then
                echo "抱歉，您需要以root权限运行此脚本。"
                exit 1
        fi
        if ! tunAvailable; then
                echo "TUN设备不可用。"
                exit 1
        fi
        checkOS
}

function installUnbound() {
        # If Unbound isn't installed, install it
        if [[ ! -e /etc/unbound/unbound.conf ]]; then

                if [[ $OS =~ (debian|ubuntu) ]]; then
                        apt-get install -y unbound

                        # Configuration
                        echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

                elif [[ $OS =~ (centos|amzn|oracle) ]]; then
                        yum install -y unbound

                        # Configuration
                        sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
                        sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
                        sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
                        sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
                        sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

                elif [[ $OS == "fedora" ]]; then
                        dnf install -y unbound

                        # Configuration
                        sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
                        sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
                        sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
                        sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
                        sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

                elif [[ $OS == "arch" ]]; then
                        pacman -Syu --noconfirm unbound

                        # Get root servers list
                        curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

                        if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
                                mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
                        fi

                        echo 'server:
        use-syslog: yes
        do-daemonize: no
        username: "unbound"
        directory: "/etc/unbound"
        trust-anchor-file: trusted-key.key
        root-hints: root.hints
        interface: 10.8.0.1
        access-control: 10.8.0.1/24 allow
        port: 53
        num-threads: 2
        use-caps-for-id: yes
        harden-glue: yes
        hide-identity: yes
        hide-version: yes
        qname-minimisation: yes
        prefetch: yes' >/etc/unbound/unbound.conf
                fi

                # IPv6 DNS for all OS
                if [[ $IPV6_SUPPORT == 'y' ]]; then
                        echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
                fi

                if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
                        # DNS Rebinding fix
                        echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
                fi
        else # Unbound is already installed
                echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

                # Add Unbound 'server' for the OpenVPN subnet
                echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
                if [[ $IPV6_SUPPORT == 'y' ]]; then
                        echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
                fi
        fi

        systemctl enable unbound
        systemctl restart unbound
}

function resolvePublicIP() {
        # IP version flags, we'll use as default the IPv4
        CURL_IP_VERSION_FLAG="-4"
        DIG_IP_VERSION_FLAG="-4"

        # Behind NAT, we'll default to the publicly reachable IPv4/IPv6.
        if [[ $IPV6_SUPPORT == "y" ]]; then
                CURL_IP_VERSION_FLAG=""
                DIG_IP_VERSION_FLAG="-6"
        fi

        # If there is no public ip yet, we'll try to solve it using: https://api.seeip.org
        if [[ -z $PUBLIC_IP ]]; then
                PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.seeip.org 2>/dev/null)
        fi

        # If there is no public ip yet, we'll try to solve it using: https://ifconfig.me
        if [[ -z $PUBLIC_IP ]]; then
                PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://ifconfig.me 2>/dev/null)
        fi

        # If there is no public ip yet, we'll try to solve it using: https://api.ipify.org
        if [[ -z $PUBLIC_IP ]]; then
                PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.ipify.org 2>/dev/null)
        fi

        # If there is no public ip yet, we'll try to solve it using: https://ip.sb
        if [[ -z $PUBLIC_IP ]]; then
                PUBLIC_IP=$(curl  -s --retry 2   http://ip.sb 2>/dev/null)
        fi

        # If there is no public ip yet, we'll try to solve it using: ns1.google.com
        if [[ -z $PUBLIC_IP ]]; then
                PUBLIC_IP=$(dig $DIG_IP_VERSION_FLAG TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
        fi

        if [[ -z $PUBLIC_IP ]]; then
                echo >&2 echo "无法获取公网IP地址"
                exit 1
        fi

        echo "$PUBLIC_IP"
}

# 计算下一个可用的固定IP地址
function getNextAvailableIP() {
        local base_ip="10.8.0"
        local start_ip=100  # 从10.8.0.100开始分配固定IP

        # 检查CCD目录是否存在
        if [[ ! -d /etc/openvpn/ccd ]]; then
                echo "${base_ip}.${start_ip}"
                return
        fi

        # 获取已使用的IP列表
        local used_ips=()
        if [[ -f /etc/openvpn/ipp.txt ]]; then
                while IFS=',' read -r client ip; do
                        if [[ -n "$ip" && "$ip" =~ ^10\.8\.0\.[0-9]+$ ]]; then
                                used_ips+=("$ip")
                        fi
                done < /etc/openvpn/ipp.txt
        fi

        # 检查CCD文件中的固定IP
        for ccd_file in /etc/openvpn/ccd/*; do
                if [[ -f "$ccd_file" ]]; then
                        local fixed_ip=$(grep -o 'ifconfig-push [0-9.]*' "$ccd_file" | awk '{print $2}')
                        if [[ -n "$fixed_ip" ]]; then
                                used_ips+=("$fixed_ip")
                        fi
                fi
        done

        # 找到下一个可用IP
        local current_ip=$start_ip
        while [[ $current_ip -le 254 ]]; do
                local test_ip="${base_ip}.${current_ip}"
                local ip_used=false

                for used_ip in "${used_ips[@]}"; do
                        if [[ "$used_ip" == "$test_ip" ]]; then
                                ip_used=true
                                break
                        fi
                done

                if [[ "$ip_used" == false ]]; then
                        echo "$test_ip"
                        return
                fi

                ((current_ip++))
        done

        # 如果没有可用IP，返回错误
        echo "找不到新的可用IP了"
}

# 验证IP地址是否可用
function validateIP() {
        local ip="$1"
        local base_ip="10.8.0"

        # 检查IP格式
        if [[ ! "$ip" =~ ^10\.8\.0\.[0-9]+$ ]]; then
                return 1
        fi

        # 提取IP的最后一段
        local last_octet=$(echo "$ip" | cut -d'.' -f4)

        # 检查是否在有效范围内（100-254）
        if [[ $last_octet -lt 100 || $last_octet -gt 254 ]]; then
                return 1
        fi

        # 检查IP是否已被使用
        if [[ -f /etc/openvpn/ipp.txt ]]; then
                if grep -q ",$ip$" /etc/openvpn/ipp.txt; then
                        return 1
                fi
        fi

        # 检查CCD文件中的固定IP
        if [[ -d /etc/openvpn/ccd ]]; then
                for ccd_file in /etc/openvpn/ccd/*; do
                        if [[ -f "$ccd_file" ]]; then
                                if grep -q "ifconfig-push $ip" "$ccd_file"; then
                                        return 1
                                fi
                        fi
                done
        fi

        return 0
}

function installQuestions() {
        echo "欢迎使用OpenVPN安装程序！"
        echo "Git仓库地址：https://github.com/angristan/openvpn-install"
        echo ""

        echo "在开始设置之前，我需要询问您几个问题。"
        echo "如果您对默认选项满意，只需按回车键即可。"
        echo ""
        echo "填写OpenVPN服务监听的网络接口的IPv4地址(一般会自动识别)："

        # Detect public IPv4 address and pre-fill for the user
        IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

        if [[ -z $IP ]]; then
                # Detect public IPv6 address
                IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
        fi
        APPROVE_IP=${APPROVE_IP:-n}
        if [[ $APPROVE_IP =~ n ]]; then
                read -rp "IP地址: " -e -i "$IP" IP
        fi
        # If $IP is a private IP address, the server must be behind NAT
        if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
                echo ""
                echo "看起来此服务器在NAT后面。它的公共IPv4地址或主机名是什么？"
                echo "正在获取公网出口地址......"

                if [[ -z $ENDPOINT ]]; then
                        DEFAULT_ENDPOINT=$(resolvePublicIP)
                fi
                echo "获取到公网出口地址：$DEFAULT_ENDPOINT 当然，你也可以改用域名，以应对服务器ip变更"
                until [[ $ENDPOINT != "" ]]; do
                        read -rp "公共IPv4地址或主机名: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
                done
        fi

        echo ""
        echo "检查IPv6连接性..."
        echo ""
        # "ping6" and "ping -6" availability varies depending on the distribution
        if type ping6 >/dev/null 2>&1; then
                PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
        else
                PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
        fi
        if eval "$PING6"; then
                echo "您的主机似乎具有IPv6连接性。"
                SUGGESTION="y"
        else
                echo "您的主机似乎没有IPv6连接性。"
                SUGGESTION="n"
        fi
        echo ""
        # Ask the user if they want to enable IPv6 regardless its availability.
        until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
                read -rp "您是否要启用IPv6支持（NAT）？[y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
        done
        echo ""
        echo "您希望OpenVPN监听哪个端口？（！选定端口后记得去安全组/防火墙 对0.0.0.0/0放通该端口！）"
        echo "   1) 默认: 1194"
        echo "   2) 自定义"
        echo "   3) 随机 [49152-65535]"
        until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
                read -rp "端口选择 [1-3]: " -e -i 1 PORT_CHOICE
        done
        case $PORT_CHOICE in
        1)
                PORT="1194"
                ;;
        2)
                until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
                        read -rp "自定义端口 [1-65535]: " -e -i 1194 PORT
                done
                ;;
        3)
                # Generate random number within private ports range
                PORT=$(shuf -i49152-65535 -n1)
                echo "随机端口: $PORT"
                ;;
        esac
        echo ""
        echo "您希望OpenVPN使用什么协议？"
        echo "UDP更快。除非不可用，否则不应使用TCP。"
        echo "   1) UDP"
        echo "   2) TCP"
        until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
                read -rp "协议 [1-2]: " -e -i 1 PROTOCOL_CHOICE
        done
        case $PROTOCOL_CHOICE in
        1)
                PROTOCOL="udp"
                ;;
        2)
                PROTOCOL="tcp"
                ;;
        esac
        echo ""
        echo "您希望VPN客户端使用什么DNS服务器？仅组网时选0即可"
        echo "   0) 不需要给客户端推送DNS"
        echo "   1) 当前系统解析器（来自/etc/resolv.conf）"
        echo "   2) 自托管DNS解析器（Unbound）"
        echo "   3) Cloudflare（任播：全球）"
        echo "   4) Quad9（任播：全球）"
        echo "   5) Quad9无审查（任播：全球）"
        echo "   6) FDN（法国）"
        echo "   7) DNS.WATCH（德国）"
        echo "   8) OpenDNS（任播：全球）"
        echo "   9) Google（任播：全球）"
        echo "   10) Yandex Basic（俄罗斯）"
        echo "   11) AdGuard DNS（任播：全球）"
        echo "   12) NextDNS（任播：全球）"
        echo "   13) 自定义"
        until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 0 ] && [ "$DNS" -le 13 ]; do
                read -rp "DNS [0-13]: " -e -i 0 DNS
                if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
                        echo ""
                        echo "Unbound已经安装。"
                        echo "您可以允许脚本配置它以从OpenVPN客户端使用它"
                        echo "我们只需在/etc/unbound/unbound.conf中为OpenVPN子网添加第二个服务器。"
                        echo "不会对当前配置进行任何更改。"
                        echo ""

                        until [[ $CONTINUE =~ (y|n) ]]; do
                                read -rp "对Unbound应用配置更改？[y/n]: " -e CONTINUE
                        done
                        if [[ $CONTINUE == "n" ]]; then
                                # Break the loop and cleanup
                                unset DNS
                                unset CONTINUE
                        fi
                elif [[ $DNS == "13" ]]; then
                        until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
                                read -rp "主DNS: " -e DNS1
                        done
                        until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
                                read -rp "备用DNS（可选）: " -e DNS2
                                if [[ $DNS2 == "" ]]; then
                                        break
                                fi
                        done
                fi
        done
        echo ""
        echo "您是否要使用压缩？由于VORACLE攻击利用它，因此不推荐使用。"
        until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
                read -rp"启用压缩？[y/n]: " -e -i n COMPRESSION_ENABLED
        done
        if [[ $COMPRESSION_ENABLED == "y" ]]; then
                echo "选择您要使用的压缩算法：（按效率排序）"
                echo "   1) LZ4-v2"
                echo "   2) LZ4"
                echo "   3) LZ0"
                until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
                        read -rp"压缩算法 [1-3]: " -e -i 1 COMPRESSION_CHOICE
                done
                case $COMPRESSION_CHOICE in
                1)
                        COMPRESSION_ALG="lz4-v2"
                        ;;
                2)
                        COMPRESSION_ALG="lz4"
                        ;;
                3)
                        COMPRESSION_ALG="lzo"
                        ;;
                esac
        fi
        echo ""
        echo "您是否要自定义加密设置？"
        echo "除非您知道自己在做什么，否则应该坚持脚本提供的默认参数。"
        echo "请注意，无论您选择什么，脚本中提供的所有选择都是安全的（与OpenVPN的默认值不同）。"
        echo "请参阅 https://github.com/angristan/openvpn-install#security-and-encryption 了解更多信息。"
        echo ""
        until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
                read -rp "自定义加密设置？[y/n]: " -e -i n CUSTOMIZE_ENC
        done
        if [[ $CUSTOMIZE_ENC == "n" ]]; then
                # Use default, sane and fast parameters
                CIPHER="AES-128-GCM"
                CERT_TYPE="1" # ECDSA
                CERT_CURVE="prime256v1"
                CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
                DH_TYPE="1" # ECDH
                DH_CURVE="prime256v1"
                HMAC_ALG="SHA256"
                TLS_SIG="1" # tls-crypt
        else
                echo ""
                echo "选择您要用于数据通道的加密算法："
                echo "   1) AES-128-GCM（推荐）"
                echo "   2) AES-192-GCM"
                echo "   3) AES-256-GCM"
                echo "   4) AES-128-CBC"
                echo "   5) AES-192-CBC"
                echo "   6) AES-256-CBC"
                until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
                        read -rp "加密算法 [1-6]: " -e -i 1 CIPHER_CHOICE
                done
                case $CIPHER_CHOICE in
                1)
                        CIPHER="AES-128-GCM"
                        ;;
                2)
                        CIPHER="AES-192-GCM"
                        ;;
                3)
                        CIPHER="AES-256-GCM"
                        ;;
                4)
                        CIPHER="AES-128-CBC"
                        ;;
                5)
                        CIPHER="AES-192-CBC"
                        ;;
                6)
                        CIPHER="AES-256-CBC"
                        ;;
                esac
                echo ""
                echo "选择您要使用的证书类型："
                echo "   1) ECDSA（推荐）"
                echo "   2) RSA"
                until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
                        read -rp"证书密钥类型 [1-2]: " -e -i 1 CERT_TYPE
                done
                case $CERT_TYPE in
                1)
                        echo ""
                        echo "选择您要用于证书密钥的曲线："
                        echo "   1) prime256v1（推荐）"
                        echo "   2) secp384r1"
                        echo "   3) secp521r1"
                        until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
                                read -rp"曲线 [1-3]: " -e -i 1 CERT_CURVE_CHOICE
                        done
                        case $CERT_CURVE_CHOICE in
                        1)
                                CERT_CURVE="prime256v1"
                                ;;
                        2)
                                CERT_CURVE="secp384r1"
                                ;;
                        3)
                                CERT_CURVE="secp521r1"
                                ;;
                        esac
                        ;;
                2)
                        echo ""
                        echo "选择您要用于证书RSA密钥的大小："
                        echo "   1) 2048位（推荐）"
                        echo "   2) 3072位"
                        echo "   3) 4096位"
                        until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
                                read -rp "RSA密钥大小 [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
                        done
                        case $RSA_KEY_SIZE_CHOICE in
                        1)
                                RSA_KEY_SIZE="2048"
                                ;;
                        2)
                                RSA_KEY_SIZE="3072"
                                ;;
                        3)
                                RSA_KEY_SIZE="4096"
                                ;;
                        esac
                        ;;
                esac
                echo ""
                echo "选择您要用于控制通道的加密算法："
                case $CERT_TYPE in
                1)
                        echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256（推荐）"
                        echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
                        until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
                                read -rp"控制通道加密算法 [1-2]: " -e -i 1 CC_CIPHER_CHOICE
                        done
                        case $CC_CIPHER_CHOICE in
                        1)
                                CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
                                ;;
                        2)
                                CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
                                ;;
                        esac
                        ;;
                2)
                        echo "   1) ECDHE-RSA-AES-128-GCM-SHA256（推荐）"
                        echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
                        until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
                                read -rp"控制通道加密算法 [1-2]: " -e -i 1 CC_CIPHER_CHOICE
                        done
                        case $CC_CIPHER_CHOICE in
                        1)
                                CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
                                ;;
                        2)
                                CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
                                ;;
                        esac
                        ;;
                esac
                echo ""
                echo "选择您要使用的Diffie-Hellman密钥类型："
                echo "   1) ECDH（推荐）"
                echo "   2) DH"
                until [[ $DH_TYPE =~ [1-2] ]]; do
                        read -rp"DH密钥类型 [1-2]: " -e -i 1 DH_TYPE
                done
                case $DH_TYPE in
                1)
                        echo ""
                        echo "选择您要用于ECDH密钥的曲线："
                        echo "   1) prime256v1（推荐）"
                        echo "   2) secp384r1"
                        echo "   3) secp521r1"
                        while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
                                read -rp"曲线 [1-3]: " -e -i 1 DH_CURVE_CHOICE
                        done
                        case $DH_CURVE_CHOICE in
                        1)
                                DH_CURVE="prime256v1"
                                ;;
                        2)
                                DH_CURVE="secp384r1"
                                ;;
                        3)
                                DH_CURVE="secp521r1"
                                ;;
                        esac
                        ;;
                2)
                        echo ""
                        echo "选择您要使用的Diffie-Hellman密钥大小："
                        echo "   1) 2048位（推荐）"
                        echo "   2) 3072位"
                        echo "   3) 4096位"
                        until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
                                read -rp "DH密钥大小 [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
                        done
                        case $DH_KEY_SIZE_CHOICE in
                        1)
                                DH_KEY_SIZE="2048"
                                ;;
                        2)
                                DH_KEY_SIZE="3072"
                                ;;
                        3)
                                DH_KEY_SIZE="4096"
                                ;;
                        esac
                        ;;
                esac
                echo ""
                # The "auth" options behaves differently with AEAD ciphers
                if [[ $CIPHER =~ CBC$ ]]; then
                        echo "摘要算法对数据通道数据包和控制通道的tls-auth数据包进行身份验证。"
                elif [[ $CIPHER =~ GCM$ ]]; then
                        echo "摘要算法对控制通道的tls-auth数据包进行身份验证。"
                fi
                echo "您希望使用哪种摘要算法进行HMAC？"
                echo "   1) SHA-256（推荐）"
                echo "   2) SHA-384"
                echo "   3) SHA-512"
                until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
                        read -rp "摘要算法 [1-3]: " -e -i 1 HMAC_ALG_CHOICE
                done
                case $HMAC_ALG_CHOICE in
                1)
                        HMAC_ALG="SHA256"
                        ;;
                2)
                        HMAC_ALG="SHA384"
                        ;;
                3)
                        HMAC_ALG="SHA512"
                        ;;
                esac
                echo ""
                echo "您可以使用tls-auth和tls-crypt为控制通道添加额外的安全层"
                echo "tls-auth对数据包进行身份验证，而tls-crypt对数据包进行身份验证和加密。"
                echo "   1) tls-crypt（推荐）"
                echo "   2) tls-auth"
                until [[ $TLS_SIG =~ [1-2] ]]; do
                        read -rp "控制通道额外安全机制 [1-2]: " -e -i 1 TLS_SIG
                done
        fi
        echo ""
        echo "好的，这就是我需要了解的全部内容。我们现在准备设置您的OpenVPN服务器。"
        echo "您将能够在安装结束时生成客户端。"
        APPROVE_INSTALL=${APPROVE_INSTALL:-n}
        if [[ $APPROVE_INSTALL =~ n ]]; then
                read -n1 -r -p "按任意键继续..."
        fi
}

function installOpenVPN() {
        if [[ $AUTO_INSTALL == "y" ]]; then
                # 设置默认选项，以便不会询问问题。
                APPROVE_INSTALL=${APPROVE_INSTALL:-y}
                APPROVE_IP=${APPROVE_IP:-y}
                IPV6_SUPPORT=${IPV6_SUPPORT:-n}
                PORT_CHOICE=${PORT_CHOICE:-1}
                PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
                DNS=${DNS:-1}
                COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
                CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
                CLIENT=${CLIENT:-client}
                PASS=${PASS:-1}
                CONTINUE=${CONTINUE:-y}

                if [[ -z $ENDPOINT ]]; then
                        ENDPOINT=$(resolvePublicIP)
                fi
        fi

        # 首先运行设置问题，并设置其他变量（如果自动安装）
        installQuestions

        # 从默认路由获取 "public" 接口
        NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
        if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
                NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
        fi

        # $NIC can not be empty for script rm-openvpn-rules.sh
        if [[ -z $NIC ]]; then
                echo
                echo "无法检测到公共接口。"
                echo "这需要设置MASQUERADE。"
                until [[ $CONTINUE =~ (y|n) ]]; do
                        read -rp "继续？[y/n]: " -e CONTINUE
                done
                if [[ $CONTINUE == "n" ]]; then
                        exit 1
                fi
        fi

        # 如果 OpenVPN 尚未安装，则安装它。此脚本在多次运行时或多或少是幂等的，
        # 但只会第一次从上游安装 OpenVPN。
        if [[ ! -e /etc/openvpn/server.conf ]]; then
                if [[ $OS =~ (debian|ubuntu) ]]; then
                        apt-get update
                        apt-get -y install ca-certificates gnupg
                        # 我们添加 OpenVPN 仓库以获取最新版本。
                        if [[ $VERSION_ID == "16.04" ]]; then
                                echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
                                wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
                                apt-get update
                        fi
                        # Ubuntu > 16.04 和 Debian > 8 具有无需第三方仓库的 OpenVPN >= 2.4。
                        apt-get install -y openvpn iptables openssl wget ca-certificates curl
                elif [[ $OS == 'centos' ]]; then
                        yum install -y epel-release
                        yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
                elif [[ $OS == 'oracle' ]]; then
                        yum install -y oracle-epel-release-el8
                        yum-config-manager --enable ol8_developer_EPEL
                        yum install -y openvpn iptables openssl wget ca-certificates curl tar policycoreutils-python-utils
                elif [[ $OS == 'amzn' ]]; then
                        amazon-linux-extras install -y epel
                        yum install -y openvpn iptables openssl wget ca-certificates curl
                elif [[ $OS == 'amzn2023' ]]; then
                        dnf install -y openvpn iptables openssl wget ca-certificates
                elif [[ $OS == 'fedora' ]]; then
                        dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
                elif [[ $OS == 'arch' ]]; then
                        # 安装必需的依赖项并升级系统
                        pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
                fi
                # easy-rsa 的旧版本在某些 OpenVPN 包中默认可用
                if [[ -d /etc/openvpn/easy-rsa/ ]]; then
                        rm -rf /etc/openvpn/easy-rsa/
                fi
        fi

        # 找出机器是否使用 nogroup 或 nobody 作为权限组
        if grep -qs "^nogroup:" /etc/group; then
                NOGROUP=nogroup
        else
                NOGROUP=nobody
        fi

        # 从源代码安装最新版本的 easy-rsa，如果尚未安装。
        if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
                local version="3.1.2"

                # 检查本地是否存在easy-rsa文件
                if [[ -f "$EASY_RSA_FILE" ]]; then
                        echo "使用本地easy-rsa文件: $EASY_RSA_FILE"
                        cp "$EASY_RSA_FILE" ~/easy-rsa.tgz
                else
                        echo "本地easy-rsa文件未找到，下载easy-rsa 版本 $version..."
            echo "如下载失败，请手动下载并放置到$EASY_RSA_FILE"
                        # wget -O ~/easy-rsa.tgz "$EASY_RSA_URL"
            wget -O ~/easy-rsa.tgz $EASY_RSA_URL
                fi

                mkdir -p /etc/openvpn/easy-rsa
                tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
                rm -f ~/easy-rsa.tgz

                cd /etc/openvpn/easy-rsa/ || return
                case $CERT_TYPE in
                1)
                        echo "set_var EASYRSA_ALGO ec" >vars
                        echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
                        ;;
                2)
                        echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
                        ;;
                esac

                # 生成一个 16 字符的随机字母数字标识符用于 CN 和服务器名称
                SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
                echo "$SERVER_CN" >SERVER_CN_GENERATED
                SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
                echo "$SERVER_NAME" >SERVER_NAME_GENERATED

                # 创建 PKI，设置 CA，DH 参数和证书
                ./easyrsa init-pki
                EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

                if [[ $DH_TYPE == "2" ]]; then
                        # ECDH 密钥在运行时生成，因此我们不需要预先生成它们
                        openssl dhparam -out dh.pem $DH_KEY_SIZE
                fi

                EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
                EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

                case $TLS_SIG in
                1)
                        # 生成 tls-crypt 密钥
                        openvpn --genkey --secret /etc/openvpn/tls-crypt.key
                        ;;
                2)
                        # 生成 tls-auth 密钥
                        openvpn --genkey --secret /etc/openvpn/tls-auth.key
                        ;;
                esac
        else
                # 如果 easy-rsa 已安装，获取生成的 SERVER_NAME
                # 用于客户端配置
                cd /etc/openvpn/easy-rsa/ || return
                SERVER_NAME=$(cat SERVER_NAME_GENERATED)
        fi

        # 移动所有生成的文件
        cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
        if [[ $DH_TYPE == "2" ]]; then
                cp dh.pem /etc/openvpn
        fi

        # 使证书吊销列表对非 root 用户可读
        chmod 644 /etc/openvpn/crl.pem

        # 生成 server.conf
        echo "port $PORT" >/etc/openvpn/server.conf
        if [[ $IPV6_SUPPORT == 'n' ]]; then
                echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
        elif [[ $IPV6_SUPPORT == 'y' ]]; then
                echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
        fi

        echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
client-to-client
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

        # DNS 解析器
        case $DNS in
        0) # 不推送路由
                echo "不推送DNS配置到客户端"
                ;;

        1) # 当前系统解析器
                # 定位正确的 resolv.conf
                # 需要系统运行 systemd-resolved
                if grep -q "127.0.0.53" "/etc/resolv.conf"; then
                        RESOLVCONF='/run/systemd/resolve/resolv.conf'
                else
                        RESOLVCONF='/etc/resolv.conf'
                fi
                # 从 resolv.conf 获取解析器并用于 OpenVPN
                sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
                        # 复制，如果是 IPv4 |或| 如果启用了 IPv6，IPv4/IPv6 不重要
                        if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
                                echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
                        fi
                done
                ;;
        2) # 自托管 DNS 解析器 (Unbound)
                echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
                if [[ $IPV6_SUPPORT == 'y' ]]; then
                        echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
                fi
                ;;
        3) # Cloudflare
                echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
                ;;
        4) # Quad9
                echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
                ;;
        5) # Quad9 未过滤
                echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
                ;;
        6) # FDN
                echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
                ;;
        7) # DNS.WATCH
                echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
                ;;
        8) # OpenDNS
                echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
                ;;
        9) # Google
                echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
                ;;
        10) # Yandex Basic
                echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
                ;;
        11) # AdGuard DNS
                echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
                ;;
        12) # NextDNS
                echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
                echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
                ;;
        13) # 自定义 DNS
                echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
                if [[ $DNS2 != "" ]]; then
                        echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
                fi
                ;;
        esac
        # echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

        # IPv6 网络设置（如果需要）
        if [[ $IPV6_SUPPORT == 'y' ]]; then
                echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6' >>/etc/openvpn/server.conf
# push "route-ipv6 2000::/3"
# push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
        fi

        if [[ $COMPRESSION_ENABLED == "y" ]]; then
                echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
        fi

        if [[ $DH_TYPE == "1" ]]; then
                echo "dh none" >>/etc/openvpn/server.conf
                echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
        elif [[ $DH_TYPE == "2" ]]; then
                echo "dh dh.pem" >>/etc/openvpn/server.conf
        fi

        case $TLS_SIG in
        1)
                echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
                ;;
        2)
                echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
                ;;
        esac

        echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

        # 创建 client-config-dir 目录
        mkdir -p /etc/openvpn/ccd
        # 创建日志目录
        mkdir -p /var/log/openvpn

        # 启用路由
        echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
        if [[ $IPV6_SUPPORT == 'y' ]]; then
                echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
        fi
        # 应用 sysctl 规则
        sysctl --system

        # 如果启用了 SELinux 且选择了自定义端口，则需要此项
        if hash sestatus 2>/dev/null; then
                if sestatus | grep "Current mode" | grep -qs "enforcing"; then
                        if [[ $PORT != '1194' ]]; then
                                semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
                        fi
                fi
        fi

        # 最后，重启并启用 OpenVPN
        if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' || $OS == 'amzn2023' ]]; then
                # 不要修改包提供的服务
                cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

                # 解决 OpenVZ 上的 OpenVPN 服务问题
                sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
                # 另一个解决方法，继续使用 /etc/openvpn/
                sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service

                systemctl daemon-reload
                systemctl enable openvpn-server@server
                systemctl restart openvpn-server@server
        elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
                # 在 Ubuntu 16.04 上，我们使用 OpenVPN 仓库提供的包
                # 此包使用 sysvinit 服务
                systemctl enable openvpn
                systemctl start openvpn
        else
                # 不要修改包提供的服务
                cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

                # 解决 OpenVZ 上的 OpenVPN 服务问题
                sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
                # 另一个解决方法，继续使用 /etc/openvpn/
                sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

                systemctl daemon-reload
                systemctl enable openvpn@server
                systemctl restart openvpn@server
        fi

        if [[ $DNS == 2 ]]; then
                installUnbound
        fi

        # 在两个脚本中添加 iptables 规则
        mkdir -p /etc/iptables

        # 添加规则的脚本
        echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

        if [[ $IPV6_SUPPORT == 'y' ]]; then
                echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
        fi

        # 删除规则的脚本
        echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

        if [[ $IPV6_SUPPORT == 'y' ]]; then
                echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
        fi

        chmod +x /etc/iptables/add-openvpn-rules.sh
        chmod +x /etc/iptables/rm-openvpn-rules.sh

        # 通过 systemd 脚本处理规则
        echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

        # 启用服务并应用规则
        systemctl daemon-reload
        systemctl enable iptables-openvpn
        systemctl start iptables-openvpn

        # 如果服务器位于 NAT 之后，请使用正确的 IP 地址让客户端连接
        if [[ $ENDPOINT != "" ]]; then
                IP=$ENDPOINT
        fi

        # client-template.txt 已创建，以便我们稍后可以添加更多用户
        echo "client" >/etc/openvpn/client-template.txt
        if [[ $PROTOCOL == 'udp' ]]; then
                echo "proto udp" >>/etc/openvpn/client-template.txt
                echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
        elif [[ $PROTOCOL == 'tcp' ]]; then
                echo "proto tcp-client" >>/etc/openvpn/client-template.txt
        fi
        echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
verb 3" >>/etc/openvpn/client-template.txt

        if [[ $COMPRESSION_ENABLED == "y" ]]; then
                echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
        fi

        # 生成自定义 client.ovpn
        echo "服务端布署完成"
        echo "==================================================="
        echo "接下来我们生成首个客户端文件"
        newClient
        echo "如果您想添加更多客户端，只需再次运行此脚本！"
}

function newClient() {
        echo ""
        echo "告诉我客户端的名称。"
        echo "名称必须由字母数字字符组成。它也可以包含下划线或破折号。"

        until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
                read -rp "客户端名称: " -e CLIENT
        done

        echo ""
        echo "您是否要为客户端分配固定IP地址？"
        echo "   1) 使用动态IP"
        echo "   2) 分配固定IP"

        until [[ $FIXED_IP_CHOICE =~ ^[1-2]$ ]]; do
                read -rp "选择选项 [1-2]: " -e -i 2 FIXED_IP_CHOICE
        done

        FIXED_IP=""
        if [[ $FIXED_IP_CHOICE == "2" ]]; then
                # 获取下一个可用IP
                NEXT_IP=$(getNextAvailableIP)
                if [[ "$NEXT_IP" == "ERROR_NO_IP_AVAILABLE" ]]; then
                        echo "错误：没有可用的IP地址。"
                        exit 1
                fi

                echo ""
                echo "建议的固定IP地址: $NEXT_IP"
                echo "您可以使用建议的IP或输入自定义IP地址（格式：10.8.0.xxx，范围：100-254）"

                until [[ $FIXED_IP != "" ]]; do
                        read -rp "固定IP地址: " -e -i "$NEXT_IP" FIXED_IP

                        if [[ "$FIXED_IP" == "" ]]; then
                                FIXED_IP="$NEXT_IP"
                        fi

                        if ! validateIP "$FIXED_IP"; then
                                echo "错误：IP地址无效或已被使用。请选择其他IP地址。"
                                FIXED_IP=""
                        fi
                done

                echo "将为客户端 $CLIENT 分配固定IP: $FIXED_IP"
        fi

        echo ""
        echo "您是否要保护配置文件？"
        echo "（例如，用密码加密私钥）"
        echo "   1) 添加无密码客户端"
        echo "   2) 为客户端使用密码"

        until [[ $PASS =~ ^[1-2]$ ]]; do
                read -rp "选择选项 [1-2]: " -e -i 1 PASS
        done

        CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
        if [[ $CLIENTEXISTS == '1' ]]; then
                echo ""
                echo "指定的客户端CN已在easy-rsa中找到，请选择另一个名称。"
                exit
        else
                cd /etc/openvpn/easy-rsa/ || return
                case $PASS in
                1)
                        EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT" nopass
                        ;;
                2)
                        echo "⚠️ 您将在下面被要求输入客户端密码 ⚠️"
                        EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT"
                        ;;
                esac
                echo "客户端 $CLIENT 已添加。"
        fi

        # 如果选择了固定IP，创建CCD配置文件
        if [[ -n "$FIXED_IP" ]]; then
                echo "ifconfig-push $FIXED_IP 255.255.255.0" > "/etc/openvpn/ccd/$CLIENT"
                echo "已为客户端 $CLIENT 创建固定IP配置: $FIXED_IP"
        fi

        # Home directory of the user, where the client configuration will be written
        if [ -e "/home/${CLIENT}" ]; then
                # if $1 is a user name
                homeDir="/home/${CLIENT}"
        elif [ "${SUDO_USER}" ]; then
                # if not, use SUDO_USER
                if [ "${SUDO_USER}" == "root" ]; then
                        # If running sudo as root
                        homeDir="/root"
                else
                        homeDir="/home/${SUDO_USER}"
                fi
        else
                # if not SUDO_USER, use /root
                homeDir="/root"
        fi

        # Determine if we use tls-auth or tls-crypt
        if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
                TLS_SIG="1"
        elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
                TLS_SIG="2"
        fi

        # Generates the custom client.ovpn
        cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
        {
                echo "<ca>"
                cat "/etc/openvpn/easy-rsa/pki/ca.crt"
                echo "</ca>"

                echo "<cert>"
                awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
                echo "</cert>"

                echo "<key>"
                cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
                echo "</key>"

                case $TLS_SIG in
                1)
                        echo "<tls-crypt>"
                        cat /etc/openvpn/tls-crypt.key
                        echo "</tls-crypt>"
                        ;;
                2)
                        echo "key-direction 1"
                        echo "<tls-auth>"
                        cat /etc/openvpn/tls-auth.key
                        echo "</tls-auth>"
                        ;;
                esac
        } >>"$homeDir/$CLIENT.ovpn"

        echo ""
        echo "配置文件已写入 $homeDir/$CLIENT.ovpn。"
        echo "下载.ovpn文件并将其导入到您的OpenVPN客户端中。"
        if [[ -n "$FIXED_IP" ]]; then
                echo "此客户端将使用固定IP地址: $FIXED_IP"
        fi

        exit 0
}

function revokeClient() {
        NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
        if [[ $NUMBEROFCLIENTS == '0' ]]; then
                echo ""
                echo "您还没有创建客户端！"
                exit 1
        fi

        echo ""
        echo "选择您要撤销的现有客户端"
        tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
        until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
                if [[ $CLIENTNUMBER == '1' ]]; then
                        read -rp "选择一个客户端 [1]: " CLIENTNUMBER
                else
                        read -rp "选择一个客户端 [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
                fi
        done
        CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
        cd /etc/openvpn/easy-rsa/ || return
        ./easyrsa --batch revoke "$CLIENT"
        EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
        rm -f /etc/openvpn/crl.pem
        cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
        chmod 644 /etc/openvpn/crl.pem
        find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
        rm -f "/root/$CLIENT.ovpn"
        sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt

        # 清理固定IP配置
        if [[ -f "/etc/openvpn/ccd/$CLIENT" ]]; then
                rm -f "/etc/openvpn/ccd/$CLIENT"
                echo "已删除客户端 $CLIENT 的固定IP配置。"
        fi

        cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}

        echo ""
        echo "客户端 $CLIENT 的证书已被撤销。"
}

function removeUnbound() {
        # Remove OpenVPN-related config
        sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
        rm /etc/unbound/openvpn.conf

        until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
                echo ""
                echo "如果您在安装OpenVPN之前已经在使用Unbound，我删除了与OpenVPN相关的配置。"
                read -rp "您是否要完全删除Unbound？[y/n]: " -e REMOVE_UNBOUND
        done

        if [[ $REMOVE_UNBOUND == 'y' ]]; then
                # Stop Unbound
                systemctl stop unbound

                if [[ $OS =~ (debian|ubuntu) ]]; then
                        apt-get remove --purge -y unbound
                elif [[ $OS == 'arch' ]]; then
                        pacman --noconfirm -R unbound
                elif [[ $OS =~ (centos|amzn|oracle) ]]; then
                        yum remove -y unbound
                elif [[ $OS == 'fedora' ]]; then
                        dnf remove -y unbound
                fi

                rm -rf /etc/unbound/

                echo ""
                echo "Unbound已删除！"
        else
                systemctl restart unbound
                echo ""
                echo "Unbound未被删除。"
        fi
}

function removeOpenVPN() {
        echo ""
        read -rp "您真的想要卸载OpenVPN并删除相关文件吗？[y/n]: " -e -i n REMOVE
        if [[ $REMOVE == 'y' ]]; then
                # Get OpenVPN port from the configuration
                PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
                PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

                # Stop OpenVPN
                if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
                        systemctl disable openvpn-server@server
                        systemctl stop openvpn-server@server
                        # Remove customised service
                        rm /etc/systemd/system/openvpn-server@.service
                elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
                        systemctl disable openvpn
                        systemctl stop openvpn
                else
                        systemctl disable openvpn@server
                        systemctl stop openvpn@server
                        # Remove customised service
                        rm /etc/systemd/system/openvpn\@.service
                fi

                # Remove the iptables rules related to the script
                systemctl stop iptables-openvpn
                # Cleanup
                systemctl disable iptables-openvpn
                rm /etc/systemd/system/iptables-openvpn.service
                systemctl daemon-reload
                rm /etc/iptables/add-openvpn-rules.sh
                rm /etc/iptables/rm-openvpn-rules.sh

                # SELinux
                if hash sestatus 2>/dev/null; then
                        if sestatus | grep "Current mode" | grep -qs "enforcing"; then
                                if [[ $PORT != '1194' ]]; then
                                        semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
                                fi
                        fi
                fi

                if [[ $OS =~ (debian|ubuntu) ]]; then
                        apt-get remove --purge -y openvpn
                        if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
                                rm /etc/apt/sources.list.d/openvpn.list
                                apt-get update
                        fi
                elif [[ $OS == 'arch' ]]; then
                        pacman --noconfirm -R openvpn
                elif [[ $OS =~ (centos|amzn|oracle) ]]; then
                        yum remove -y openvpn
                elif [[ $OS == 'fedora' ]]; then
                        dnf remove -y openvpn
                fi

                # Cleanup
                find /home/ -maxdepth 2 -name "*.ovpn" -delete
                find /root/ -maxdepth 1 -name "*.ovpn" -delete
                rm -rf /etc/openvpn
                rm -rf /usr/share/doc/openvpn*
                rm -f /etc/sysctl.d/99-openvpn.conf
                rm -rf /var/log/openvpn

                # Unbound
                if [[ -e /etc/unbound/openvpn.conf ]]; then
                        removeUnbound
                fi
                echo ""
                echo "OpenVPN已卸载！"
        else
                echo ""
                echo "卸载已取消！"
        fi
}

function manageMenu() {
        echo "欢迎使用OpenVPN安装维护程序！"
        echo ""
        echo "OpenVPN服务已经安装"
        echo ""
        echo "您想要做什么？"
        echo "   1) 添加新用户"
        echo "   2) 注销已有用户"
        echo "   3) 卸载OpenVPN"
        echo "   4) 退出"
        until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
                read -rp "选择选项 [1-4]: " MENU_OPTION
        done

        case $MENU_OPTION in
        1)
                newClient
                ;;
        2)
                revokeClient
                ;;
        3)
                removeOpenVPN
                ;;
        4)
                exit 0
                ;;
        esac
}

# 检查 root、TUN、OS...
initialCheck

# 检查 OpenVPN 是否已安装
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
        manageMenu
else
        installOpenVPN
fi
