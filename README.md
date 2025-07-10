# openvpn-install

## FORK了https://github.com/angristan 大佬的 openvpn-install 脚本，并针对对国内的内网组网需求做了定制化修改，默认支持client之间互联，不支持单配置文件多端复用（与固定IP冲突）
- 0、所有交互提示改为中文
- 1、增加客户端静态IP的选项，允许增加客户端时固定其内网IP
- 2、默认去除了全局路由推送、DNS推送，组网场景不使用服务器作为流量出口，不修改客户的DNS
- 3、增加了测试可用的获取公网IP的网站 http://ip.sb


## 使用方法

- 最好在全新安装的服务器部署，最好独立部署，不与其他应用共用服务器
- 对Linux发行版一般没有限制，但建议使用Ubuntu/CentOS/Debian的较新稳定版本

- 获取脚本，并授予执行权限

```bash
curl -O https://raw.githubusercontent.com/yaf0/openvpn-install/master/openvpn-install.sh
# 国内一般无法顺利下载，可以项目中直接复制脚本代码粘贴到终端，或者下载上传
chmod +x openvpn-install.sh
```

- 获取EasyRSA，并校验

```bash
wget -O /opt/EasyRSA-3.1.2.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.2/EasyRSA-3.1.2.tgz
# 国内easy-rsa一般也无法直接下载，请点击上面链接手动下载后放到服务器/opt目录下，注意不要改文件名，使用其原始文件名 EasyRSA-3.1.2.tgz
# 使用下面命令校验文件是否就绪
ls /opt/EasyRSA-3.1.2.tgz > /dev/null 2>&1 && echo "EasyRSA已经正确上传，可以开始安装" || echo "EasyRSA未正确上传，请检查"
```

- 如EasyRSA已经正确上传，则可以开始安装

```bash
./openvpn-install.sh
```

最后请务必记得放通安全组/防火墙的对应端口
