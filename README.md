# openvpn-install

## FORK了https://github.com/angristan大佬的openvpn-install脚本，并针对对国内的内网组网需求做了定制化修改，默认支持client之间互联，不支持单配置文件多端复用（与固定IP冲突）
- 0、所有交互提示改为中文
- 1、增加客户端静态IP的选项，允许增加客户端时固定其内网IP
- 2、默认去除了全局路由推送、DNS推送，组网场景不使用服务器作为流量出口，不修改客户的DNS
- 3、增加了测试可用的获取公网IP的网站 http://ip.sb


## 使用方法

- 获取脚本，并授予执行权限
- 最好在全新安装的服务器安装，在使用其他方式安装过openvpn的服务器上可能会有异常


```bash
curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh
```

- 对于国内场景，easy-rsa无法直接下载，请手动下载后放到服务器/opt目录下，注意不要改文件名，使用其原始文件名 EasyRSA-3.1.2.tgz
- https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.2/EasyRSA-3.1.2.tgz

- 执行以验证EasyRSA是否就绪

```bash
ls /opt/EasyRSA-3.1.2.tgz > /dev/null 2>&1 && echo "EasyRSA已经正确上传，可以开始安装" || echo "EasyRSA未正确上传，请检查"
```

- 如EasyRSA已经正确上传，则可以开始安装

```bash
./openvpn-install.sh
```

最后请务必记得放通安全组/防火墙的对应端口
