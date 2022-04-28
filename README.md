
## 改动

- 优化
  - [x] 优化安装前检查系统命令
  - [x] 增加安装期间检查临时变更系统软件源为国内镜像源
  - [x] 修改记录客户端连接信息到钉钉的方式为记录到日志文件
  - [x] 优化系统日志文件路径
  - [x] 优化文件存放目录
- 新增
  - [x] 在邮件中增加发送Windows客户端配置文件
  - [x] 新增设置SMTP服务时是否使用SSL协议端口
  - [x] 新增设置SMTP服务时发送测试邮件
  - [x] 新增IP地址池，直接给每个客户端分配固定IP地址，删除用户后并归还IP地址进行重复利用
  - [x] 实现根据角色划分网段的功能，使用iptables限制角色访问的网段，实现网络权限隔离限制
  - [x] 检查并优化系统参数
  - [x] 卸载时备份配置文件和iptables规则等相关文件到/tmp目录中



# 一、OpenVPN安装管理脚本

## 根据 https://github.com/Nyr/openvpn-install 进行的功能优化

1. 汉化
2. 增加选择客户端分配固定IP地址池网段的功能
3. 增加用户名密码验证脚本
4. 增加配置SMTP发送邮件的功能
5. 去除发送客户端连接、断开状态到钉钉Webhook机器人，改为记录到日志文件
6. 增加配置简单密码认证管理端口的功能
7. 增加创建用户后将用户名密码及配置文件等信息通过SMTP邮件服务发送到用户邮箱
8. 增加安装时控制是否允许客户端之间进行网络互联，是否允许客户端访问服务端所在的网络
9. 实现根据角色划分网段的功能，使用iptables限制角色访问的网段，实现网络权限隔离限制
10. 卸载时备份配置文件和iptables规则等相关文件到/tmp目录中
11. 新增用户时分配角色，设置网络访问策略
12. 去除不必要的脚本代码

# 二、安装使用方法

```bash
git clone https://github.com/RationalMonster/install-manage-openvpn.git
bash install-manage-openvpn/ovpnx.sh
```

# 三、客户端连接方法参考

## Linux

```bash
openvpn --config 客户端配置文件(以.ovpn结尾的文件) --auth-user-pass --daemon
# 断开连接
ps -ef |grep openvpn |grep "daemon" |awk '{print $2}' | xargs kill -9
```

## Windows

- Windows下使用客户端openvpn gui，将配置文件放置在`C盘:\用户\您的用户名\OpenVPN\config`目录下即可导入配置文件
- Openvpn GUI下载地址：https://openvpn.net/community-downloads/


## MacOS

- MacOS下使用客户端tunnelblick，将配置文件使用tunnelblick打开即可导入配置文件
- Tunnelblick下载地址：https://tunnelblick.net/downloads.html


# 参考文章

- https://gitbook.curiouser.top/origin/openvpn-server.html
- https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4
