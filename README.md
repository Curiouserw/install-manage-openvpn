# 为实现更多功能，近期改动较多，有部分功能未实现。当前安装脚本不可用，请不要直接使用。欢迎各位大神提issue和pull request!
## 改动

- 优化
  - [x] 优化安装前检查系统命令
  - [x] 增加安装期间临时变更系统软件源为国内镜像源
  - [x] 修改记录客户端连接信息到钉钉的方式为记录到日志文件
  - [x] 优化系统日志文件路径
- 新增
  - [x] 在邮件中增加发送Windows客户端配置文件
  - [x] 新增设置SMTP服务时是否使用SSL协议端口
  - [x] 新增设置SMTP服务时发送测试邮件
  - [x] 新增IP地址池，直接给每个客户端分配固定IP地址。
- 实现中
  - [ ] 根据角色划分多个网段，同时使用iptables限制角色访问不同的内网网段
  - [ ] 检查并优化系统参数。



# 一、OpenVPN安装管理脚本

## 根据 https://github.com/Nyr/openvpn-install 进行的功能优化

1. 汉化
2. 增加选择客户端分配IP地址池网段的功能
3. 增加用户名密码验证脚本
4. 增加配置SMTP发送邮件的功能
5. 去除发送客户端连接、断开状态到钉钉Webhook机器人，改为记录到日志文件
6. 增加配置简单密码认证管理端口的功能
7. 增加创建用户后将用户名密码及配置文件等信息通过SMTP邮件服务发送到用户邮箱
8. 增加安装时控制是否允许客户端之间进行网络互联，是否允许客户端访问服务端所在的网络
9. 去除不必要的脚本代码

# 二、安装使用方法

```bash
git clone https://github.com/RationalMonster/install-manage-openvpn.git
bash install-manage-openvpn/ovpnx.sh
```

# 三、客户端连接方法参考

### Linux

```bash
openvpn --config 客户端配置文件(以.ovpn结尾的文件) --auth-user-pass --daemon
# 断开连接
ps -ef |grep openvpn |grep "daemon" |awk '{print $2}' | xargs kill -9
```

[参考文章](https://gitbook.curiouser.top/origin/openvpn-server.html)
