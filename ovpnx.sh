#!/bin/bash

#请勿删除该预制空变量，后续会赋予将安装后的用户角色编号
setup_subnet_roles_nu=1,2,3,5
developer_allowed_access_net=
tester_allowed_access_net=
manager_allowed_access_net=
bussiness_allowed_access_net=
robots_allowed_access_net=
# set -x

INSTALL_DIR=/etc/openvpn

check_command() {
	no_command=""
	if ! command -v ifconfig >/dev/null 2>&1; then
		no_command=$no_command"net-tools "
	fi
	if ! command -v ip >/dev/null 2>&1; then
		no_command=$no_command"iproute2 "
	fi
	if ! command -v curl >/dev/null 2>&1; then
		no_command=$no_command"curl "
	fi
	if ! command -v wget >/dev/null 2>&1; then
		no_command=$no_command"wget "
	fi
	if ! command -v ipset >/dev/null 2>&1; then
		no_command=$no_command"ipset "
	fi
	if ! command -v tail >/dev/null 2>&1; then
		no_command=$no_command"coreutils "
	fi
	if ! command -v sed >/dev/null 2>&1; then
		no_command=$no_command"sed "
	fi
	if ! command -v grep >/dev/null 2>&1; then
		no_command=$no_command"grep "
	fi
	if [[ ! -z "$no_command" ]]; then
		echo -e "\033[31m$no_command 命令不存在，正在下载安装！\033[0m"
		if os="ubuntu"; then
			apt install -y $no_command >/dev/null 2>&1
			rm -f /etc/apt/sources.list.d/tmp.list
		elif os="debian"; then
			apt install -y $no_command >/dev/null 2>&1
			rm -f /etc/apt/sources.list.d/tmp.list
		elif os="centos"; then
			yum install -y $no_command >/dev/null 2>&1
		elif os="fedora"; then
			dnf install -y $no_command >/dev/null 2>&1
		fi
	fi
}

system_check() {
	# Detect OS
	# $os_version variables aren't always in use, but are kept here for convenience
	if grep -qs "ubuntu" /etc/os-release; then
		os="ubuntu"
		os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
		group_name="nogroup"

	elif [[ -e /etc/debian_version ]];then
		os="debian"
		os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
		group_name="nogroup"
	elif [[ -e /etc/centos-release ]]; then
		os="centos"
		os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
		group_name="nobody"
	elif [[ -e /etc/fedora-release ]]; then
		os="fedora"
		os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
		group_name="nobody"
	else
		echo "本脚本只支持Ubuntu, Debian, CentOS, and Fedora."
		exit
	fi

	# Detect Debian users running the script with "sh" instead of bash
	if readlink /proc/$$/exe | grep -q "dash"; then
		echo '本脚本不支持使用sh执行'
		exit
	fi

	# Discard stdin. Needed when running from an one-liner which includes a newline
	read -N 999999 -t 0.001

	# Detect OpenVZ 6
	if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
		echo "内核太旧，本脚本不支持，请升级内核！"
		exit
	fi

	if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
		echo "本脚本仅支持Ubuntu 18.04 或更高的版本！"
		exit
	fi

	if [[ "$os" == "ubuntu" ]]; then
		if cat /etc/apt/sources.list |grep -vE "#" |grep -E "ustc.edu|aliyun|tuna.tsinghua|163" ;then
			echo "apt源已经是国内源，无需设置"
		else
			cp /etc/apt/sources.list /etc/apt/sources.list.d/tmp.list
			sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/tmp.list
			sed -i 's/security.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/tmp.list
			echo "临时更换Ubuntu apt源为中科大镜像站，正在apt update"
			apt update >/dev/null 2>&1
			check_command
		fi
	fi

	if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
		echo "本脚本仅支持Debian 9 或更高的版本！"
		exit
	fi
	if [[ "$os" == "debian" ]]; then
		cp /etc/apt/sources.list /etc/apt/sources.list.d/tmp.list
		sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/tmp.list
		sed -i 's/security.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/tmp.list
		echo "临时更换Debian apt源为中科大镜像站，正在apt update"
		apt update >/dev/null 2>&1
	fi

	if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
		echo "本脚本仅支持CentOS 7 或更高的版本！"
		exit
	fi

	# if [[ "$os" == "centos" ]];then
	# 	# todo: 临时更换Yum源
	# fi

	# Detect environments where $PATH does not include the sbin directories
	if ! grep -q sbin <<<"$PATH"; then
		echo '$PATH does not include sbin. Try using "su -" instead of "su".'
		exit
	fi

	if [[ "$EUID" -ne 0 ]]; then
		echo "本脚本仅支持使用root权限执行"
		exit
	fi

	if [[ ! -e /dev/net/tun ]] || ! (exec 7<>/dev/net/tun) >/dev/null 2>&1; then
		echo "The system does not have the TUN device available. Tun needs to be enabled before running this installer."
		exit
	fi

}

setup_smtp_server_profile() {
	read -p "SMTP服务器地址: " smtp_server_addr

	read -p "SMTP服务器是否使用SSL/TLS安全连接？[Yy/Nn] " setup_smtp_server_tls_ssl
	until [[ -z "$setup_smtp_server_tls_ssl" || "$setup_smtp_server_tls_ssl" =~ ^[yYnN]*$ ]]; do
		read -p "$setup_smtp_server_tls_ssl为无效的选项,SMTP服务器是否使用SSL/TLS连接？[Yy/Nn] " setup_client_profile_nat_pub_ip_domain
	done
	if [[ $setup_smtp_server_tls_ssl =~ ^[nN] ]]; then
		read -p "SMTP服务器端口: " smtp_server_port
		if [[ $smtp_server_port == 25 ]]; then
			smtp_url="smtp://$smtp_server_addr:$smtp_server_port"
		else
			echo "$smtp_server_port 是非常见SMTP服务商的普通端口，请和SMTP服务商确认。"
			exit
		fi
	elif [[ $setup_smtp_server_tls_ssl =~ ^[yY] ]]; then
		read -p "SMTP服务器安全端口: " smtp_server_security_port
		if [[ "$smtp_server_security_port" =~ ^[465|587] ]]; then
			smtp_url="smtps://$smtp_server_addr:$smtp_server_security_port"
		else
			echo "$smtp_server_security_port 是非常见SMTP服务商的安全端口，请和SMTP服务商确认。"
			exit
		fi

	fi

	read -p "SMTP服务器用户名: " smtp_server_user
	read -s -p "SMTP服务器用户密码: " smtp_server_passwd

	echo "FROM: $smtp_server_user
To: $smtp_server_user <$smtp_server_user>
Subject: SMTP测试邮件
Cc:
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="DELIMETER"

--DELIMETER
Content-Type: text/html; charset="utf-8"

<html>
<body>
<h2>OpenVPN服务SMTP测试邮件，请勿回复！</h2>
</body>
</html>

--DELIMETER
" >/tmp/emai-data.txt

	response=$(
		curl -s --ssl-reqd --write-out %{http_code} --output /dev/null \
			--url "$smtp_url" \
			--user "$smtp_server_user:$smtp_server_passwd" \
			--mail-from "$smtp_server_user" \
			--mail-rcpt $smtp_server_user \
			--upload-file /tmp/emai-data.txt
	)
	if [ $response -eq 250 ]; then
		{
			echo "smtp_server_addr=$smtp_server_addr"
			echo "smtp_server_port=${smtp_url##*:}"
			echo "smtp_server_user=$smtp_server_user"
			echo "smtp_server_passwd=$smtp_server_passwd"
		} >$INSTALL_DIR/server/smtp.conf
		echo
		echo "已通过SMTP服务器发送测试邮件。SMTP服务器设置成功！如需重新配置请直接修改$INSTALL_DIR/server/smtp.conf或删除后重新运行该脚本进行配置]"
		echo
	else
		echo "无法通过SMTP服务器发送测试邮件。SMTP服务返回状态码：$response 。请根据SMTP服务状态码检查SMTP服务配置！"
		exit 1
	fi
}

check_smtp_server_profile() {
	if [[ -f $INSTALL_DIR/server/smtp.conf ]]; then
		while read line; do
			eval "$line"
		done <$INSTALL_DIR/server/smtp.conf

		if [[ -z $smtp_server_addr || -z $smtp_server_port || -z $smtp_server_user || -z $smtp_server_passwd ]]; then
			echo "SMTP配置不全，请重新配置！"
			rm -rf $INSTALL_DIR/server/smtp.conf
			setup_smtp_server_profile
			exit
		else
			if [[ "$smtp_server_port" =~ ^[465|587] ]]; then
				smtp_url="smtps://$smtp_server_addr:$smtp_server_security_port"
			fi
			if [[ "$smtp_server_port" =~ ^[25] ]]; then
				smtp_url="smtp://$smtp_server_addr:$smtp_server_security_port"
			fi
		fi
	else
		echo "SMTP配置文件不存在,无法通过邮件发送新用户的配置！请先正确配置SMTP服务"
		setup_smtp_server_profile
	fi
}

send_email() {
	check_smtp_server_profile
	if [ $? -eq 0 ]; then
		windows_config_context=$(
			echo "windows-driver wintun"
			cat $4
		)
		echo "FROM: $smtp_server_user
To: $2 <$1>
Subject: VPN配置信息
Cc:
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="DELIMETER"

--DELIMETER
Content-Type: text/html; charset="utf-8"

<html>
<head>
    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />
    <style type=\"text/css\">
        p {text-indent: 4em;}
        h3 {text-indent: 2em;}
        .table {margin-left: 6em;}
    </style>
</head>
<body>
    <h2>Dear $2 :</h2>
    <h3>1. VPN配置信息</h3>
    <table class=\"table\" border=\"1\">
        <tr>
            <th>用户名</th>
            <th>密码</th>
            <th>配置文件</th>
        </tr>
        <tr>
            <td width="50">
                <font size=\"4\" color=\"red\">$2</font>
            </td>
            <td width="180">
                <font size=\"4\" color=\"red\">$3</font>
            </td>
            <td>
                <font size=\"4\" color=\"red\">见附件</font>
            </td>
        </tr>
    </table>
    <h3>2. 使用说明</h3>
    <p>Windows下使用客户端<b>openvpn gui</b>，下载附件中的配置文件，放置在<b>\"C盘:\用户\您的用户名\OpenVPN\config\"</b>目录下即可导入配置文件</p>
    <p>MacOS下使用客户端<b>tunnelblick</b>，下载附件中的配置文件，使用tunnelblick打开即可导入配置文件</p>
</body>
</html>

--DELIMETER
Content-Type: text/plain
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=\"OpenVPN-Windows.ovpn\"

[$(echo "$windows_config_context" | base64)]

--DELIMETER

--DELIMETER
Content-Type: text/plain
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=\"OpenVPN-MacOS.ovpn\"

[$(cat "$4" | base64)]

--DELIMETER
" >/tmp/emai-data.txt
		response=$(
			curl -s --ssl-reqd --write-out %{http_code} --output /dev/null \
				--url "$smtp_url" \
				--user "$smtp_server_user:$smtp_server_passwd" \
				--mail-from "$smtp_server_user" \
				--mail-rcpt $1 \
				--upload-file /tmp/emai-data.txt
		)
		if [ $response -eq 250 ]; then
			echo "新用户配置等信息已通过SMTP服务发送至用户邮箱，请提醒用户及时查收！"
			rm -f /tmp/emai-data.txt
		else
			echo "新用户配置等信息通过SMTP服务无法发送至用户邮箱，SMTP服务返回状态码：$response 。请根据SMTP服务状态码检查SMTP服务配置！"
		fi
	else
		exit
	fi
}


new_client_profile(){
	cd $INSTALL_DIR/server/easy-rsa/
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$1" nopass
	# Generates the custom client.ovpn
	{
		cat $INSTALL_DIR/server/client-common.txt
		echo "<ca>"
		cat $INSTALL_DIR/server/easy-rsa/pki/ca.crt
		echo "</ca>"
		echo "<cert>"
		sed -ne '/BEGIN CERTIFICATE/,$ p' $INSTALL_DIR/server/easy-rsa/pki/issued/"$1".crt
		echo "</cert>"
		echo "<key>"
		cat $INSTALL_DIR/server/easy-rsa/pki/private/"$1".key
		echo "</key>"
		echo "<tls-crypt>"
		sed -ne '/BEGIN OpenVPN Static key/,$ p' $INSTALL_DIR/server/pki/tc.key
		echo "</tls-crypt>"
	} >$INSTALL_DIR/client/profiles/"$1".ovpn
	client_random_password=$(echo $(date +%s)$RANDOM | md5sum | head -c 15)
	echo "$1 $client_random_password" >>$INSTALL_DIR/server/psw-file
	if [[ ! -f $INSTALL_DIR/server/ccd/$1 ]]; then
		cleint_ip=$(head -n 1 $INSTALL_DIR/server/ip-pools/$2-ip-pools)
		echo "ifconfig-push $cleint_ip 255.255.255.0" >>$INSTALL_DIR/server/ccd/$1
		echo -e "push \"route $3 255.255.255.0 $cleint_ip\"" >>$INSTALL_DIR/server/ccd/$1
		sed -i "/\<$cleint_ip\>/d" $INSTALL_DIR/server/ip-pools/$2-ip-pools
	fi
	echo "$2 $1" >> $INSTALL_DIR/server/clients-info
}
new_client() {
	check_smtp_server_profile
	if [ $? -eq 0 ]; then
		case "$2" in
		1)
			new_client_profile $1 developer $4
		;;
		2)
			new_client_profile $1 tester $4
			;;
		3)
			new_client_profile $1 manager $4
			;;
		4)
			new_client_profile $1 bussiness $4
			;;
		5)
			new_client_profile $1 robots $4
			;;
		esac

		send_email $3 $1 $client_random_password $INSTALL_DIR/client/profiles/$1.ovpn
		
	fi
}

mask2cdr() {
	local x=${1##*255.}
	set -- 0^^128^192^224^240^248^252^254^ $(((${#1} - ${#x}) * 2)) ${x%%.*}
	x=${1%%$3*}
	echo $(($2 + (${#x} / 4)))
}

if [[ ! -e $INSTALL_DIR/server/server.conf ]]; then
	system_check
	clear
	echo 'OpenVPN安装管理脚本(根据https://github.com/Nyr/openvpn-install进行的优化), 以下为优化的功能:'
	echo "    1. 汉化"
	echo "    2. 增加选择客户端分配IP地址池网段的功能"
	echo "    3. 增加用户名密码验证脚本"
	echo "    4. 增加配置SMTP发送邮件的功能"
	echo "    5. 增加发送客户端连接、断开状态到日志文件"
	echo "    6. 增加配置简单密码认证管理端口的功能"
	echo "    7. 增加创建用户后将用户名密码及配置文件等信息通过SMTP邮件服务发送到用户邮箱"
	echo "    8. 增加安装时控制是否允许客户端之间进行网络互联，是否允许客户端访问服务端所在的网络"
	echo "    9. 去除不必要的脚本代码"
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		ip_nu=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "1. OpenVPN服务端监听在以下哪个IPv4地址上?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4地址，默认[1]: " listen_ip_nu
		until [[ -z "$listen_ip_nu" || "$listen_ip_nu" =~ ^[0-9]+$ && "$listen_ip_nu" -le "$ip_nu" ]]; do
			echo "$listen_ip_nu: 无效的选项."
			read -p "IPv4地址[1]: " listen_ip_nu
		done
		[[ -z "$listen_ip_nu" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$listen_ip_nu"p)
	fi
	server_ip_local_netmask=$(ifconfig -a|grep $ip | grep -w 'inet' | awk -F'[ :]+' '{print $5}')

	server_ip_local_net_cdr=$(mask2cdr $server_ip_local_netmask)
	case "$server_ip_local_net_cdr" in
	8)
		server_ip_local_net=$(echo $ip | awk -F'.' '{print $1".0.0.0"}')
		server_ip_local_net_with_cdr=$(echo $server_ip_local_net"/8")
		;;
	16)
		server_ip_local_net=$(echo $ip | awk -F'.' '{print $1"."$2".0.0"}')
		server_ip_local_net_with_cdr=$(echo $server_ip_local_net"/16")
		;;
	24)
		server_ip_local_net=$(echo $ip | awk -F'.' '{print $1"."$2"."$3".0"}')
		server_ip_local_net_with_cdr=$(echo $server_ip_local_net"/24")
		;;
	32)
		server_ip_local_net=$(echo $ip | awk -F'.' '{print $1"."$2"."$3"."$4}')
		server_ip_local_net_with_cdr=$(echo $server_ip_local_net"/32")
		;;
	esac

	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: 无效的选项."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi

	echo

	echo "2. 配置OpenVPN使用的通信协议?"
	echo -e "  1) \033[41;30mTCP (推荐)\033[0m"
	echo -e "  2) \033[41;30mUDP\033[0m"
	read -p "默认协议（默认TCP[1]）: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: 无效的选项."
		read -p "Protocol [1]: " protocol
	done
	case "$protocol" in
	1 | "")
		protocol=tcp
		;;
	2)
		protocol=udp
		;;
	esac

	echo

	echo "3. 配置客户端IP地址池网段模式:"
	echo -e "  1) 单网络段模式：\033[41;30m所有客户端分配至在一个网络段中,所有用户访问相同的服务端网段。适用于客户端个数少于254个的情况\033[0m"
	echo -e "  2) 多网络段模式：\033[41;30m可将客户端划分角色分配到不同网络段中,不同角色访问不同的服务端网段。同时适用于客户端个数多于254个的情况\033[0m"
	read -p "客户端IP地址池网段模式（默认单网段模式[1]）: " server_ip_subnet_option
	until [[ -z "$server_ip_subnet_option" || "$server_ip_subnet_option" =~ ^[1|2]$ ]]; do
		read -p "$server_ip_subnet_option 为无效的选项。客户端IP地址池网段模式[1]: " server_ip_subnet_option
	done
	[[ -z "$server_ip_subnet_option" ]] && server_ip_subnet_option="1"
	echo
	 
	case "$server_ip_subnet_option" in
	1 )
		echo "4. 单网络段模式：配置OpenVPN客户端IP地址池网段"
		echo -e "  1) \033[41;30m10.8.1.0\033[0m"
		echo -e "  2) \033[41;30m10.6.2.0\033[0m"
		echo -e "  3) \033[41;30m自定义客户端IP地址池网段\033[0m"
		read -p "单网络段模式：默认分配客户端IP地址池网段[1]: " server_single_ip_net_option

		[[ -z "$server_single_ip_net_option" ]] && server_single_ip_net_option="1"
		case "$server_single_ip_net_option" in
		1)
			server_ip_net="10.8.1.0"
			;;
		2)
			server_ip_net="10.6.2.0"
			;;
		3)
			read -p "请输入自定义的客户端IP地址池网段(规则: 四段位,前三段位数值范围1~254,最后一段需为0): " unsanitized_server_ip_net
			server_ip_net=$(sed 's/[^[1-9][0-9]{1,3}\.[0-9]{1,3}\.[1-9][0-9]{1,3}\.0$]/_/g' <<<"$unsanitized_server_ip_net")
			until [[ -z "$server_ip_net" || $server_ip_net =~ ^[1-9][0-9]{1,3}\.[0-9]{1,3}\.[1-9][0-9]{1,3}\.0$ && $(echo $server_ip_net | awk -F. '$1<255&&$2<255&&$3<255&&$4<255{print "yes"}') == "yes" ]]; do
				echo "  $server_ip_net为无效的IP地址池网段"
				read -p "  请输入有效的客户端IP地址池网段: " server_ip_net
			done
			;;
		esac
		;;
	2)

		read -p "4. 请客户端IP地址池主网段(例如：10.6.0.0): " server_ip_net
		until [[ -z "$server_ip_net" || $server_ip_net =~ ^[1-9][0-9]{1,3}\.[0-9]{1,3}\.0\.0$ && $(echo $server_ip_net | awk -F. '$1<255&&$2<255&&$3<255&&$4<255{print "yes"}') == "yes" ]]; do
			echo "  $server_ip_net为无效的IP地址池网段"
			read -p "  请设置有效的客户端IP地址池网段: " server_ip_net
		done
		echo 
		server_ip_net_prefix=$(echo $server_ip_net | cut -d . -f 1,2)
		echo "5. 请设置客户端角色，内置角色网段划分，可根据编号选择，多个已逗号分割："
		echo -e "  1) \033[41;30m开发人员角色\033[0m"
		echo -e "  2) \033[41;30m测试人员角色\033[0m"
		echo -e "  3) \033[41;30m运维人员角色\033[0m"
		echo -e "  4) \033[41;30m业务人员角色\033[0m"
		echo -e "  5) \033[41;30m机器人 角 色\033[0m"
		echo -e "  6) \033[41;30m以上所有角色\033[0m"
		read -p "请选择预设置客户端角色: " server_ip_subnet_roles
		until [[ -z "$server_ip_subnet_roles" || ${server_ip_subnet_roles} =~ ^[1-9,]{1,9}$ ]];do
			echo "  $server_ip_subnet_roles为无效值"
			read -p "请重新设置客户端角色: " server_ip_subnet_roles
		done
		if [[ $server_ip_subnet_roles == 6 ]];then
			server_ip_subnet_roles=1,2,3,4,5
		fi
		sed -i -e "s/^setup_subnet_roles_nu=.*/setup_subnet_roles_nu=$server_ip_subnet_roles/g" $0
		for i in ${server_ip_subnet_roles//,/ };do
			case $i in
				1)
					read -e -p "  请设置开发人员角色IP地址网段：" -i "${server_ip_net_prefix}." server_subnet_developer_ip_pool
					until [[ ! -z "$server_subnet_developer_ip_pool" && $server_subnet_developer_ip_pool =~ ^$server_ip_net_prefix.[1-9]{1,3}\.0$ ]]; do
						read -e -p "  $server_subnet_developer_ip_pool不属于$server_ip_net下的子网段，请重新设置开发人员角色IP地址网段: " -i "${server_ip_net_prefix}." server_subnet_developer_ip_pool
					done
				;;
				2)
					read -e -p "  请设置测试人员角色IP地址网段：" -i "${server_ip_net_prefix}." server_subnet_tester_ip_pool
					until [[ ! -z "$server_subnet_tester_ip_pool" && ! $server_subnet_tester_ip_pool == $server_subnet_developer_ip_pool ]];do
						read -p "  $server_subnet_tester_ip_pool网段已被占用，请重新设置测试人员角色IP地址网段：" server_subnet_tester_ip_pool
						until [[ $server_subnet_tester_ip_pool =~ ^$server_ip_net_prefix.[1-9]{1,3}\.0$ ]]; do
							read -e -p "  $server_subnet_tester_ip_pool不属于$server_ip_net下的子网段，请重新设置测试人员角色IP地址网段: " -i "${server_ip_net_prefix}." server_subnet_tester_ip_pool
						done
					done
				;;
				3)
					read -e -p "  请设置运维人员角色IP地址网段：" -i "${server_ip_net_prefix}." server_subnet_manager_ip_pool
					until [[ ! -z "$server_subnet_manager_ip_pool" && ! $server_subnet_manager_ip_pool == $server_subnet_developer_ip_pool && ! $server_subnet_manager_ip_pool == $server_subnet_tester_ip_pool ]]; do
						read -p "  $server_subnet_manager_ip_pool网段已被占用，请重新设置运维人员角色IP地址网段：" server_subnet_manager_ip_pool
						until [[ $server_subnet_manager_ip_pool =~ ^$server_ip_net_prefix.[1-9]{1,3}\.0$ ]]; do
							read -e -p "  $server_subnet_manager_ip_pool不属于$server_ip_net下的子网段，请重新设置运维人员角色IP地址网段: " -i "${server_ip_net_prefix}." server_subnet_manager_ip_pool
						done
					done
				;;
				4)
					read -e -p "  请设置业务人员角色IP地址网段：" -i "${server_ip_net_prefix}." server_subnet_bussiness_ip_pool

					until [[ ! -z "$server_subnet_bussiness_ip_pool" && ! $server_subnet_bussiness_ip_pool == $server_subnet_developer_ip_pool && ! $server_subnet_bussiness_ip_pool == $server_subnet_tester_ip_pool && ! $server_subnet_bussiness_ip_pool == $server_subnet_manager_ip_pool ]]; do
						read -p "  $server_subnet_bussiness_ip_pool网段已被占用，请重新设置业务人员角色IP地址网段：" server_subnet_bussiness_ip_pool
						until [[ $server_subnet_bussiness_ip_pool =~ ^$server_ip_net_prefix.[1-9]{1,3}\.0$ ]]; do
							read -e -p "  $server_subnet_bussiness_ip_pool不属于$server_ip_net下的子网段，请重新设置业务人员角色IP地址网段: " -i "${server_ip_net_prefix}." server_subnet_bussiness_ip_pool
						done
					done
				;;
				5)
					read -e -p "  请设置机器人 角 色IP地址网段：" -i "${server_ip_net_prefix}." server_subnet_robots_ip_pool
					
					until [[ ! -z "$server_subnet_robots_ip_pool" && ! $server_subnet_robots_ip_pool == $server_subnet_developer_ip_pool && ! $server_subnet_robots_ip_pool == $server_subnet_tester_ip_pool && ! $server_subnet_robots_ip_pool == $server_subnet_manager_ip_pool && ! $server_subnet_robots_ip_pool == $server_subnet_bussiness_ip_pool ]]; do
						read -p "  $server_subnet_robots_ip_pool网段已被占用，请重新设置机器人角色IP地址网段：" server_subnet_robots_ip_pool
						until [[ $server_subnet_robots_ip_pool =~ ^$server_ip_net_prefix.[1-9]{1,3}\.0$ ]]; do
							read -e -p "  $server_subnet_robots_ip_pool不属于$server_ip_net下的子网段，请重新设置机器人角色IP地址网段: " -i "${server_ip_net_prefix}." server_subnet_robots_ip_pool
						done
					done				
				;;
			esac
		done
		;;
	esac

	echo

	read -p "6. 配置OpenVPN服务端监听的端口? 默认端口[11940]: " port
	until [[ -z "$port" || "$port" =~ ^[1-9]+$ && "$port" -le 65535 && "$port" -gt 1024 ]]; do
		echo "$port 端口无效，请设置1025 <= => 65535范围之内的端口号: "
		read -p "默认端口[1194]: " port
	done
	[[ -z "$port" ]] && port="11940"

	echo

	read -p "7. 是否在客户端配置文件中设置NAT的公网IP地址或域名[Yy/Nn]? " setup_client_profile_nat_pub_ip_domain
	until [[ -z "$setup_client_profile_nat_pub_ip_domain" || "$setup_client_profile_nat_pub_ip_domain" =~ ^[yYnN]*$ ]]; do
		read -p "$setup_client_profile_nat_pub_ip_domain为无效的选项,是否在客户端配置文件中设置NAT的公网IP地址或域名[Yy/Nn]? " setup_client_profile_nat_pub_ip_domain
	done
	[[ -z "$setup_client_profile_nat_pub_ip_domain" ]] && setup_client_profile_nat_pub_ip_domain="y"
	case "$setup_client_profile_nat_pub_ip_domain" in
	y | Y)
		read -p "设置NAT的公网IP地址或域名: " client_profile_nat_pub_ip_domain
		until [[ ! -z "$client_profile_nat_pub_ip_domain" && "$client_profile_nat_pub_ip_domain" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$client_profile_nat_pub_ip_domain" =~ ^[a-zA-Z\.]*$ ]]; do
			read -p "$client_profile_nat_pub_ip_domain为无效的IP地址与域名，请重新设置NAT的公网IP地址或域名: " client_profile_nat_pub_ip_domain
		done
		;;
	n | N) ;;

	esac

	echo

	read -p "8. 是否允许客户端间互联[Yy/Nn]? " setup_client_conn
	until [[ -z "$setup_client_conn" || "$setup_client_conn" =~ ^[yYnN]*$ ]]; do
		read -p "  $setup_client_conn为无效的选项,是否允许客户端间互联[Yy/Nn]? " setup_client_conn
	done
	[[ -z "$setup_client_conn" ]] && setup_client_conn="y"

	echo

	read -p "9. 是否允许客户端访问服务端所在网段[Yy/Nn]? " setup_client_conn_server_net
	until [[ -z "$setup_client_conn_server_net" || "$setup_client_conn_server_net" =~ ^[yYnN]*$ ]]; do
		read -p "  $setup_client_conn_server_net为无效的选项,是否允许客户端访问服务端所在网段[Yy/Nn]? " setup_client_conn_server_net
	done
	[[ -z "$setup_client_conn_server_net" ]] && setup_client_conn_server_net="y"

    for i in ${server_ip_subnet_roles//,/ };do
		case $i in
			1)
				read -p "  请设置开发人员角色允许访问的内网网段或特定IP地址(多个网段或IP地址以逗号分割)：" client_role_developer_allow_net 
				sed -i -e "s/^developer_allowed_access_net=.*/developer_allowed_access_net=$client_role_developer_allow_net/g" $0
			;;
			2)
				read -p "  请设置测试人员角色允许访问的内网网段或特定IP地址(多个网段或IP地址以逗号分割)：" client_role_tester_allow_net 
				sed -i -e "s/^tester_allowed_access_net=.*/tester_allowed_access_net=$client_role_developer_allow_net/g" $0
			;;
			3)
				read -p "  请设置运维人员角色允许访问的内网网段或特定IP地址(多个网段或IP地址以逗号分割)：" client_role_manager_allow_net 
				sed -i -e "s/^manager_allowed_access_net=.*/manager_allowed_access_net=$client_role_developer_allow_net/g" $0
			;;
			4)
				read -p "  请设置业务人员角色允许访问的内网网段或特定IP地址(多个网段或IP地址以逗号分割)：" client_role_bussiness_allow_net 
				sed -i -e "s/^bussiness_allowed_access_net=.*/bussiness_allowed_access_net=$client_role_developer_allow_net/g" $0
			;;
			5)
				read -p "  请设置机器人 角 色允许访问的内网网段或特定IP地址(多个网段或IP地址以逗号分割)：" client_role_robots_allow_net 
				sed -i -e "s/^robots_allowed_access_net=.*/robots_allowed_access_net=$client_role_developer_allow_net/g" $0
			;;
		esac	
	done
	

	echo

	read -p "10. 是否配置管理端口?[Yy/Nn]? " setup_management
	until [[ -z "$setup_management" || "$setup_management" =~ ^[yYnN]*$ ]]; do
		read -p "  $setup_management为无效的选项，是否配置管理端口?[Yy/Nn] " setup_management
	done
	[[ -z "$setup_management" ]] && setup_management="y"

	echo

	case "$setup_management" in
	y | Y)
		read -p "  设置管理端口[默认27506]: " management_port
		until [[ -z "$management_port" || ${management_port} =~ ^[0-9]{0,5}$ && $management_port -le 65535 && $management_port -gt 1024 ]]; do
			read -p "  $management_port为无效的端口，请重新设置1025 <= => 65535之内的端口: " management_port
		done
		[[ -z "$management_port" ]] && management_port=27506

		read -p $'  设置管理端口登录密码(默认生产15位随机0-9a-zA-Z字符串密码): ' management_psw
		until [[ -z "$management_psw" || ${management_psw} =~ ^[0-9a-zA-Z]{15}$ ]]; do
			read -s -p "  设置的密码过于简单，请重新设置更为复杂的密码: " management_psw
		done
		[[ -z "$management_psw" ]] && management_psw=$(echo $(date +%s)$RANDOM | md5sum | base64 | head -c 15)
		;;
	n | N) ;;

	esac

	echo

	echo "11. 开始准备安装OpenVPN服务端"
	read -n1 -r -p "  按任意键继续"
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		echo "  正在下载安装OpenVPN软件"
		apt-get update >/dev/null 2>&1
		apt-get install -y openvpn openssl ca-certificates $firewall >/dev/null 2>&1
	elif [[ "$os" = "centos" ]]; then
		echo "  正在下载安装OpenVPN软件"
		yum install -y epel-release >/dev/null 2>&1
		yum install -y openvpn openssl ca-certificates tar $firewall >/dev/null 2>&1
	else
		# Else, OS must be Fedora
		echo "  正在下载安装OpenVPN软件"
		dnf install -y openvpn openssl ca-certificates tar $firewall >/dev/null 2>&1
	fi
	# 下载安装证书工具easy-rsa
	mkdir -p $INSTALL_DIR/server/{easy-rsa,ccd,logs,ip-pools,pki} $INSTALL_DIR/client/profiles
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.7/EasyRSA-3.0.7.tgz'
	echo "  正在下载easy-rsa证书工具"
    wget --tries=3 --continue --timeout=10 --show-progress --progress=dot -q $easy_rsa_url -O - | tar -xzf - -C /etc/openvpn/server/easy-rsa --strip-components 1 --exclude doc
	if [[ $? == 0 && -f $INSTALL_DIR/server/easy-rsa/easyrsa ]] ;then
		chown -R root:root $INSTALL_DIR/server
		# 创建CA和客户端证书
		cd $INSTALL_DIR/server/easy-rsa/
		echo 
		echo "  正在创建CA和客户端证书"
		./easyrsa init-pki >/dev/null 2>&1
		./easyrsa --batch build-ca nopass >/dev/null 2>&1
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass >/dev/null 2>&1
		# EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl >/dev/null 2>&1
		# Move the stuff we need
		cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem $INSTALL_DIR/server/pki
		# CRL is read with each client connection, while OpenVPN is dropped to nobody
		chown nobody:"$group_name" $INSTALL_DIR/server/pki/crl.pem
		# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
		chmod o+x $INSTALL_DIR/server/
		# Generate key for tls-crypt
		openvpn --genkey --secret $INSTALL_DIR/server/pki/tc.key >/dev/null 2>&1
		# Create the DH parameters file using the predefined ffdhe2048 group
		echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' >$INSTALL_DIR/server/pki/dh.pem
	else
		echo "easy-rsa证书工具下载失败，请检查网络状态"
		sed -i 's/^setup_subnet_roles_nu=.*/setup_subnet_roles_nu=/g' $0
		rm -rf $INSTALL_DIR
		exit 1
	fi
	# Install a firewall in the rare case where one is not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "安装防火墙软件firewalld"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
			echo "安装防火墙软件iptables"
		fi
	fi
	echo "  正在检查防火墙软件，当前操作系统的防护墙为: $firewall"
	
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/nul
		echo "[Service]
LimitNPROC=infinity" >/etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		echo "  开启防火墙"
		systemctl enable --now firewalld.service >/dev/null 2>&1
	fi
		
	if [[ ! -z "$server_subnet_developer_ip_pool" ]]; then
		seq -f "${server_subnet_developer_ip_pool%.*}.%g" 2 254 > $INSTALL_DIR/server/ip-pools/developer-ip-pools
	fi
	if [[ ! -z "$server_subnet_tester_ip_pool" ]]; then
		seq -f "${server_subnet_tester_ip_pool%.*}.%g" 2 254 > $INSTALL_DIR/server/ip-pools/tester-ip-pools
	fi
	if  [[ ! -z "$server_subnet_manager_ip_pool" ]]; then
		seq -f "${server_subnet_manager_ip_pool%.*}.%g" 2 254 > $INSTALL_DIR/server/ip-pools/manager-ip-pools
	fi
	if  [[ ! -z "$server_subnet_bussiness_ip_pool" ]]; then
		seq -f "${server_subnet_bussiness_ip_pool%.*}.%g" 2 254 > $INSTALL_DIR/server/ip-pools/bussiness-ip-pools
	fi
	if  [[ ! -z "$server_subnet_robots_ip_pool" ]]; then
		seq -f "${server_subnet_robots_ip_pool%.*}.%g" 2 254 > $INSTALL_DIR/server/ip-pools/robots-ip-pools
	fi

	# 生成OpenVPN服务端配置文件
	echo "  正在生成OpenVPN服务端配置文件"
	echo "local 0.0.0.0
port $port
proto $protocol
dev tun
ca pki/ca.crt
cert pki/server.crt
key pki/server.key
dh pki/dh.pem
auth SHA512
tls-crypt pki/tc.key
crl-verify pki/crl.pem
topology subnet
mute 30
auth-user-pass-verify openvpn-utils.sh via-env
username-as-common-name
verb 3
script-security 3
client-config-dir ccd
ifconfig-pool-persist ipp.txt
log-append logs/openvpn-server.log
server $server_ip_net 255.255.0.0" >$INSTALL_DIR/server/server.conf
	echo "  正在生成OpenVPN服务端脚本"
	echo "#!/bin/sh
PASSFILE=\"$INSTALL_DIR/server/psw-file\"
LOG_FILE=\"$INSTALL_DIR/server/logs/openvpn-all-\$(date \"+%Y-%m-%d\").log\"
TIME_STAMP=\`date \"+%Y-%m-%d %T\"\`
swap_seconds ()
{
    SEC=\$1
    [ \"\$SEC\" -le 60 ] && echo \"\$SEC秒\"
    [ \"\$SEC\" -gt 60 ] && [ \"\$SEC\" -le 3600 ] && echo \"\$(( SEC / 60 ))分钟\$(( SEC % 60 ))秒\"
    [ \"\$SEC\" -gt 3600 ] && echo \"\$(( SEC / 3600 ))小时\$(( (SEC % 3600) / 60 ))分钟\$(( (SEC % 3600) % 60 ))秒\"
}

if [ \$script_type = 'user-pass-verify' ] ; then
	if [ ! -r \"\${PASSFILE}\" ]; then
		echo \"\${TIME_STAMP}: Could not open password file \"\${PASSFILE}\" for reading.\" >> \${LOG_FILE}
		exit 1
	fi
	CORRECT_PASSWORD=\`awk '!/^;/&&!/^#/&&\$1==\"'\${username}'\"{print \$2;exit}' \${PASSFILE}\`
	if [ \"\${CORRECT_PASSWORD}\" = \"\" ]; then
		echo \"\${TIME_STAMP}: User does not exist: username=\"\${username}\", password=\"\${password}\".\" >> \${LOG_FILE}
		exit 1
	fi
	if [ \"\${password}\" = \"\${CORRECT_PASSWORD}\" ]; then
		echo \"\${TIME_STAMP}: Successful authentication: username=\"\${username}\".\" >> \${LOG_FILE}
		exit 0
	fi
	echo \"\${TIME_STAMP}: Incorrect password: username=\"\${username}\", password=\"\${password}\".\" >> \${LOG_FILE}
	exit 1
fi

case  \"\$IV_PLAT\" in
  os )
    device_type=ios
  ;;
  win )
    device_type=Windows
  ;;
  linux )
    device_type=Linux
  ;;
  solaris )
    device_type=Solaris
  ;;
  openbsd )
    device_type=OpenBSD
  ;;
  mac )
    device_type=Mac
  ;;
  netbsd )
    device_type=NetBSD
  ;;
  freebsd )
    device_type=FreeBSD
  ;;
  * )
    device_type=None
  ;;
esac

if [ \$script_type = 'client-connect' ] ; then
  echo \"\${TIME_STAMP}: \$common_name 连接了OpenVPN. 设备: \$device_type IP端口: \$trusted_ip:\$trusted_port 端对端IP: \$ifconfig_pool_remote_ip <===> \$ifconfig_local\" >> \${LOG_FILE}
fi
if [ \$script_type = 'client-disconnect' ]; then
	duration_time=\`swap_seconds \$time_duration\`
  	echo \"\${TIME_STAMP}: \$common_name 断开了OpenVPN. 设备: \$device_type IP端口: \$trusted_ip:\$trusted_port 端对端IP: \$ifconfig_pool_remote_ip <===> \$ifconfig_local 持续时间: \$duration_time \" >> \${LOG_FILE}
fi
" >$INSTALL_DIR/server/openvpn-utils.sh
	chmod +x $INSTALL_DIR/server/openvpn-utils.sh

	echo "keepalive 10 120
cipher AES-256-CBC
user root
group $group_name
persist-key
persist-tun
status logs/openvpn-status.log
client-connect openvpn-utils.sh
client-disconnect openvpn-utils.sh" >>$INSTALL_DIR/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >>$INSTALL_DIR/server/server.conf
	fi

	# if [[ "$setup_client_conn_server_net" =~ ^[yY]$ ]]; then
	# 	echo "push \"route $server_ip_local_net $server_ip_local_netmask\"" >>$INSTALL_DIR/server/server.conf
	# fi

	if [[ "$setup_client_conn" =~ ^[yY]$ ]]; then
		echo "client-to-client" >>$INSTALL_DIR/server/server.conf
	fi
	if [[ "$setup_management" =~ ^[yY]$ && ${management_port} ]]; then
		echo $management_psw >$INSTALL_DIR/server/management-psw-file
		echo "management 127.0.0.1 $management_port management-psw-file" >>$INSTALL_DIR/server/server.conf
	fi

	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/30-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo "  正在开起内核路由转发功能"
	echo 1 >/proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >/etc/sysctl.d/30-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 >/proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source="$server_ip_net"/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source="$server_ip_net"/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s "$server_ip_net"/24 ! -d "$server_ip_net"/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "$server_ip_net"/24 ! -d "$server_ip_net"/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		
		echo "  正在生成OpenVPN的iptables规则"
		echo "[Unit]
Before=network.target

[Service]
Type=oneshot
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT

ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
		" >>/etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service >/dev/null 2>&1

		if [[ "$setup_client_conn_server_net" =~ ^[yY]$ && ! -z $server_subnet_developer_ip_pool ]] ;then
			echo "[Unit]
Before=network.target

[Service]
Type=oneshot
ExecStart=$iptables_path  -I FORWARD -s $server_subnet_developer_ip_pool/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $server_subnet_developer_ip_pool/24 -j ACCEPT
# ============================开发人员放行网段============================" >>/etc/systemd/system/openvpn-iptables-developer.service
			if [[ ! -z $client_role_developer_allow_net ]]; then
				for i in ${client_role_developer_allow_net//,/ };do
					echo -e "ExecStart=$iptables_path -t nat -I POSTROUTING -s $server_subnet_developer_ip_pool/24 -d $i -j SNAT --to $ip\nExecStop=$iptables_path -t nat -D POSTROUTING -s $server_subnet_developer_ip_pool/24 -d $i -j SNAT --to $ip\n" >>/etc/systemd/system/openvpn-iptables-developer.service
				done
			fi
			echo -e "RemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target" >>/etc/systemd/system/openvpn-iptables-developer.service
			systemctl enable --now openvpn-iptables-developer.service >/dev/null 2>&1
		fi

		if [[ "$setup_client_conn_server_net" =~ ^[yY]$ && ! -z $server_subnet_tester_ip_pool ]] ;then
			echo "[Unit]
Before=network.target

[Service]
Type=oneshot
ExecStart=$iptables_path  -I FORWARD -s $server_subnet_tester_ip_pool/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $server_subnet_tester_ip_pool/24 -j ACCEPT
# ============================测试人员放行网段============================" >>/etc/systemd/system/openvpn-iptables-tester.service
			if [[ "$setup_client_conn_server_net" =~ ^[yY]$ && ! -z $client_role_tester_allow_net ]]; then
				for i in ${client_role_tester_allow_net//,/ };do
					echo -e "ExecStart=$iptables_path -t nat -I POSTROUTING -s $server_subnet_tester_ip_pool/24 -d $i -j SNAT --to $ip\nExecStop=$iptables_path -t nat -D POSTROUTING -s $server_subnet_tester_ip_pool/24 -d $i -j SNAT --to $ip\n" >>/etc/systemd/system/openvpn-iptables-tester.service
				done
			fi
			echo -e "RemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target" >>/etc/systemd/system/openvpn-iptables-tester.service
			systemctl enable --now openvpn-iptables-tester.service >/dev/null 2>&1
		fi

		if [[ "$setup_client_conn_server_net" =~ ^[yY]$ && ! -z $server_subnet_manager_ip_pool ]] ;then
			echo "[Unit]
Before=network.target

[Service]
Type=oneshot
ExecStart=$iptables_path  -I FORWARD -s $server_subnet_manager_ip_pool/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $server_subnet_manager_ip_pool/24 -j ACCEPT
# ============================运维人员放行网段============================" >>/etc/systemd/system/openvpn-iptables-manager.service
			if [[ "$setup_client_conn_server_net" =~ ^[yY]$ &&  ! -z $client_role_manager_allow_net ]]; then
				for i in ${client_role_manager_allow_net//,/ };do
					echo -e "ExecStart=$iptables_path -t nat -I POSTROUTING -s $server_subnet_manager_ip_pool/24 -d $i -j SNAT --to $ip\nExecStop=$iptables_path -t nat -D POSTROUTING -s $server_subnet_manager_ip_pool/24 -d $i -j SNAT --to $ip\n" >>/etc/systemd/system/openvpn-iptables-manager.service
				done
			fi
			echo -e "RemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target" >>/etc/systemd/system/openvpn-iptables-manager.service
			systemctl enable --now openvpn-iptables-manager.service >/dev/null 2>&1
		fi

		if [[ "$setup_client_conn_server_net" =~ ^[yY]$ && ! -z $server_subnet_bussiness_ip_pool ]] ;then
			echo "[Unit]
Before=network.target

[Service]
Type=oneshot
ExecStart=$iptables_path  -I FORWARD -s $server_subnet_bussiness_ip_pool/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $server_subnet_bussiness_ip_pool/24 -j ACCEPT
# ============================业务人员放行网段============================" >>/etc/systemd/system/openvpn-iptables-bussiness.service
			if [[ "$setup_client_conn_server_net" =~ ^[yY]$ && ! -z $client_role_bussiness_allow_net ]]; then
				for i in ${client_role_bussiness_allow_net//,/ };do
					echo -e "ExecStart=$iptables_path -t nat -I POSTROUTING -s $server_subnet_bussiness_ip_pool/24 -d $i -j SNAT --to $ip\nExecStop=$iptables_path -t nat -D POSTROUTING -s $server_subnet_bussiness_ip_pool/24 -d $i -j SNAT --to $ip\n" >>/etc/systemd/system/openvpn-iptables-bussiness.service
				done
			fi
			echo -e "RemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target" >>/etc/systemd/system/openvpn-iptables-bussiness.service
			systemctl enable --now openvpn-iptables-bussiness.service >/dev/null 2>&1
		fi
		if [[ "$setup_client_conn_server_net" =~ ^[yY]$ && ! -z $server_subnet_robots_ip_pool ]] ;then
			echo "[Unit]
Before=network.target

[Service]
Type=oneshot
ExecStart=$iptables_path  -I FORWARD -s $server_subnet_robots_ip_pool/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $server_subnet_robots_ip_pool/24 -j ACCEPT
# ============================机器人放行网段============================" >>/etc/systemd/system/openvpn-iptables-robots.service

			if [[ "$setup_client_conn_server_net" =~ ^[yY]$ && ! -z $client_role_robots_allow_net ]]; then
				for i in ${client_role_robots_allow_net//,/ };do
					echo -e "ExecStart=$iptables_path -t nat -I POSTROUTING -s $server_subnet_robots_ip_pool/24 -d $i -j SNAT --to $ip\nExecStop=$iptables_path -t nat -D POSTROUTING -s $server_subnet_robots_ip_pool/24 -d $i -j SNAT --to $ip\n" >>/etc/systemd/system/openvpn-iptables-robots.service
				done
			fi
			echo -e "RemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target" >>/etc/systemd/system/openvpn-iptables-robots.service
			systemctl enable --now openvpn-iptables-robots.service >/dev/null 2>&1
		fi
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python >/dev/null 2>&1
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils >/dev/null 2>&1
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$client_profile_nat_pub_ip_domain" ]] && ip="$client_profile_nat_pub_ip_domain"
	# client-common.txt is created so we have a template to add further users later
	echo "  正在生成通用客户端配置文件"
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
verb 3
auth-user-pass" >$INSTALL_DIR/server/client-common.txt
	# Enable and start the OpenVPN service
	echo "  正在启动OpenVPN服务并设置开机自启"
	systemctl enable --now openvpn-server@server.service >/dev/null 2>&1
	echo "########################################################"
	echo
	echo "1. 管理端口密码已保存在$INSTALL_DIR/server/management-psw-file文件中，更多管理端口的使用方法详见:https://openvpn.net/community-resources/management-interface"
	echo "2. OpenVPN服务安装完成！可重新运行此脚本执行添加用户等其他功能"
	echo
	echo "########################################################"
else
	clear
	echo "OpenVPN服务已安装"
	echo
	echo "选择以下功能:"
	echo "   0) 配置SMTP"
	echo "   1) 添加用户"
	echo "   2) 查看已有用户"
	echo "   3) 删除用户"
	echo "   4) 卸载OpenVPN"
	echo "   5) 退出"
	read -p "功能选项: " option
	until [[ "$option" =~ ^[0-4]$ ]]; do
		read -p "$option为无效的选项，请重新输入选项: " option
	done
	case "$option" in
	0)
		check_smtp_server_profile
		;;
	1)
		check_smtp_server_profile
		read -p "新用户名(3~16位,包含以下字符a-zA-Z0-9_-): " client
		until [[ -z ${client+x} || ! -e $INSTALL_DIR/server/easy-rsa/pki/issued/$client.crt && $client =~ ^[a-zA-Z0-9_\-]{3,16}$ ]]; do
			read -p "$client已存在或不符合规则，请设置新的用户名: " client
		done

		if [[ ! -z $setup_subnet_roles_nu ]] ;then
			echo "已配置的用户角色："
			display_nu=1
			for i in ${setup_subnet_roles_nu//,/ };do
				case $i in
					1)
						echo "  ${display_nu}: 开发人员角色，允许访问的网段或IP：$developer_allowed_access_net"
						display_nu=$((display_nu+1))
					;;
					2)
						echo "  ${display_nu}: 测试人员角色，允许访问的网段或IP：$tester_allowed_access_net"
						display_nu=$((display_nu+1))
					;;
					3)
						echo "  ${display_nu}: 运维人员角色，允许访问的网段或IP：$manager_allowed_access_net"
						display_nu=$((display_nu+1))
					;;
					4)
						echo "  ${display_nu}: 业务人员角色，允许访问的网段或IP：$bussiness_allowed_access_net"
						display_nu=$((display_nu+1))
					;;
					5)
						echo "  ${display_nu}: 机器人 角 色，允许访问的网段或IP：$robots_allowed_access_net"
						display_nu=$((display_nu+1))
					;;
				esac
			done
		fi

		read -p "请设置新用户角色: " new_client_role
		until [[ -z "$new_client_role" || "$new_client_role" =~ ^[1|2|3|4|5]$ ]]; do
			echo "$new_client_role: 无效的选项."
			read -p "请重新设置新用户角色" new_client_role
		done

		read -p "设置用户邮箱: " user_email_address 
		until [[ -z ${user_email_address+x} || ${user_email_address} =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]; do
			read -p "${user_email_address}不是一个正确的邮箱格式，请重新设置: " user_email_address
		done
		tmp_var=${new_client_role}_allowed_access_net
		new_client $client $new_client_role $user_email_address ${!tmp_var}
		exit
		;;
	2)
		tail -n +2 $INSTALL_DIR/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
		;;
	3)
		number_of_clients=$(tail -n +2 $INSTALL_DIR/server/easy-rsa/pki/index.txt | grep -c "^V")
		if [[ "$number_of_clients" = 0 ]]; then
			echo
			echo "暂时没有已存在的客户端用户"
			exit
		fi		
		echo
		echo "请选择要删除的客户端用户:"
		tail -n +2 $INSTALL_DIR/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
		read -p "用户编号: " client_number
		until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
			echo "$client_number: 无效的选项."
			read -p "用户编号: " client_number
		done
		release_client_username=$(tail -n +2 $INSTALL_DIR/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)

		read -p "请确认是否要删除用户$release_client_username? [Y/n]: " revoke_client_option
		until [[ "$revoke_client_option" =~ ^[Y]$ ]]; do
			echo "$revoke_client_option: 无效的选项."
			read -p "请确认是否要删除客户端用户$release_client_username [Y/n]: " revoke_client_option
		done
		
		if [[ "$revoke_client_option" =~ ^[Y]$ && -f $INSTALL_DIR/server/ccd/$release_client_username ]]; then
			cd $INSTALL_DIR/server/easy-rsa
			./easyrsa --batch revoke "$release_client_username" >/dev/null 2>&1
			# EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl >/dev/null 2>&1
			# rm -f $INSTALL_DIR/server/crl.pem
			# cp $INSTALL_DIR/server/easy-rsa/pki/crl.pem $INSTALL_DIR/server/crl.pem
			# CRL is read with each client connection, when OpenVPN is dropped to nobody
			# chown nobody:"$group_name" $INSTALL_DIR/server/crl.pem
			client_ip_ready_release=$(grep "ifconfig-push" $INSTALL_DIR/server/ccd/$release_client_username | awk '{print $2}')
			release_client_role=$(grep -w "$release_client_username" /etc/openvpn/server/clients-info |awk -F" " '{print $1}')
			sed -i "/$release_client_username/d" $INSTALL_DIR/server/clients-info
			sed -i "/\<$release_client_username\>/d" $INSTALL_DIR/server/psw-file
			echo "$client_ip_ready_release" >> $INSTALL_DIR/server/ip-pools/$release_client_role-ip-pools
			rm -f $INSTALL_DIR/server/ccd/$release_client_username $INSTALL_DIR/client/profiles/$release_client_username.ovpn
			echo "用户$release_client_username已删除!"
		else
			echo "客户端用户$release_client_username删除中断!"
		fi
		exit
		;;
	4)
		echo
		read -p "请确认是否卸载OpenVPN? [Y/N]: " remove
		until [[ "$remove" =~ ^[YN]*$ ]]; do
			echo "$remove: 无效的选项."
			read -p "请确认是否卸载OpenVPN? [Y/N]: " remove
		done
		if [[ "$remove" =~ ^[Y]$ ]]; then
			port=$(grep '^port ' $INSTALL_DIR/server/server.conf | cut -d " " -f 2)
			protocol=$(grep '^proto ' $INSTALL_DIR/server/server.conf | cut -d " " -f 2)
			if systemctl is-active --quiet firewalld.service; then
				ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s $server_ip_net/24 '"'"'!'"'"' -d $server_ip_net/24' | grep -oE '[^ ]+$')
				# Using both permanent and not permanent rules to avoid a firewalld reload.
				firewall-cmd --remove-port="$port"/"$protocol"
				firewall-cmd --zone=trusted --remove-source="$server_ip_net"/24
				firewall-cmd --permanent --remove-port="$port"/"$protocol"
				firewall-cmd --permanent --zone=trusted --remove-source="$server_ip_net"/24
				firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s "$server_ip_net"/24 ! -d "$server_ip_net"/24 -j SNAT --to "$ip"
				firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s "$server_ip_net"/24 ! -d "$server_ip_net"/24 -j SNAT --to "$ip"
				# if grep -qs "server-ipv6" $INSTALL_DIR/server/server.conf; then
				# 	ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
				# 	firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
				# 	firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
				# 	firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
				# 	firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
				# fi
			else
				
				systemctl disable --now openvpn-iptables.service >/dev/null 2>&1
				
			fi
			if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
				semanage port -d -t openvpn_port_t -p "$protocol" "$port"
			fi

			if [[ ! -z $setup_subnet_roles_nu ]];then
				for i in ${setup_subnet_roles_nu//,/ };do
					case $i in
						1)
							systemctl disable --now openvpn-iptables-developer.service >/dev/null 2>&1
							systemctl stop --now openvpn-iptables-developer.service >/dev/null 2>&1
						;;
						2)
							systemctl disable --now openvpn-iptables-tester.service >/dev/null 2>&1
							systemctl stop --now openvpn-iptables-tester.service >/dev/null 2>&1
						;;
						3)
							systemctl disable --now openvpn-iptables-manager.service >/dev/null 2>&1
							systemctl stop --now openvpn-iptables-manager.service >/dev/null 2>&1
						;;
						4)
							systemctl disable --now openvpn-iptables-bussiness.service >/dev/null 2>&1
							systemctl stop --now openvpn-iptables-bussiness.service >/dev/null 2>&1
						;;
						5)
							systemctl disable --now openvpn-iptables-robots.service >/dev/null 2>&1
							systemctl stop --now openvpn-iptables-robots.service >/dev/null 2>&1
						;;
					esac
				done
			fi
			
			systemctl disable --now openvpn-server@server.service >/dev/null 2>&1
			sed -i -e 's/^setup_subnet_roles_nu=.*/setup_subnet_roles_nu=/g' \
			       -e 's/^developer_allowed_access_net=.*/developer_allowed_access_net=/g' \
			       -e 's/^tester_allowed_access_net=.*/tester_allowed_access_net=/g' \
			       -e 's/^manager_allowed_access_net=.*/manager_allowed_access_net=/g' \
			       -e 's/^bussiness_allowed_access_net=.*/bussiness_allowed_access_net=/g' \
			       -e 's/^robots_allowed_access_net=.*/robots_allowed_access_net=/g' $0
			cp /etc/systemd/system/openvpn-iptables*.service /etc/openvpn
			tar -czf /tmp/openvpn-$(date "+%Y%m%d%M").tar.gz --exclude=logs -C /etc openvpn
			rm -rf $INSTALL_DIR /etc/systemd/system/openvpn-iptables*.service /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf /etc/sysctl.d/30-openvpn-forward.conf
			if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
				apt-get remove --purge -y openvpn >/dev/null 2>&1
			else
				# Else, OS must be CentOS or Fedora
				yum remove -y openvpn >/dev/null 2>&1
			fi
			echo
			echo "######################################################################"
			echo
			echo "OpenVPN已卸载！相关文件已备份在/tmp路径下，请及时下载转移到其他存储位置！"
			echo
			echo "######################################################################"
		else
			echo
			echo "OpenVPN卸载中断!"
		fi
		exit
		;;
	5)
		exit
		;;
	esac
fi
