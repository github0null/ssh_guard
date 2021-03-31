## 简述

运行该脚本，会检查 ssh 的登陆失败记录，将超过尝试次数（默认3）的 ip 加入到黑名单 `/etc/hosts.deny`

***

## 安装

1. 安装 Python3

2. 将 src/main.py 复制到你的服务器中某个目录中

3. 使用命令编辑定时任务 `vim /etc/crontab`，添加如下任务:

```ini
# 每隔 2 min 运行一次 ssh_guard
*/2 * * * * root python3 /<YOUR_PATH>/main.py >> /<YOUR_LOG_PATH>/sshd_guard.log 2>&1
```
