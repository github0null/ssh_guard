#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import re
import time
import subprocess

# == /var/log/btmp ==
#
# oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# root     ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# root     ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# root     ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)
# root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)
# root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)
# root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)
# root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)
# root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)
#
# == /etc/hosts.deny ==
#
# sshd:223.230.41.108:deny

btmp_path = '/var/log/btmp'
host_deny_path = '/etc/hosts.deny'

btmp_cmd = 'lastb'
try_max = 3

btmp_matcher = re.compile(
    r'\s*\w+\s+[^\s]+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
deny_host_matcher = re.compile(
    r'\s*sshd:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):deny\s*$', re.IGNORECASE)

def append_to_host_deny(deny_host):

    if deny_host.__len__() == 0:
        return deny_host.__len__()

    lines = None
    with open(host_deny_path, 'r') as fp:
        lines = fp.readlines()

    exsited_deny_list = []

    # get old deny list
    for line in lines:
        m_res = deny_host_matcher.search(line)
        if m_res and m_res.groups().__len__() > 1:
            exsited_deny_list.append(m_res.group(1))

    # filter existed ip
    append_list = []
    for ip in deny_host:
        if ip in exsited_deny_list:
            continue
        append_list.append('sshd:{}:deny\n'.format(ip))

    # append to deny_list
    if append_list.__len__() > 0:
        with open(host_deny_path, 'a') as fp:
            fp.writelines(append_list)

    return append_list.__len__()


def clear_btmp_log():
    with open(btmp_path, 'w') as fp:
        fp.write('')

def main():

    print('[start]: at {}'.format(time.strftime(
        "%Y-%m-%d %H:%M:%S", time.localtime())))

    proc = subprocess.run(btmp_cmd, shell=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, encoding="utf-8")
    log_lines = re.split(r'\r\n|\n', proc.stdout)

    cur_try_map = {}

    # get deny list
    for line in log_lines:
        if line == '':
            continue
        m_res = btmp_matcher.search(line)
        if m_res and m_res.groups().__len__() > 0:
            ip = m_res.group(1)
            old_count = 0
            if ip in cur_try_map:
                old_count = cur_try_map[ip]
            cur_try_map[ip] = old_count + 1

    # filter deny list
    deny_list = []
    for ip in cur_try_map:
        if cur_try_map[ip] >= try_max:
            deny_list.append(ip)
            print('confirm ip: {}'.format(ip))
        else:
            print('ignore ip: {}, try count: {}'.format(ip, cur_try_map[ip]))

    # append to host deny list
    real_num = append_to_host_deny(deny_list)

    # append ok, clear log
    if real_num > 0:
        clear_btmp_log()  # clear btmp log

    print('[done]: found {} ip, deny: {} ip\n'.format(deny_list.__len__(), real_num))

if __name__ == '__main__':
    main()