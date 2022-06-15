#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# @Time     :2021/9/27
# @Author   :Donvin.li
# @File     :iislog.py


import re
import sys
import socket
import random

import requests
import threading
import ast
import pymysql
import time
import datetime


class LogRead():
    def __init__(self):
        self.LA=LogAnalysis()
        self.l_day=[]   # 用来保存一天内邮箱和IP的键值对，实现一天内相同的邮箱和IP只分析一次。
    # 循环实时读取日志文件的最新内容
    # 整体功能：每天循环实时读取当天日志文件的最新行，交给analysis_log函数分析，直到0点时结束，进入下一天的日志文件循环
    def run(self,log_path):
        count = 0
        position = 0    #记录上次读取文件的位置(大小)

        with open(log_path, mode='r',encoding='ISO-8859-1') as f1:
            # global d_day
            # d_day = []
            self.l_day=[]
            while True:
                try:
                    line = f1.readline().strip()
                except Exception as e:
                    print(e)
                if line:
                    count += 1
                    self.get_login_log(line)  # 提取登录相关的日志
                    # print(line)
                    time.sleep(0.01)
                    # print("count %s line %s" % (count, line))

                cur_position = f1.tell()  # 记录当前读取文件的位置(大小)

                if cur_position == position:    # 如果当前读取大小和上次读取大小相同，说明文件无新内容
                    # time.sleep(0.1)
                    now = time.strftime("%Y-%m-%d %H:%M:%S")
                    # 当时间到8点时，结束当前文件读取的循环，不再读取当前文件，进入下一天文件的循环读取；
                    # 解决日志文件每天8:00重新生成新的文件的问题。
                    if '08:00:00' in now:
                        log = '[*]%s 当前文件读取结束，开始读取下一文件' % (now)
                        print(log)
                        Wrlog.myself_log(log)
                        time.sleep(0.1)
                        break
                    continue    # 如果文件没有新内容，继续循环读取，等待文件有新内容
                else:
                    position = cur_position # 如果文件有新内容，将上次读取大小更新为当前读取大小
                    # time.sleep(0.1)


    # 提取和登录相关的日志
    # 基本功能：将日志中关于登录的日志筛选出来，交给format_log函数处理。
    def get_login_log(self,line):
        zzstr='(auth.owa.*[0-9a-zA-Z_.]{0,19}@[0-9a-zA-Z]{1,13}\.[com,cn,net,cc]{1,3})|(/Microsoft-Server-ActiveSync/default.eas.*[0-9a-zA-Z_.]{0,19}@[0-9a-zA-Z]{1,13}\.[com,cn,net,cc]{1,3})|(/EWS/Exchange.asmx.*GOODWILL-IC)' # 包含auth.owa和longsys.com邮箱的行为登录请求
        # zzstr='/EWS/Exchange.asmx.*GOODWILL-IC'
        zz=re.compile(zzstr)
        result=zz.findall(line)
        if result:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 匹配到一条登录数据：%s' % (now, line)
            # Wrlog.myself_log(log)
            self.format_log(line)    # 将登录请求日志交给format_log函数处理

    # 日志格式化函数
    # 基本功能：将登录日志中的登录邮箱、登录源地址、登录时间、状态码等信息提取出来，给send_log函数进行处理。
    def format_log(self,line):
        # global d_day
        d1={}
        l1=line.split(' ')
        # print(l1)
        mail=l1[9]
        ip=l1[10]
        try:
            zzstr_localip='^(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(218\.17\.181\.\d{1,3})|(120\.234\.47\.\d{1,3})|(103\.215\.40\.\d{1,3})|(183\.58\.24\.\d{1,3})|(183\.237\.59\.\d{1,3})|(112\.91\.62\.\d{1,3})$'
            re_localip = re.search(zzstr_localip, ip)
            localip=re_localip.group()
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 当前登录IP为内网IP或者白名单IP：%s，跳过' % (now, localip)
            # print(log)
            # Wrlog.myself_log(log)
        except:
            d2={mail:ip}
            # print(d_day)
            # print(self.l_day)
            # print(d2)
            if d2 not in self.l_day:
                self.l_day.append(d2)
                logtime='%s %s'%(l1[0],l1[1])
                d1['time'] = logtime
                d1['ip'] = ip
                d1['mail'] = self.mail_format(mail)
                code=l1[16]
                d1['code'] = code
                logintype=l1[12]
                d1['type'] = logintype
                now = time.strftime("%Y-%m-%d %H:%M:%S")
                log = '[*]%s 当前登录IP为互联网IP：%s，格式化结果：%s' % (now, ip,str(d1))
                print(log)
                Wrlog.myself_log(log)
                t = threading.Thread(target=self.LA.analysis_log, args=(d1, ))  # 创建线程
                t.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
                t.start()  # 开启线程
            else:
                pass


    # zzstr_ip='\d+\.\d+\.\d+\.\d+'
    # re_ip = re.findall(zzstr_ip, line)
    # ip = re_ip[1]
    # d1['ip'] = ip
    #
    # zzstr_mail='[0-9a-zA-Z_.]{0,19}@[0-9a-zA-Z]{1,13}\.[com,cn,net,cc]{1,3}'
    # re_mail = re.search(zzstr_mail, line)
    # mail = re_mail.group()
    # d1['mail'] = mail
    # # zzstr_mail='(?:[0-9a-zA-Z_]+.)+@[0-9a-zA-Z]{1,13}\.[com,cn,net,cc]{1,3}'
    # zzstr_time='(\d{4}-\d{1,2}-\d{1,2} \d{2}:\d{2}:\d{2})'
    # re_time = re.search(zzstr_time, line)
    # time = re_time.group()
    # d1['time'] = time
    #
    # zzstr_code='(?<=[wm|mail|mobile].longsys.com )\d{3}'
    # re_code = re.search(zzstr_code, line)
    # code = re_code.group()
    # d1['code'] = code
    #
    # logintype='OWA'
    # d1['type']=logintype

    # tb = pt.PrettyTable()
    # tb.field_names = ["IP", "Mail", "Time", "Code"]
    # tb.add_row([ip, mail, time, code])
    #     print(d1)
    # time.sleep(1)
    # send_log(d1)
    def mail_format(self,mail):
        try:
            zzstr_mail = '[0-9a-zA-Z_.]{0,19}@[0-9a-zA-Z]{1,13}\.[com,cn,net,cc]{1,3}'
            re_mail = re.search(zzstr_mail, mail)
            email = re_mail.group()
        except:
            l1=mail.split('\\')
            email='%s@longsys.com'%l1[1]
        return email


    def socket_client(d):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('172.16.10.123', 8888))
            s.send(str(d).encode('utf-8'))
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 发送数据：%s' % (now, str(d))
            Wrlog.myself_log(log)
        except socket.error as msg:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 发送数据失败：%s' % (now, msg)
            Wrlog.myself_log(log)
            sys.exit(1)
        s.close()

class LogAnalysis():

    def __init__(self):
        self.dd=DD()
    # 数据接收函数，主要功能是接收来自客户端发来的数据
    def socket_service(self):
        HOST = '0.0.0.0'
        PORT = 8888
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 定义socket类型，网络通信，TCP
        # 防止socket server重启后端口被占用（socket.error: [Errno 98] Address already in use）
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))  # 套接字绑定的IP与端口
        s.listen(10)  # 开始TCP监听,监听10个请求
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        log = '[*]%s 程序开始监听，%s:%s' % (now, HOST, str(PORT))
        print(log)
        Wrlog.myself_log(log)
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=self.deal_data, args=(conn, addr))
            t.start()

    # 数据接收函数，主要功能是接收来自客户端发来的数据，并交给数据分析函数处理
    def deal_data(self,conn, addr):
        response = conn.recv(4096)  # 每次接收4096个字节的数据
        try:
            data = ast.literal_eval(response.decode())
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 从%s接收到一条数据：%s' % (now, addr, str(data))
            print(log)
            Wrlog.myself_log(log)
            self.analysis_log(data)
            conn.close()
        except:
            pass

    # 登录地址分析函数，主要功能是分析登录地址，将异常登录地址交给消息警告函数处理
    def analysis_log(self,data):
        mail = data['mail']
        ip = data['ip']
        clienttype = data['type'].strip()
        address = self.query_city_bychinaz(ip)
        addr = address[0]
        city = address[1]
        province = address[2]
        sql = "SELECT count(*) FROM login_addr WHERE mail=%s"
        args = (mail)
        count = DBUtil.getCount(sql, args)
        if count == 0:  # 首次登录，插入原始日志，且插入地址信息
            is_diff = 0  # 等于0的表示是首次登录
            addrtype = 0  # 首次登录都作为正常地址
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 首次登录，插入IP记录同时插入这条IP对应的登录城市地址：【%s】' % (now, addr)
            print(log)
            Wrlog.myself_log(log)

            t = threading.Thread(target=self.insert_log, args=(data, is_diff,))  # 创建线程
            t.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
            t.start()  # 开启线程

            t2 = threading.Thread(target=self.insert_addr, args=(mail, addr, ip, addrtype, clienttype,))  # 创建线程
            t2.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
            t2.start()  # 开启线程
        else:  # 已经登录过，在地址表中查询
            sql = "SELECT id,time FROM login_addr WHERE mail=%s AND type=0 AND address LIKE %s"
            province = '%' + province + '%'
            args = (mail, province)
            result = DBUtil.executeQuery(sql, args)
            if result:  # 如果正常地址里能查到结果,则继续判断时间是否大于60天
                now = time.strftime("%Y-%m-%d %H:%M:%S")
                log = '[*]%s 已查到【%s】之前登录过，开始查询地址是否大于60天' % (now, mail)
                print(log)
                Wrlog.myself_log(log)
                id = result[0]
                his_time = result[1]
                his_days = self.month_check(his_time)
                if his_days <= 60:  # 如果小于60天，则认为是正常地址
                    is_diff = 1  # 等于1的表示该IP是小于60天的正常地址
                    now = time.strftime("%Y-%m-%d %H:%M:%S")
                    log = '[*]%s 查询到【%s】相同的历史登录城市【%s】，且历史登录时间小于60天,插入IP记录同时更新地址的时间为当前时间' % (now,mail, addr)
                    print(log)
                    Wrlog.myself_log(log)
                    addrtype = 0

                    t = threading.Thread(target=self.insert_log, args=(data, is_diff,))  # 创建线程
                    t.daemon = True
                    t.start()  # 开启线程

                    t1 = threading.Thread(target=self.update_addr, args=(id, addrtype, ip, clienttype,))  # 将时间更新到今天
                    t1.daemon = True
                    t1.start()  # 开启线程

                elif his_days > 60: # 如果大于60天则认为是异常地址
                    is_diff = 2  # 等于2的表示该IP是大于60天的正常地址
                    now = time.strftime("%Y-%m-%d %H:%M:%S")
                    log = '[*]%s 查询到【%s】相同的历史登录城市【%s】，但是历史登录时间大于60天，将把该地址的type更新为1(即异常登录地址)' % (now,mail, addr)
                    print(log)
                    Wrlog.myself_log(log)
                    addrtype = 1

                    t2 = threading.Thread(target=self.insert_log, args=(data, is_diff,))  # 创建线程
                    t2.daemon = True
                    t2.start()  # 开启线程

                    t3 = threading.Thread(target=self.update_addr, args=(id, addrtype, ip, clienttype,))  # 创建线程
                    t3.daemon = True
                    t3.start()  # 开启线程

            else:  # 如果正常地址里查不到结果，在异常地址里查
                sql = "SELECT id,token FROM login_addr WHERE mail=%s AND type=1 AND address LIKE %s"
                province = '%' + province + '%'
                args = (mail, province)
                result = DBUtil.executeQuery(sql, args)
                if result:  # 如果在异常地址查到结果，则直接判定为异常地址
                    id = result[0]
                    token = result[1]
                    is_diff = 3  # 等于3的表示该IP的地址是历史异常地址
                    addrtype = 1
                    now = time.strftime("%Y-%m-%d %H:%M:%S")
                    log = '[*]%s 查询到【%s】本次登录城市是历史异常地址，插入IP记录，同时再更新这条异常地址的时间：【%s】' % (now,mail, addr)
                    print(log)
                    Wrlog.myself_log(log)

                    t = threading.Thread(target=self.insert_log, args=(data, is_diff,))  # 创建线程
                    t.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
                    t.start()  # 开启线程

                    t2 = threading.Thread(target=self.result_do1, args=(id, token, mail, addr, ip, clienttype,))  # 创建线程
                    t2.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
                    t2.start()  # 开启线程
                else:   # 如果在异常地址没查到结果，
                    sql = "SELECT COUNT(*) FROM login_addr WHERE mail=%s AND type=0 AND client=%s"
                    args = (mail, clienttype)
                    count = DBUtil.getCount(sql, args)
                    if count >= 0:  #
                        is_diff = 5  # 地址不同客户端相同的正常地址
                        addrtype = 0  # 地址不同客户端相同的正常地址
                        now = time.strftime("%Y-%m-%d %H:%M:%S")
                        log = '[*]%s 未查询到【%s】该城市的历史登录信息，但是查询到该客户端之前正常登录过，插入IP记录同时插入这条IP对应的登录城市地址：【%s】' % (now,mail,addr)
                        print(log)
                        Wrlog.myself_log(log)

                        t = threading.Thread(target=self.insert_log, args=(data, is_diff,))  # 创建线程
                        t.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
                        t.start()  # 开启线程

                        t2 = threading.Thread(target=self.insert_addr,
                                              args=(mail, addr, ip, addrtype, clienttype,))  # 创建线程
                        t2.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
                        t2.start()  # 开启线程

                    else:
                        is_diff = 4  # 表示新的异常地址
                        addrtype = 1
                        now = time.strftime("%Y-%m-%d %H:%M:%S")
                        log = '[*]%s 查到该地址是首次出现的异常地址，插入IP记录，同时插入这条异常地址：【%s】' % (now, addr)
                        print(log)
                        Wrlog.myself_log(log)

                        t = threading.Thread(target=self.insert_log, args=(data, is_diff,))  # 创建线程
                        t.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
                        t.start()  # 开启线程

                        t2 = threading.Thread(target=self.result_do, args=(mail, addr, ip, clienttype,))  # 创建线程
                        t2.daemon = True  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
                        t2.start()  # 开启线程

    def month_check(self,his_time):
        now = datetime.datetime.now()
        his_t = datetime.datetime.strptime(str(his_time), '%Y-%m-%d %H:%M:%S')
        x = now - his_t
        return x.days

    def result_do(self,mail, addr, ip, clienttype):
        mail_list = ['cosine.yu@longsys.com', 'fred.yin@longsys.com', 'ding.luo@longsys.com', 'sheldon.li@longsys.com',
                     'kim.wu@longsys.com', 'jinglu.zhu@longsys.com', 'brian.xu@longsys.com', 'donvin.li@longsys.com',
                     'peihui.liu@longsys.com']
        randomurl = self.get_randomurl()
        token = randomurl.split('=')[1].strip()
        addrtype = 1
        t = threading.Thread(target=self.insert_addr1, args=(mail, addr, ip, addrtype, token, clienttype,))  # 创建线程
        t.daemon = True
        t.start()  # 开启线程

        # if mail in mail_list:
        #     t2 = threading.Thread(target=send_warning_test, args=(mail, addr, ip, randomurl,))  # 创建线程
        #     t2.daemon = True
        #     t2.start()  # 开启线程
        # else:
        t2 = threading.Thread(target=self.send_warning, args=(mail, addr, ip, randomurl,))  # 创建线程
        t2.daemon = True
        t2.start()  # 开启线程

    def result_do1(self,id, token, mail, addr, ip, clienttype):
        mail_list = ['cosine.yu@longsys.com', 'fred.yin@longsys.com', 'ding.luo@longsys.com', 'sheldon.li@longsys.com',
                     'kim.wu@longsys.com', 'jinglu.zhu@longsys.com', 'brian.xu@longsys.com', 'donvin.li@longsys.com',
                     'peihui.liu@longsys.com']
        randomurl = 'http://ex.longsys.com/userself/Update?token=%s' % token
        t = threading.Thread(target=self.update_addr1, args=(id, ip, clienttype,))  # 创建线程
        t.daemon = True
        t.start()  # 开启线程

        # if mail in mail_list:
        #     t2 = threading.Thread(target=send_warning_test, args=(mail, addr, ip, randomurl,))  # 创建线程
        #     t2.daemon = True
        #     t2.start()  # 开启线程
        # else:
        t2 = threading.Thread(target=self.send_warning, args=(mail, addr, ip, randomurl,))  # 创建线程
        t2.daemon = True
        t2.start()  # 开启线程

    # 登录地址插入数据函数，主要功能是将之前没有地址信息的用户地址插入到数据库
    def insert_addr(self,mail, addr, ip, type, clienttype):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        sql = "INSERT INTO login_addr(mail, address,time,ip,type,client) VALUES (%s,%s,%s,%s,%s,%s)"
        args = (mail, addr, now, ip, type, clienttype)
        DBUtil.executeUpdate(sql, args)

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        log = '[*]%s 插入【%s】的地址：【%s】 成功' % (now, mail,addr)
        print(log)
        Wrlog.myself_log(log)

    def insert_addr1(self,mail, addr, ip, type, token, clienttype):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        sql = "INSERT INTO login_addr(mail, address,time,ip,type,token,client)VALUES (%s,%s,%s,%s,%s,%s,%s)"
        args = (mail, addr, now, ip, type, token, clienttype)
        DBUtil.executeUpdate(sql, args)

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        log = '[*]%s 插入【%s】带TOKEN的地址：【%s】 成功' % (now,mail, addr)
        print(log)
        Wrlog.myself_log(log)

    # 地址更新函数，主要功能是将新的异地登录地址更新到数据中
    def update_addr(self,id, addrtype, ip, clienttype):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        sql = "UPDATE login_addr SET time=%s,type=%s,ip=%s,client=%s WHERE id=%s"
        args = (now, addrtype, ip, clienttype, id)
        DBUtil.executeUpdate(sql, args)

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        log = '[*]%s 更新ID为【%s】的地址TYPE为【%s】成功' % (now, id, addrtype)
        print(log)
        Wrlog.myself_log(log)

    def update_addr1(self,id, ip, clienttype):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        sql = "UPDATE login_addr SET time=%s,ip=%s,client=%s WHERE id=%s"
        args = (now, ip, clienttype, id)
        DBUtil.executeUpdate(sql, args)

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        log = '[*]%s 更新ID:【%s】的时间为当前时间成功' % (now, id)
        print(log)
        Wrlog.myself_log(log)

    def send_warning(self,mail, addr, ip, randomurl):
        lidongfeng = ['donvin.li@longsys.com', '李东锋']
        usernames = '%s' % lidongfeng[1]
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        msg = '【江波龙信息安全】 尊敬的用户，%s 于%s在%s(IP：%s)异地登录。请点击下面的链接确认是否是本人登录：%s' % (mail, now, addr, ip, randomurl)
        Wrlog.myself_log(msg)
        print(msg)
        self.dd.sendmsg(msg, lidongfeng[0])

    # 警告发送函数，主要功能是将异常登录的警告通过钉钉发送给对应的用户
    def send_warning1(self,mail, addr, ip, randomurl):
        user = self.dd.getuserid(mail)
        lidongfeng = ['donvin.li@longsys.com', '李东锋']
        if user != 0:
            userid = user[0]
            mobile = user[1]
            name = user[2]
            userlist = '%s,%s' % (userid, lidongfeng[0])
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 查询到%s的userid，通过钉钉发送警告给%s' % (now, mail, name)
            print(log)
            Wrlog.myself_log(log)
            msg = '【江波龙信息安全】 尊敬的%s，您的账号%s 于%s在%s(IP：%s)登录，这并不是您的常用登录地。请点击下面的链接确认是否是本人登录：%s' % (
            name, mail, now, addr, ip, randomurl)
            self.dd.sendmsg(msg, lidongfeng[0])
        else:
            usernames = '%s' % lidongfeng[1]
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 未查询到%s的userid，通过钉钉发送警告给%s' % (now, mail, usernames)
            print(log)
            Wrlog.myself_log(log)
            msg = '【江波龙信息安全】 尊敬的用户，%s 于%s在%s(IP：%s)异地登录。请点击下面的链接确认是否是本人登录：%s' % (mail, now, addr, ip, randomurl)
            self.dd.sendmsg(msg, lidongfeng[0])

    # 数据插入函数，主要作用是将新的数据插入到数据库中
    def insert_log(self,data, is_diff):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        mail = data['mail']
        logtime = data['time']
        ip = data['ip']
        code = data['code']
        logintype = data['type']

        sql = """INSERT INTO iis_log(time,
                             ip, mail, type, code,is_diff,create_time)
                             VALUES (%s, %s, %s, %s, %s, %s, %s)"""

        args = (logtime, ip, mail, logintype, code, is_diff, now)
        DBUtil.executeUpdate(sql, args)
        log = '[*]%s 插入日志成功' % now
        print(log)
        Wrlog.myself_log(log)

    def get_randomurl(self):
        # psw = "123.com.cN"
        # url = 'http://172.17.0.4:8080/userself/GenUrlServlet?pass=%s' % psw
        # r = requests.get(url)
        # return r.text

        base_url='http://ex.longsys.com/userself/Update?token='
        random_str = ''
        base_str='ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
        length = len(base_str) - 1
        for i in range(8):
            random_str += base_str[random.randint(0, length)]
        randomurl=base_url+random_str
        return randomurl
    # 地址查询函数，主要功能是通过IP查询城市地址
    def ip_tocity(self,ip):
        url = "http://ip-api.com/json/%s?lang=zh-CN" % ip  # 查询归属地网址
        try:
            r = requests.get(url)  # 网页访问请求
            r.raise_for_status()  # 查询访问状态是否异常，异常直接进入except部分进行处理
            # r.encoding = r.apparent_encoding # 把编码改为可以使用户读懂的编码
            # print(r.json())
            country = r.json()['country'] if r.json()['country'] else ''
            regionName = r.json()['regionName'] if r.json()['regionName'] else ''
            city = r.json()['city'] if r.json()['city'] else ''
            addr = country + regionName + city
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            print('[*]%s IP：%s 地址：%s' % (now, ip, addr))
        except:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            print("[*]%s 地址查询失败" % now)
        return addr, city, regionName

    def query_city_bychinaz(self,ip):
        token = 'c8a09a824b67498e860eba3ce7db8d89'
        url = "https://apidatav2.chinaz.com/ipapi/city?key=%s&ip=%s&coordsys=" % (token, ip)
        r = requests.get(url)
        # print(r.json())
        country = r.json()['Result']['data']['country'] if r.json()['Result']['data']['country'] else ''
        province = r.json()['Result']['data']['prov'] if r.json()['Result']['data']['prov'] else ''
        city = r.json()['Result']['data']['city'] if r.json()['Result']['data']['city'] else ''
        addr = country + province + city
        return addr, city, province

    def get_mail_list(self,id):
        mail_list = []
        users = self.dd.getdepartmentuser(id)
        for userlist in users['userlist']:
            email = userlist['email']
            mail_list.append(email)
        print(mail_list)

class DD():
    def __init__(self):
        self.access_token=''
        self.Appkey = 'dingplx3n3x8y1tc2s3g'
        self.AppSecret = 'FDSkn0TuQKfosJjazuqQeTbxaznGsOEHPTHrClpMEUsdWAS7caD3lmYbe0zZe1NS'

    def gettoken(self):
        url = 'https://oapi.dingtalk.com/gettoken?appkey=%s&appsecret=%s' % (self.Appkey, self.AppSecret)
        try:
            r = requests.get(url)  # 网页访问请求
            r.raise_for_status()  # 查询访问状态是否异常，异常直接进入except部分进行处理
            # r.encoding = r.apparent_encoding # 把编码改为可以使用户读懂的编码
            self.access_token = r.json()['access_token']
            print(self.access_token)
            # return access_token

        except:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            print("[*]%s 获取钉钉access_token失败" % now)
        #
        # time.sleep(7000)
        # dd_gettoken()
    # 按需请求token(token二小时失效，且不能频繁请求)
    def check_token_by_mobile(func):
        def warpper(self, *args, **kwargs):
            url = 'https://oapi.dingtalk.com/user/get_by_mobile?access_token=%s&mobile=%s' % (
                self.access_token, '15920040120')
            r = requests.get(url)
            if r.json()['errcode'] == 40014:
                self.gettoken()
                return func(self, *args, **kwargs)
            else:
                return func(self, *args, **kwargs)

        return warpper
    # 钉钉发送工作通知消息
    @check_token_by_mobile
    def sendmsg(self,msg, userid_list):
        agent_id = '1326192553'
        url = 'https://oapi.dingtalk.com/topapi/message/corpconversation/asyncsend_v2?access_token=%s' % self.access_token
        data = {"msg": {"text": {"content": msg}, "msgtype": "text"},
                # "to_all_user":"false",
                "agent_id": agent_id,
                # "dept_id_list":"123,456",
                "userid_list": userid_list
                }
        r = requests.post(url, json=data)
        print(r.json())

    # 钉钉递归获取所有部门列表，取得部门ID
    @check_token_by_mobile
    def getdepartment(self):
        url = 'https://oapi.dingtalk.com/department/list?access_token=%s&lang=zh_CN&fetch_child=true&id=1' % self.access_token
        r = requests.get(url)
        # print(r.json())
        department_list = []
        for department in r.json()['department']:
            department_list.append(department['id'])
        # print(department_list)
        return department_list

    # 钉钉通过部门ID获取部门下用户信息
    @check_token_by_mobile
    def getdepartmentuser(self,department):
        url = 'https://oapi.dingtalk.com/user/listbypage?access_token=%s&lang=zh_CN&department_id=%s&offset=1&size=100&order=entry_asc' % (
        self.access_token, department)
        r = requests.get(url)
        # print(r.json())
        return r.json()
        # [14159978, 14172432, 14174378, 14177329, 14200028, 14200097]

    # 钉钉通过
    @check_token_by_mobile
    def getuserid(self,mail):
        department_list = self.getdepartment()
        try:
            sign = 0
            for id in department_list:
                user = self.getdepartmentuser(id)
                for userlist in user['userlist']:
                    if userlist:
                        # print(userlist)
                        email = userlist['email']
                        if mail == email:
                            userid = userlist['userid']
                            mobile = userlist['mobile']
                            name = userlist['name']
                            sign = 1
                            break
                if sign == 1:
                    break
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 通过%s查询到userid：%s 手机：%s 姓名：%s' % (now, mail, userid, mobile, name)
            print(log)
            Wrlog.myself_log(log)
            return userid, mobile, name
        except Exception as e:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            log = '[*]%s 通过%s未查询到用户信息' % (now, mail)
            print(e)
            print(log)
            Wrlog.myself_log(log)
            return 0

    @check_token_by_mobile
    def getuserid_by_mobile(self,mobile):
        url = 'https://oapi.dingtalk.com/user/get_by_mobile?access_token=%s&mobile=%s' % (self.access_token, mobile)
        r = requests.get(url)
        userid = r.json()['userid']
        # print(r.json())
        print(userid)
        return userid

class DBUtil():
    db_host = '172.17.0.5'
    db_user = 'root'
    db_password = '123.com.cn'
    db_name = 'exchange_log'

    @classmethod
    def getConnection(cls):
        conn = pymysql.connect(host=cls.db_host, user=cls.db_user, password=cls.db_password, database=cls.db_name,charset='utf8')
        return conn

    @classmethod
    def executeQuery(cls, sql,args):
        conn = cls.getConnection()
        try:
            cursor = conn.cursor()
            cursor.execute(sql,args)
            # results = cursor.fetchall()
            result=cursor.fetchone()
            return result
        except Exception as e:
            # 如果发生错误则回滚
            print(e)
            conn.rollback()
        # 关闭数据库连接
        conn.close()

    @classmethod
    def executeQueryAny(cls, sql,args):
        conn = cls.getConnection()
        try:
            cursor = conn.cursor()
            cursor.execute(sql,args)
            results = cursor.fetchall()
            return results
        except Exception as e:
            # 如果发生错误则回滚
            print(e)
            conn.rollback()
        # 关闭数据库连接
        conn.close()

    @classmethod
    def getCount(cls, sql, args):
        conn = cls.getConnection()
        try:
            cursor = conn.cursor()
            cursor.execute(sql, args)
            results = cursor.fetchall()
            count=results[0][0]
            return count
        except Exception as e:
            # 如果发生错误则回滚
            print(e)
            conn.rollback()
        # 关闭数据库连接
        conn.close()

    @classmethod
    def executeUpdate(cls, sql, args):
        conn = cls.getConnection()
        try:
            cursor = conn.cursor()
            cursor.execute(sql, args)
            conn.commit()
        except Exception as e:
            # 如果发生错误则回滚
            print(e)
            conn.rollback()
        # 关闭数据库连接
        conn.close()

class Wrlog():
    @classmethod
    def myself_log(self,log):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        filename = now[0:4] + now[5:7] + now[8:10]
        log_name = '%s.log' % filename
        with open(log_name, 'a+') as f:
            f.write(log + '\n')
            f.close()

if __name__ == "__main__":
    logrd=LogRead()
    # 自动根据当前的时间生成当天的日志文件名
    while True:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        # now = '2021-08-19 00:00:00'
        filename = now[2:4] + now[5:7] + now[8:10]
        # log_path = '//172.16.8.10/w3svc1/u_ex%s.log' % filename
        log_path = '/var/tmp/u_ex%s.log' % filename
        # log_path='//172.16.8.10/w3svc1/u_ex220613.log'
        log = '[*]%s 开始读取日志，当前文件名为：%s' % (now, log_path)
        print(log)
        Wrlog.myself_log(log)
        try:
            logrd.run(log_path)   # 每天0点run()会break，进入下一天的run()
        except IOError:
            log = '[*]%s 未找到日志文件：%s，10秒后继续读取' % (now, log_path)
            print(log)
            Wrlog.myself_log(log)
            time.sleep(10)
            continue

    # log_path = "log/u_ex210819.log"
    # run(log_path)




