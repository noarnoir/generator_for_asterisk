#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import requests, random, paramiko, socket, struct, time
chars = '-_abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
otv =[]
ot = []
data =[]
diff = []
di = []
dis = []
print('')
print('')
print('')
print (' $$$$$$\  $$$$$$\ $$$$$$$\         $$$$$$\   $$$$$$\  $$\   $$\ $$$$$$$$\ ')
print ('$$  __$$\ \_$$  _|$$  __$$\       $$  __$$\ $$  __$$\ $$$\  $$ |$$  _____|')
print ('$$ /  \__|  $$ |  $$ |  $$ |      $$ /  \__|$$ /  $$ |$$$$\ $$ |$$ |      ')
print ('\$$$$$$\    $$ |  $$$$$$$  |      $$ |      $$ |  $$ |$$ $$\$$ |$$$$$\    ')
print (' \____$$\   $$ |  $$  ____/       $$ |      $$ |  $$ |$$ \$$$$ |$$  __|   ')
print ('$$\   $$ |  $$ |  $$ |            $$ |  $$\ $$ |  $$ |$$ |\$$$ |$$ |      ')
print ('\$$$$$$  |$$$$$$\ $$ |            \$$$$$$  | $$$$$$  |$$ | \$$ |$$ |      ')
print (' \______/ \______|\__|             \______/  \______/ \__|  \__|\__|      ')
print('')
print('')
print('')
print('')
print ('Внешний IP вводить с маской!!! Можно и подсеть:)')
if not len(ex) == 0:
    ex_ext=[]
    ext_ex=[]
    ext_ex_1 =[]
    for i in range(len(ex)):
        ex_i = ex[i].split('/')
        ex_i_0 = ex_i[0]
        ex_i_1 = 32 - int(ex_i[1])
        netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << ex_i_1 ))) 
        ext_ex = ex_i_0 + '/' + netmask
        ext_ex_1.append(ext_ex)
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
}
params = (
    ('module', 'sip'),
    ('show', 'action'),
    ('sql', 'search'),
)
data = {
    'phone': 'num'
	}
    if y != -1 :
    y = otv[i].replace('<td align="left">','').replace('</td>','').replace('<tr><td','')
    ot.append(y)
for n in range(1):
    password =''
    for i in range(10):
        password += random.choice(chars)
dog_keep = ''.join(dog_k)
ipa_bi = ''.join(ipadd_bi)
ipa_bi_svn = ''.join(ipadd_bi_svn)
username_1 = ['username = ',nomer]
username_sip = ''.join(username_1)
username_1_svn = ['username = ',nomer+'\n']
username_sip_svn = ''.join(username_1_svn)
secret_1 = ['secret = ',password]
secret_sip = ''.join(secret_1)
secret_1_svn = ['secret = ',password+'\n']
secret_sip_svn = ''.join(secret_1_svn)
accountcode_1 = ['accountcode = ',nomer]
accountcode_sip = ''.join(accountcode_1)
accountcode_1_svn = ['accountcode = ',nomer+'\n']
accountcode_sip_svn = ''.join(accountcode_1_svn)
callerid_1 = ['callerid = ',nomer]
callerid_sip = ''.join(callerid_1)
callerid_1_svn = ['callerid = ',nomer+'\n']
callerid_sip_svn = ''.join(callerid_1_svn)
defa_ip = ['defaultip = ',ipadd_bill]
default_ip_sip = ''.join(defa_ip)
defa_ip_svn = ['defaultip = ',ipadd_bill+'\n']
default_ip_sip_svn = ''.join(defa_ip_svn)
ipa_1 = ['permit = ',ipa_bi]
ipadd_sip = ''.join(ipa_1)
ipa_1_svn = ['permit = ',ipa_bi+'\n']
ipadd_sip_svn = ''.join(ipa_1_svn)
limit_1 = ['call-limit = ',limit_bill]
limit_sip = ''.join(limit_1)
limit_1_svn = ['call-limit = ',limit_bill+'\n']
limit_sip_svn = ''.join(limit_1_svn)
st = str(len(setvar_bill))
print ('')
print ('')
print ('')
print ('')
print ('~~~~~SIP conf~~~~~')
print ('')
print ('')
print nomer_bill
print dog
print ('type = friend')
print username_sip
print secret_sip
print accountcode_sip
print callerid_sip
print ('host = dynamic')
print default_ip_sip
print ('deny = 0.0.0.0/0.0.0.0')
print 'permit =',ipa_bi
        ext_si = ['permit = ', ext_ex_1[i]]
        ext_sip = ''.join(ext_si)
        print ext_sip
    cont_1 =['context = ',context_bill]
    context_sip = ''.join(cont_1)
if context_sip != 0:
	    print context_sip
st = len(setvar_bill)
        setvar_si ='setvar = ',setvar_bill[i]
        setvar_sip = ''.join(setvar_si)
        print setvar_sip
print ('disallow = all')
print ('allow = alaw')
print ('allow = ulaw')
print limit_sip
print ('directmedia = no')
print ('nat = auto_force_rport,auto_comedia')
print ('~~~~~~~~~~~~~~~~')
print ('')
print ('')
print ('')
print ('')
print ('~~~~~Отсылаем клиенту~~~~~')
print ('')
print ('Адрес для поднятия регистрации sipserver.novotelecom.ru')
print 'username =',nomer
print 'secret =',password
print ('')
print ('')
print ('~~~~~~~~~~~~~~~~')
sip_conf_genera = [nomer_bill, dog, 'type = friend', username_sip, secret_sip, accountcode_sip, callerid_sip, 'host = dynamic', default_ip_sip]
        ext_si = ['permit = ', ext_ex_1[i]]
        ext_sip = ''.join(ext_si)
        sip_conf_genera.append(ext_sip)
sip_conf_genera.append('deny = 0.0.0.0/0.0.0.0')
if context_bill != 0:
    sip_conf_genera.append (context_sip)
        setvar_si ='setvar = ',setvar_bill[i]
        setvar_sip = ''.join(setvar_si)
        sip_conf_genera.append(setvar_sip)
sip_conf_genera.append('disallow = all')
sip_conf_genera.append('allow = alaw')
sip_conf_genera.append('allow = ulaw')
sip_conf_genera.append(limit_sip)
sip_conf_genera.append('directmedia = no')
sip_conf_genera.append('nat = auto_force_rport,auto_comedia')
host_sip1 = 'sipserver1.core'
host_sip2 = 'sipserver2.core'
host_sip3 = 'sipserver-03.core'
host_sip4 = 'sipserver-04.core'
command_sip_from_host = 'grep', nomer, '/etc/asterisk/sip.conf -A17 -B1'
command_find = ' '.join(command_sip_from_host)
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(hostname=host_sip4, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
stdin, stdout, stderr = client.exec_command(command_find)
data_search_from_sipserver = stdout.read() + stderr.read()
client.close()
print ('')
print ('')
strok_sip_server = len(data_search_from_sipserver)
svn_yes = 'y'
if not len(data_search_from_sipserver) != 0:
    print ('На SVN пусто. Покажем diff')
    if svn_add == svn_yes:
        os.system("rm /home/grigorevada/asterisk/sip.conf")
        os.system("/usr/bin/svn up ~/asterisk/")
        svn_sip_conf.write("\n")
        svn_sip_conf.write(nomer_bill_svn)
        svn_sip_conf.write(dog_svn)
        svn_sip_conf.write("type = friend\n")
        svn_sip_conf.write(username_sip_svn)
        svn_sip_conf.write(secret_sip_svn)
        svn_sip_conf.write(accountcode_sip_svn)
        svn_sip_conf.write(callerid_sip_svn)
        svn_sip_conf.write("host = dynamic\n")
        svn_sip_conf.write(default_ip_sip_svn)
        svn_sip_conf.write("deny = 0.0.0.0/0.0.0.0\n")
        svn_sip_conf.write(ipa_bi_svn)
                ext_si = ['permit = ', ext_ex_1[i],'\n']
                ext_sip = ''.join(ext_si)
                svn_sip_conf.write(ext_sip)
            cont_1_svn =['context = ',context_bill,'\n']
            context_sip_svn = ''.join(cont_1_svn)
        if context_sip_svn != 0:
                svn_sip_conf.write(context_sip_svn)
                setvar_si_svn ='setvar = ',setvar_bill[i],'\n'
                setvar_sip_svn = ''.join(setvar_si_svn)
                svn_sip_conf.write(setvar_sip_svn)
        svn_sip_conf.write("disallow = all\n")
        svn_sip_conf.write("allow = alaw\n")
        svn_sip_conf.write("allow = ulaw\n")
        svn_sip_conf.write(limit_sip_svn)
        svn_sip_conf.write("directmedia = no\n")
        svn_sip_conf.write("nat = auto_force_rport,auto_comedia\n")
        svn_sip_conf.write("\n")
        os.system("/usr/bin/svn diff ~/asterisk/")
        if svn_ci == svn_yes:
            print ('GO')
            os.system("/usr/bin/svn commit -m sip-conf ~/asterisk/")
            print ('Ok')
else:  
	print('Нужно добавить в sip.conf') 
	print('')
	print('')
        for i in range(len(diff_list)):
            di = []
            diff = (diff_list[i])
            di.append(diff)
            if di != -1:
                for i in range(len(di)):
                    if y != -1:
                         dis.append(di[i])
            if di != -1:
                for i in range(len(di)):
                    if y != -1:
                        dis.append(di[i])
        for i in range(len(diff_list)):
            di = []
            diff = (diff_list[i])
            di.append(diff)
            if di != -1:
                for i in range(len(di)):
                    if y != -1:
                         dis.append(di[i])
            if di != -1:
                for i in range(len(di)):
                    if y != -1:
                        dis.append(di[i])
        for i in range(len(diff_list)):
            di = []
            diff = (diff_list[i])
            di.append(diff)
            if di != -1:
                for i in range(len(di)):
                    if y != -1:
                         dis.append(di[i])
            if di != -1:
                for i in range(len(di)):
                    if y != -1:
                        dis.append(di[i])
        for i in range(len(dis)):
            diff = (dis[i])
            print diff
print ('')
route = []
data_route_find =[]
data_route_check =[]
data_keep_check =[]
command_find_route =[]
host_dc004 = 'a0dc-004'                                                                                                         
host_dc010 = 'a0dc-010'                                                                                                         
host_sip1 = 'sipserver1.core'  
host_sip2 = 'sipserver2.core'  
host_sip3 = 'sipserver-03.core'
host_sip4 = 'sipserver-04.core'
def chosen_dc():
    while True: 
        print "Выбор проброса:"
        print ""
        print "1 - Добавить IP в firewall DC классическая телефония"
        print "2 - Kazoo DC"
        print "3 - Эмуляция. Просто печать команд"
        print "4 - Проверка где есть IP"
        print ""
        if "1" in route:
            print ('Запуск проброса IP в firewall DC')
            print ('')
            print ('DC-004') 
            print ('')
            print ('')
            command_route_add_dc_conf = 'configure private\n'
            command_route_add_dc_show_compare = 'show | compare\n'
            command_route_add_dc_commit_and_quit = 'commit and-quit\n\n'
            ssh_pre = paramiko.SSHClient()
            ssh_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_pre.connect(hostname=host_dc004, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
            ssh = ssh_pre.invoke_shell()
            ssh.send(command_route_add_dc_conf)
            time.sleep(2)
            for i in range(len(ex)):
                command_route_find_dc = 'show firewall | match '+  ex[i] +'\n'
                ssh.send(command_route_find_dc)
                time.sleep(1)
                output004 = []
                output004 = ssh.recv(65535)
                if len(output004) != 1177:
                    print ('На a0dc-004 ' + ex[i] + ' есть')
                    output004 = []
                else:
                    print (ex[i]+ ' нет. Добавляем в a0dc-004')
                    command_route_add_dc_pre = 'set firewall family inet filter VLAN1536_out term external_to_sipserver from source-address '+  ex[i] +'\n'
                    command_route_add_dc = ''.join(command_route_add_dc_pre)
                    ssh.send(command_route_add_dc)
                    output004 = []
            ssh.send(command_route_add_dc_commit_and_quit)
            time.sleep(10)
            output004 = ssh.recv(65535)
            ssh_pre.close()
            print ('')
            print ('DC-010')
            print ('')
            print ('')
            command_route_add_dc_conf = 'configure private\n'
            command_route_add_dc_show_compare = 'show | compare\n'
            command_route_add_dc_commit_and_quit = 'commit and-quit\n'
            ssh_pre = paramiko.SSHClient()
            ssh_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_pre.connect(hostname=host_dc010, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
            ssh = ssh_pre.invoke_shell()
            ssh.send(command_route_add_dc_conf)
            time.sleep(2)
            for i in range(len(ex)):
                command_route_find_dc = 'show firewall | match '+  ex[i] +'\n'
                ssh.send(command_route_find_dc)
                time.sleep(1)
                output010 = []
                output010 = ssh.recv(65535)
                if len(output010) != 816:
                    print ('На a0dc-010 ' + ex[i] + ' есть')
                    output010 = []
                else:
                    print (ex[i] +' нет. Добавляем в a0dc-010')
                    command_route_add_dc_pre = 'set firewall family inet filter VLAN1536_out term external_to_sipserver from source-address '+  ex[i] +'\n'
                    command_route_add_dc = ''.join(command_route_add_dc_pre)
                    ssh.send(command_route_add_dc)
                    output010 = []
            ssh.send(command_route_add_dc_commit_and_quit)
            time.sleep(10)
            ssh_pre.close()
        elif "2" in route:
            print ('Запуск проброса IP Kazoo DC')
            for i in range(len(ex)):
                print ('DC-004')        
                command_route_add_dc_conf = 'configure private\n'
                command_route_add_dc_show_compare = 'show | compare\n'
                command_route_add_dc_commit_and_quit = 'commit and-quit\n\n'
                ssh_pre = paramiko.SSHClient()
                ssh_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_pre.connect(hostname=host_dc004, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
                ssh = ssh_pre.invoke_shell()
                ssh.send(command_route_add_dc_conf)
                time.sleep(2)
                for i in range(len(ex)):
                    command_route_add_kazoo_sip_rtp = 'set firewall family inet filter VLAN1536_out term kazoo_sip_rtp from source-address  '+  ex[i] +'\n'
                    command_route_add_kazoo_sip = 'set firewall family inet filter VLAN1536_out term kazoo_sip from source-address '+  ex[i] +'\n'
                    ssh.send(command_route_add_kazoo_sip)
                    ssh.send(command_route_add_kazoo_sip_rtp)
            ssh.send(command_route_add_dc_commit_and_quit)
            time.sleep(10)
            output004 = ssh.recv(65535)
            ssh_pre.close()
            for i in range(len(ex)):
                print ('DC-010')        
                command_route_add_dc_conf = 'configure private\n'
                command_route_add_dc_show_compare = 'show | compare\n'
                command_route_add_dc_commit_and_quit = 'commit and-quit\n'
                ssh_pre = paramiko.SSHClient()
                ssh_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_pre.connect(hostname=host_dc010, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
                ssh = ssh_pre.invoke_shell()
                ssh.send(command_route_add_dc_conf)
                time.sleep(2)
                for i in range(len(ex)):
                    command_route_add_kazoo_sip_rtp = 'set firewall family inet filter VLAN1536_out term kazoo_sip_rtp from source-address  '+  ex[i] +'\n'
                    command_route_add_kazoo_sip = 'set firewall family inet filter VLAN1536_out term kazoo_sip from source-address '+  ex[i] +'\n'
                    ssh.send(command_route_add_kazoo_sip)
                    ssh.send(command_route_add_kazoo_sip_rtp)
                ssh.send(command_route_add_dc_commit_and_quit)
                time.sleep(10)
                output010 = ssh.recv(65535)
                ssh_pre.close()
        elif "3" in route:
            print ('')
            print ('')
            print ('')
            print ('')
            print ('Эмуляция команд')
            print ('')
            print ('')
            print ('')
            print ('Добавление route')
            print ('')
            print ('')
            for i in range(len(ex)): 
                command_route_add = 'sudo ip route add ' + ex[i] +' via 178.49.132.1 dev eth0.1536'
                print command_route_add
            print ('Data Centre')
            print ('')
            for i in range(len(ex)):
                command_route_add_dc_pre = 'set firewall family inet filter VLAN1536_out term external_to_sipserver from source-address '+  ex[i] +'\n'
                command_route_add_dc = ''.join(command_route_add_dc_pre)
                print command_route_add_dc
            print ('Kazoo')
            print ('')
            print ('')
            for i in range(len(ex)):
                command_route_add_kazoo_sip_rtp = 'set firewall family inet filter VLAN1536_out term kazoo_sip_rtp from source-address  '+  ex[i] +'\n'
                command_route_add_kazoo_sip = 'set firewall family inet filter VLAN1536_out term kazoo_sip from source-address '+  ex[i] +'\n'
                print command_route_add_kazoo_sip
                print command_route_add_kazoo_sip_rtp
        elif "4" in route:
            print ('Проверка')
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host_sip4, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
            for i in range(len(ex)):
                ex_i = ex[i].split('/')
                ex_i_0 = ex_i[0]
                command_route_from_host = 'ip r | grep '+  ex_i_0
                command_find_route = ''.join(command_route_from_host)
                stdin, stdout, stderr = client.exec_command(command_find_route)
                data_route_find_004 = stdout.read() + stderr.read()
            print ('sipserver4')
            print data_route_find_004
            client.close()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host_sip3, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
            for i in range(len(ex)):
                ex_i = ex[i].split('/')
                ex_i_0 = ex_i[0]
                command_route_from_host = 'ip r | grep '+  ex_i_0
                command_find_route = ''.join(command_route_from_host)
                stdin, stdout, stderr = client.exec_command(command_find_route)
                data_route_find_010 = stdout.read() + stderr.read()
            print ('sipserver3')
            print data_route_find_010
            client.close()
            print ('DC-004')
            for i in range(len(ex)):
                ssh_pre = paramiko.SSHClient()
                ssh_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_pre.connect(hostname=host_dc004, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
                ssh = ssh_pre.invoke_shell()
                time.sleep(2)
                for i in range(len(ex)):
                    command_route_find_dc = 'show configuration firewall | match '+  ex[i] +'\n'
                    ssh.send(command_route_find_dc)
                time.sleep(1)
                output004 = ssh.recv(65535)
                print output004
                ssh_pre.close()
            for i in range(len(ex)):
                ssh_pre = paramiko.SSHClient()
                ssh_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_pre.connect(hostname=host_dc010, username=user_secret, password=pass_secret, look_for_keys=False, allow_agent=False)
                ssh = ssh_pre.invoke_shell()
                time.sleep(2)
                for i in range(len(ex)):
                    command_route_find_dc = 'show configuration firewall | match '+  ex[i] +'\n'
                    ssh.send(command_route_find_dc)
                time.sleep(1)
                output010 = ssh.recv(65535)
                print output010
                ssh_pre.close()
                print ('DC-010')
        else:                                                                                  
            print ('')
            print ('')
            print ('Выбери что делать')
            print ('')
            continue
        return
chosen_dc()
