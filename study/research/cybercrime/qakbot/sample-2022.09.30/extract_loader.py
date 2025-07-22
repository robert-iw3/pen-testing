import pefile
import re
import binascii
import hashlib
import struct
import base64

def rc4_decrypt(key,data):
	cipher = ARC4(key)
	return cipher.decrypt(data)
	
def return_key(data):
	
	pattern = "[a-zA-Z]{84}"
	match_object = re.search(pattern,data)
	string = data[match_object.start():match_object.end()]

	pattern = "[a-z]{33}"
	match_object = re.search(pattern,data)
	string += data[match_object.start():match_object.end()+1] 

	return hashlib.md5(string).hexdigest()


def return_shellcode_data(data):

	offset_size = 0x21884
	size =  data[offset_size:offset_size+0x3]
	size = struct.unpack("<i",size.ljust(4,"\x00"))[0]
	shellcode = data[offset_size-size:offset_size]
	return shellcode,size


def retrieve_data(filename):

	data_section = ""

	pe = pefile.PE(filename)
	for section in pe.sections:
		if ".rdata" in section.Name:
			key =	return_key(section.get_data())
		elif ".data" in section.Name:
			shellcode,size = return_shellcode_data(section.get_data())

	return key,shellcode,size

def decrypt_shellcode(shellcode,key):

	i = 0
	base64_shellcode ="\x00"
	for b in (shellcode):
		base64_shellcode += chr(ord(b) ^ ord(key[i % len(key)]))
		i+=1
	return base64_shellcode

	
def main():

	f = open("shellcode.bin","wb")
	filename = "tiddler.dat"
	key,shellcode,size = retrieve_data(filename)
	print "[+] KEY: " + str(key)
	print "[+] SIZE: " + str(size)
	shellcode = base64.b64decode(decrypt_shellcode(shellcode,key))
	f.write(shellcode)


if __name__ == '__main__':
	main()