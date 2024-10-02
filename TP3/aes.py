import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


#print(key)
#       def process(self, msg=b""):

#def encrypt(key, plaintext, associated_data=b''):
def encrypt(key, plaintext, associated_data):
	# Generate a random 96-bit IV.
	iv = os.urandom(12)

	# Construct an AES-GCM Cipher object with the given key and a
	# randomly generated IV.
	print('Key: ' + str(key))
	encryptor = Cipher(
		algorithms.AES128(key),
		modes.GCM(iv),
		).encryptor()

	# associated_data will be authenticated but not encrypted,
	# it must also be passed in on decryption.
	encryptor.authenticate_additional_data(associated_data)
	print('Data: ' + str(associated_data))

	# Encrypt the plaintext and get the associated ciphertext.
	# GCM does not require padding.
	ciphertext = encryptor.update(plaintext) + encryptor.finalize()

#	return (iv, ciphertext)
	return (iv, ciphertext, encryptor.tag)

def decrypt(key, associated_data, iv, ciphertext, tag):
	# Construct a Cipher object, with the key, iv, and additionally the
	# GCM tag used for authenticating the message.
	print('Key: ' + str(key))
	decryptor = Cipher(
		algorithms.AES128(key),
		modes.GCM(iv, tag),
		).decryptor()

	print('Data: ' + str(associated_data))
	# We put associated_data back in or the tag will fail to verify
	# when we finalize the decryptor.
	decryptor.authenticate_additional_data(associated_data)

	# Decryption gets us the authenticated plaintext.
	# If the tag does not match an InvalidTag exception will be raised.
	return decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)


passphrase=input('Enter passphrase:').encode()
if len(sys.argv) != 5:
	print("	Usage: " + sys.argv[0] + " <cifra/decifra> key input-file output-file")
	sys.exit(0)
## Operation
if sys.argv[1] != "cifra" and sys.argv[1] != "decifra":
	print("	Error: Operation mode not recognized " +  sys.argv[1] + ">.\n	Available modes are: cifra, decifra.")
	sys.exit(1)
## key
try:
	with open(sys.argv[2], 'rb') as filekey: key = filekey.read()
except: # try string
	key = sys.argv[2].encode().strip()
	key = os.urandom(16) ## HACK
#	print(key.decode().strip())
	len = len(key)*8
	if len != 128:
		print("	Error: File not Found. Or wrong key size <"+ str(len) +"\nKey size must be 128-bit.")
		sys.exit(1)

## In
try:
	with open(sys.argv[3], 'rb') as infile: original = infile.read()
except FileNotFoundError:
	print("	Error: File not Found.")
	sys.exit(1)
## Out
try:
	with open(sys.argv[4], 'w') as oufile: pass
except PermissionError:
	print("	Error: Permission denied to open the file.")
	sys.exit(1)

if sys.argv[1] == "cifra":
#	iv, ciphertext, tag= encrypt(key, original, passphrase.encode())
	iv, ciphertext, tag= encrypt(key, original, passphrase)
	print('AES tag: ' + str(tag))
	print('IV: ' + str(iv))
	print('ciphertext: ' + str(ciphertext))
	size=round(int.from_bytes(tag).bit_length()/8)
	if size < 16:
		size = 16 # hack?

	with open(sys.argv[4], 'ab') as oufile:
		oufile.write((str(size)+"=").encode())
	with open(sys.argv[4], 'ab') as oufile:
		oufile.write(ciphertext)
	with open(sys.argv[4], 'ab') as oufile:
		oufile.write(iv)
		oufile.write(tag)
elif sys.argv[1] == "decifra":
	with open(sys.argv[3], 'rb') as file:
		n=0
		s=""
		while True:
			n+=1
			c = file.read(1)
			print(str(c))
			if "=" in str(c) or not c:
				break
			else:
				s+=str(c.decode())
	tg_sz=int(s)
	print('Tag size: ' + str(tg_sz) + ' bits')
	tg_iv_sz=tg_sz+12
	with open(sys.argv[3], 'rb') as file:
		file.seek(-tg_sz, os.SEEK_END)
		tag = file.read(tg_sz)
		print('AES tag: ' + str(tag))

#	with open(sys.argv[3], 'rb') as file:
		file.seek(-tg_iv_sz, os.SEEK_END)
		iv = file.read(12)
		print('IV : ' + str(iv))
	with open(sys.argv[3], 'rb') as file:
		ciphertext = file.read()[n:-tg_iv_sz]
		print('ciphertext: ' + str(ciphertext))
		result = decrypt(key,passphrase,iv,ciphertext,tag)
	with open(sys.argv[4], 'wb') as oufile:
		oufile.write(result)

