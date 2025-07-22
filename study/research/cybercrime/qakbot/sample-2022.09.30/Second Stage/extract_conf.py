import hashlib
from arc4 import ARC4  

file = open("89210AF9.bin","rb") #Resource with Qakbot configuration
resource = file.read()

key = hashlib.sha1(b"Muhcu#YgcdXubYBu2@2ub4fbUhuiNhyVtcd").digest() #change with your password
rc4 = ARC4(key)
data = rc4.decrypt(resource)

key = data[20:40]
rc4 = ARC4(key)

decrypted_data = rc4.decrypt(data[40:])
print("Qakbot Configuration:")
print((decrypted_data[20:]).decode("utf-8"))



file = open("3C91E639.bin","rb") #Resource with Qakbot C2 
resource = file.read()

key = hashlib.sha1(b"Muhcu#YgcdXubYBu2@2ub4fbUhuiNhyVtcd").digest() #change with your password
rc4 = ARC4(key)
data = rc4.decrypt(resource)


key = data[20:40]
rc4 = ARC4(key)
#print(key)
decrypted_data = rc4.decrypt(data[40:])


print("Qakbot C2:")
for i in range(21,len(decrypted_data),7):
    c2 = bytearray(decrypted_data[i:i+7])
    print("%d.%d.%d.%d:%d" % (c2[0],c2[1],c2[2],c2[3],(c2[4]<<8)+c2[5]))

