import codecs
import math
import random
import fractions
from random import randrange, getrandbits


keyfilepath = 'keys.txt'
ciphertextpath = 'ciphertext.txt'
plaintextpath = 'plaintext.txt'

'''
key object
'''
class key:
    def __init__(self, e, n):
        self.e = e
        self.n = n
        self.kl = bin(n).__len__() - 2

    def encrypt(self, pt):
        ct = pow(pt, self.e, self.n)
        return ct


'''
Test if a number n is prime, tn is the number of tests using robin miller primality test
'''
def is_prime(n, tn=64):

    if n == 2 or n == 3: #base case 1
        return True
    if n <= 1 or n % 2 == 0:  #base case 2
        return False

    # finding r and s in so that (n-1) = r*(2^s)
    s = 0 #initial value
    r = n - 1 #intial value
    while r & 1 == 0: #checking for even r's
        s += 1
        r //= 2
    # do k tests
    for temp in range(tn):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


'''
generates a list of n prime number which are kl bits long
'''
def generate_prime_numbers(kl = 16, n = 2):
    pl = []
    p = (1<<kl) - 1

    while pl.__len__() < n:
        if is_prime(p, 64):
            pl.append(p)
            p = p - 8
        p = p-2
    return pl

'''
calculate the gcd of 2 integers
'''
def gcd(a, b):
    if b == 0:
        return (a)
    else:
        return(gcd(b, a%b))

'''
calculate modular inverse of an integer a with modulo m
'''
def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

'''
returns a random coprime of z which has a modular inverse
'''
def getkeypair(z):
    while True:
        e = random.randint(3, z - 1)
        # checking for coprimes and modular inverse
        if gcd(z, e) != 1:
            continue
        d = modinv(e,z)
        if d == None or d ==e:
            continue
        return (e,d)


'''
Rsa key generator, takes in key length and returns a key set (n, e, d)
'''
def RSA_keygen(kl = 16):
    pl = generate_prime_numbers(kl, 2)
    p = pl[0]
    q = pl[1]
    n = p * q

    z = (p - 1) * (q - 1)

    # Here we pick a random e, but a fixed value for e can also be used.
    pair = getkeypair(z)
    print("( "+ str(pair[0]) + ", " + str(n) + " )")
    print("(" + str(pair[1]) + ", " + str(n) + " )")
    f = open(keyfilepath, "w")
    f.write(str(pair[0]) + "\n")
    f.write(str(pair[1]) + "\n")
    f.write(str(n))
    f.close()

''' get keys from file
'''
def RSAkeys():
    file = open(keyfilepath, 'r')
    kstring = file.readlines()
    file.close()
    keys = [int(x.strip()) for x in kstring]
    return((key(keys[0], keys[2]), key(keys[1], keys[2])))

'''
binary to srting to ascii
'''
def btoa(cs):
    ct = ''
    while (cs.__len__() > 0):
        tem = cs[:8]
        cs = cs[8:]
        ct = ct + chr(int(tem,2))
    return ct

'''
ascii to srting to binary
'''
def atob(cs):
    pt = ''
    for a in cs:
        temp = bin(ord(a))[2:]
        temp = '0'*(8-temp.__len__())+temp
        pt = pt + temp
    return pt



'''encrypts message (warper around key.encrypt)
'''
def encrypt(pt, key):
    ct = ''
    bsize = 1#(key.kl-1)//8
    kbisize = (math.ceil(key.kl/8)*8)
    pt = atob(pt)

    while (pt.__len__() > 0):
        ptb = pt[:bsize*8]
        pt = pt[8*bsize:]
        c = key.encrypt(int(ptb,2))
        ctb = bin(c)[2:]
        ctb = '0'*(kbisize - ctb.__len__()) + ctb
        print(str(c) +" "+ (btoa(ctb)))
        ct = ct + ctb

    ct = btoa(ct)
    return(ct)

'''decrypts message (warper around key.decrypt)
'''
def decrypt(ct, key):
    pt = ''
    mbitsize = 8#((key.kl-1)//8)*8
    bsize = math.ceil(key.kl/8)*8

    ct = atob(ct)

    while (ct.__len__() > 0):
        word = ct[:bsize]
        ct = ct[bsize:]

        ptb = bin(key.encrypt(int(word,2)))[2:]
        ptb = '0'*(mbitsize - ptb.__len__()) + ptb
        pt = pt + ptb

    pt = btoa(pt)
    return(pt)


def RSA():

    while(True):
        i = input("Choose an option:\n0 - Exit\n1 - Encrypt \n2 - Decrypt \n3- Generate keys\n: ")
        try:
            i = int(i)
        except:
            continue

        if(i == 3):
            kl = input("Enter key length: ")
            RSA_keygen(24)
            print()
            input("press any key to exit")
            break

        elif(i == 1):
            (priv, pub) = RSAkeys()  # loading keys

            file = open(plaintextpath, 'r')
            message = file.read()  # reading plain text
            file.close()
            ct = encrypt(message, priv) # encrypting plain text
            file = codecs.open(ciphertextpath, "w", "utf-8")
            file.write(ct) # storing cipher text
            file.close()
            #print(ct)
            print()
            input("press any key to exit")
            break

        elif(i == 2):
            (priv, pub) = RSAkeys()  # loading keys

            file = codecs.open(ciphertextpath, "r", "utf-8")
            ct = file.read() # readng cipher text
            file.close()
            pt = decrypt(ct, pub) # decrypting
            print(pt)
            file = open(plaintextpath, "w")
            file.write(pt)  # storing plain text
            file.close()
            print()
            input("press any key to exit")
            break

        else:
            print()
            continue

RSA()