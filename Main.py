# -*- coding: utf-8 -*-
import random
import hashlib
import pyaes, binascii, secrets
from base64 import b64encode, b64decode
#Name: Berke Derin Berktay
global iv
username = input("Enter username: ")
#FOR THE PROGRAM TO WORK AN EMPTY .TXT FILE NAMED COMMUNICATIONS THAT IS IN THE SAME DIRECTORY AS THIS .PY FILE IS NEEDED
#Here, because nothing is specified regarding the pool of Zq subgroup that we will use,
#I decided to randomly choose arbitrarily a 2 base bianrily
#40 bit prime number out of any 2 base binarily 40 bit primes, which 
#makes the pool very huge and therefore perfectly fits our purpose

max40digits = (pow(2,40) - 1 )
min40digits = (pow(2,39))

def isPrime(k):# function to check if the number is prime
    if k%2==0 or k<2: return False
    for i in range(3, int(k**(1/2)) + 1, 2):
        if k%i==0:
            return False
    return True

flag = False
while flag == False:
    k = random.randint(min40digits, max40digits)
    if isPrime(k) == True:
        q = k
        break# we find a prime q value in the interval

print("Our q is: " + str(q))

g = 2 #I arbitrarily chose a g value

a = random.randint(1, q-1) #this is our a for alice for question 1
h1 = pow(2,a,q) #this is our g to the power of a value or the "mixed color output of alice"
print("Our a is: " + str(a))
start = input("Type init to start the program: ")
if start == "init":
    print("Our h1 is: " + str(h1))    
    b = random.randint(1, q-1)
    print("Our b is: " + str(b))
    h2 = pow(2,b,q)
    #print("Our h2 is: " + str(h2))
    h2str = [c for c in str(h2)]
    
    f = open("Communications.txt","r+")
    for i in range(0,len(h2str)):
        f.write(str(h2str[i]))# I thought of first writing our h2 that we will look for inside the .txt since we need to have our b
                                        #for the h2 to be in between 0 and the same q-1 range that we used to determine h1 and any previous input
                                        #can not guarantee that and therefore we will put the h2 value inside the file and then assume that it was
                                        #already there(therefore not in ascii since we assume that we did not write this )and read 
                                        #it again as an input in order to ensure that we have a valid b that's in between 1 and q-1
        i = i + 1    
    f.close()
    f = open("Communications.txt","r+")
    lines = f.readlines()
    f.write("\n")
    h1str = [c for c in str(h1)]
    for i in range(0,len(h1str)):
        f.write(str(h1str[i]))# we write our h1 value into the file
        i = i + 1
    f.write(" 000000000000000\n")#because on the pdf it says that everything that we write has to have the 15 zeroes
                                    # I assumed that not just the messages but also the h1 should include the zeroes as well
    #f.close()
    inputh2 = str(lines[0])
    print("Our h2 is: " + inputh2)
    h2 = inputh2
    ourkey = pow(int(h2), a, q)
    f.close()
    f = open("Communications.txt","r+")
    lines = f.readlines()
    bobkey = pow(int(lines[1][0:len(lines[1])-16:1]), b, q)#Bob took the input for the h1 from the file
    print("Our(Alice) key is: " + str(ourkey))
    print("Our(Bob) key is: " + str(bobkey))
    if(ourkey == bobkey):
        print("The keys both match and therefore we are on the right track, let's hash the keys now")
    hashedourkey = hashlib.sha256(str(ourkey).encode('ascii')).hexdigest()
    hashedbobkey = hashlib.sha256(str(bobkey).encode('ascii')).hexdigest()
    print("Our(Alice) hashed key is: " + str(hashedourkey))
    print("Bob's hashed key is: " + str(hashedbobkey))
    
    binaryourkey256 = binascii.unhexlify(hashedourkey)
    binarybobkey256 = binascii.unhexlify(hashedbobkey)
    
    #in order for this aes 128 ctr encryption and decryption algorithm to work you need to pip install pyaes and pip install pbkdf
    # in order to terminate the conversation if wanted,the program needs to be terminated by the person whose turn it is to write a message
    #the user will play both as Alice and Bob and the encrypted messages will be put inside the .txt file. In other words, the inputs will be
    #given by the user
    # in order to write it into the text document, i turned the encryptions into strings HOWEVER I couldnt find a way to safely convert it to
    #ascii and safely convert the ascii back to the required format after reading it from the text. Something in the encryption always ends up
    #being off. So nothing is turned into ascii but the two parties still communicate or exchange info through the text file, so there is no
    #fundamental difference
    #Whoever's turn it is, the user reads the message which is encrypted from the text file and decrypts it using his or her own key.
    endconvoflag = "False"
    turnflag = "us"
    first = 1;
    while endconvoflag == "False":
        if first == 1:
            aliceinput = input("Enter " + username + "'s input message: ")
            iv = secrets.randbits(256)
            aes = pyaes.AESModeOfOperationCTR(binaryourkey256, pyaes.Counter(iv))
            ciphertext = aes.encrypt(aliceinput)
            print("The message's cyphertext in the bytes form: " + str(ciphertext)[2:len(str(ciphertext))-2:1])
            #Here we decode the cyphertext (in the type of bytes) into a string in order to put it inside the text file
            out = b64encode(ciphertext).decode('utf-8') 
            print("The message's cyphertext in the string form: " + out)
            f.write(out)
            f.write(" 000000000000000")
            turnflag = "them"
            endconvoflag = input("If you want to end the conversation, type True, if not type False: ")
            first = 0
        elif first == 0:
            if turnflag == "us":
                f.close()
                f = open("Communications.txt","r+")
                lines = f.readlines()
                #here we read the last message, parse it and then decrypt it using our key
                aes = pyaes.AESModeOfOperationCTR(binaryourkey256, pyaes.Counter(iv))
                decrypted = str(aes.decrypt(b64decode(lines[len(lines)-1][0:len(lines[len(lines)-1]) - 16:1])))
                decrypted = decrypted[2:len(decrypted)-1:1]
                print("We are in " + username + "'s window. " + "Bob's decrypted message was: " + decrypted)
                f.write("\n")
                ourinput = input("Enter "+ username + "'s input message: ")
                iv = secrets.randbits(256)
                aes = pyaes.AESModeOfOperationCTR(binaryourkey256, pyaes.Counter(iv))
                ciphertext = aes.encrypt(ourinput)
                print("The message's cyphertext in the bytes form: " + str(ciphertext)[2:len(str(ciphertext))-2:1])
                #Here we decode the cyphertext (in the type of bytes) into a string in order to put it inside the text file
                out = b64encode(ciphertext).decode('utf-8') 
                print("The message's cyphertext in the string form: " + out)
                f.write(out)
                f.write(" 000000000000000")
                turnflag = "them" 
                endconvoflag = input("If you want to end the conversation, type True, if not type False: ")
            elif turnflag == "them":
                f.close()
                f = open("Communications.txt", "r+")
                lines = f.readlines()
                #here we read the last message, parse it and then decrypt it using our key
                aes = pyaes.AESModeOfOperationCTR(binarybobkey256, pyaes.Counter(iv))
                decrypted = str(aes.decrypt(b64decode(lines[len(lines)-1][0:len(lines[len(lines)-1]) - 16:1])))
                decrypted = decrypted[2:len(decrypted)-1:1]
                print("We are in Bob's window. " + username + "'s decrypted message was: " + decrypted)
                f.write("\n")
                bobinput = input("Enter Bob" + "'s input message: ")
                iv = secrets.randbits(256)
                aes = pyaes.AESModeOfOperationCTR(binarybobkey256, pyaes.Counter(iv))
                ciphertext = aes.encrypt(bobinput)
                print("The message's cyphertext in the bytes form: " + str(ciphertext)[2:len(str(ciphertext))-2:1])
                #Here we decode the cyphertext (in the type of bytes) into a string in order to put it inside the text file
                out = b64encode(ciphertext).decode('utf-8') 
                print("The message's cyphertext in the string form: " + out)
                f.write(out)
                f.write(" 000000000000000")
                turnflag = "us" 
                endconvoflag = input("If you want to end the conversation, type True, if not type False: ")
    f.close()