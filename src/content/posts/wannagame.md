---
title: WannaGame Cyber Knight 2024
published: 2024-06-24
description: ''
image: ''
tags: ['Lattice', 'MATH', 'AES']
category: 'CTF Writeups'
draft: false 
---
# Warmup

- chall.py
```python
from Crypto.Util.number import * 
from Crypto.Util.Padding import pad 
from flag import flag 
from gmpy2 import next_prime

message = b"The challenge's flag is: " + flag
assert len(message) % 3 == 0

part1 = message[ : len(message)//3]
part2 = message[len(message)//3 : 2*len(message)//3]
part3 = message[2*len(message)//3 : ]
sep = "#"*50

## part 1: Warm-up!!!
p1 = getPrime(512)
q1 = getPrime(512)
e1 = 11
n1 = p1 * q1
c1 = pow(bytes_to_long(part1), e1, n1)
print(f'{n1 = }')
print(f'{c1 = }')
print(sep)

## part 2: One more warm-up
p2 = getPrime(1024)
q2 = getPrime(1024)
n2 = p2*q2 
e2 = 17
print(f'{n2 = }')
print(f'Real: {pow(bytes_to_long(part2), e2, n2)}')
print(f'Fake: {pow(bytes_to_long(pad(part2, 16)), e2, n2)}')
print(sep)

## part 3: The last "warm-up"
p3,q3 = getPrime(1024), getPrime(1024)
n3 = p3 * q3
power1, power2 = getPrime(128), getPrime(128)
hint1 = pow((5*p3 + q3), power1, n3)
hint2 = pow((3*p3 - 6*q3), power2, n3)

e3 = next_prime(hint1 + hint2)
c3 = pow(bytes_to_long(part3), e3, n3)
print(f'{power1 = }')
print(f'{power2 = }')
print(f'{n3 = }')
print(f'{hint1 = }')
print(f'e3 = {e3}')
print(f'c3 = {c3}')
```

## Solution
- Ta thấy **FLAG** được chia làm 3 phần có độ dài bằng nhau và được encrypt theo những cách riêng.
- Trong lúc diễn ra giải mình đã decrypt part 2 đầu tiên
- Ta có thể thấy được phần **Real** là **FLAG** sau khi encrypt còn **FAKE** là `pad(FLAG)` sau khi decrypt
- Từ đây ta có thể bruteforce hết 16 trường hợp padding có thể và tìm **GCD** giữa 2 phương trình sẽ ra được (x - **FLAG**)
- Part 2:
```python
from sage.all import *
from Crypto.Util.number import *
from Crypto.Util.Padding import pad

n2 = 19474122562778153703776906234103999694212644666605609184003798714902765132186442270466413951685774096672600567147343733732980015161843616032962680857426708013412213676449861264155297288378479051436442079937058938840721841860491557712477170366628773688474634289507561262017382779613838956398073685517438883550013563737919252844748012781298212795883037816078874734356565506037923530508679278288097627681354570158653097456586858900957218344882318145320067184688094419746980554117499065442646088691226289819440434740945671726394148366572739206464970977471727197412322136575227898097076974504287523260885786539573649783161
Real = 15636713266108700464255355282572617369877416762456096086219951374063737359559203674454786265210431923339051086905021926447634666321503985769492720281115251569517394409997291661224097948320454420612478527160246859233690225189444979403485318497052362506638619146425116246060495195223943704647051304805754627681254961634405541974848733951519522486396630609303328097791062133825888690738129275001884247653912942268589773666008633702027740289575546500039837328482189167641136880443555991865875325701485342918164649959219812272157959283006261464655737656031536878365520892164396734804695179528627342810772907739309174183304
Fake = 1901702486995025261538235880685531918771879286327896110111123890041702504494161154076737842357693655100992364579118174208323657012644698015659577716664514828814910889887457132697217080176306194565595589316187612945830703382031867854831608485926311704058671506309214522654866677161067649723883561755848469509892417562279714400249673848323509379109641015242793126408247724149712397397815568653344550396176143675147065423111733067480933601053636423334747702190300411842735906299712817499994397771633456847764374609445235276286713165285446045446123174200222508610983202190618557770618976371164659678708230871711252574428

def mygcd(f,g):
    while g != 0:
        r = g
        g = f % g
        f = r
    return f/f.lc()

P = PolynomialRing(Zmod(n2), 'x')   
x = P.gen()
p1 = x ** 17 - Real
test = b''
for i in range(16):
    padding = pad(test, 16)[i:]
    p2 = (2 ** ((16 - i) * 8) * x + bytes_to_long(padding)) ** 17 - Fake
    t = mygcd(p1, p2)
    if t.degree() == 1:
        print(long_to_bytes(int(-t[0]) % n2))
        break
    test += b'\x01'
```
```
_lA_15_h1hi__75f26f70b3fa1343153e
```
- Tiếp đến là part 1, sau khi decrypt xong part 2 ta biết được độ dài của từng thành phần là 33 ký tự và ta cũng biết được 25 ký tự đầu + thêm "W1{" là 28 ký tự. Giờ ta chỉ cần small_roots để tìm nốt phần còn lại.
- Part 1:
```python
from sage.all import *
from Crypto.Util.number import *
from Crypto.Util.Padding import pad


n1 = 78100017093042237362585803611409807219210686771960485296694671535293298684240391999007937128416933959949645805107079926652343615109335481443408319617478348436412156203990196717356668119025919695447421356649708220217528303406969275048476878616591756855326600516077838718677582495646251901652030452534739980093
c1 = 21635094418936882229318713100837056867730099226953717083953338957077431886511252266065867668680214410547969294123420920750052299754539343424046939642019856856637610693840992502539517724666655388883948397275320947350529293996784254524553566619189584795444284261967162826834735297201762488824862476117397669601

message = b"The challenge's flag is: W1{\x00\x00\x00\x00\x00"
message = bytes_to_long(message)

P = PolynomialRing(Zmod(n1), 'x')   
x = P.gen()
f = (message + x) ** 11 - c1

FLAG = f.small_roots(X=2**50, beta=0.5, epsilon=0.015)
print(b"The challenge's flag is: W1{" + long_to_bytes(int(FLAG[0])))
```
```
The challenge's flag is: W1{A_p0r
```
- Đến với part cuối cùng, bạn có thể tham khảo Modular Binomials
- Giờ bạn chỉ cần bruteforce hết tất cả các hint2 phù hợp cho đến khi nào xuất hiện $p$ là được
- Part 3:
```python
import math
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from gmpy2 import next_prime

power1 = 216515682056074917890546762360422775759
power2 = 181261651362416112447857910756974715253
n3 = 21359428772367567762465177652844235016399133661109374171468438854776561246101192389880378563002849491963133317822943728663659947135787662718455826488579139110050277672340965370240377096647337916266432987314270685198434379314123632571454622139263629066529934934145277818436942937601606973322506307539554768214679444922661752071123001107723044536675764939605450418550872933311130411355136155266638811137191949645399770280529254355150837851996371018266855150538183941848828564579160123399867316204489663532672172085306182442910667707542525506401104797512848908939121437800995819119455775357620426817733038470495147276793
hint1 = 21165771737478725950851391268640839742282738803460982495702522148737396455865260539601340347151173375617657055655041043517629027492240234235183580296831387302596600695810822254431016035932293471628759197250919622480691606652634091857970182748360357623125515085919940174799049558949629746381693045991973156293505919951290743073241929003963830080590083449251389368841868741731209817737242746289090221167945649864511277017186337822956848075038306043349755593388069666507069280026419826266727104285440789673438901905195589837692674191838634684368474851772930333812341283933491515890683850912453399208298386277684434445251
e3 = 37168304783168980393920173579379710993074140739837792931728618759911393587739974232300850198277091657299514225039110963445571485237776790392542202542871178828780578794970964528554601212794008256754381717435669983473010005148311575428821001052237868999060224515275873668669213982474419104490433570572105845650251833635244326980880559203371594232931397547585750248068741794286062945536039069446641110263273308725041343806223241749757368437839639116744539107461153105289738651458945715419945820612645097201055521095139028646379860663948813756288318543675883368961217287301785966051639519026541020372279840744062219039191
c3 = 1096068813757106861072993580055082418953963625562486119593706360815623910450146273178847639647973866883042811190136050041007753762866893600939527521717867763640548952449681014994092425911219237532793217675033536632826439864589482883751579581380877418411747043359264793736856167378058319757084322522347500331245555941134923517945671002893760566068668447306048296218747434127148067031352038287679665515172443331784546991573906825482519792803285599056922851777942853546318660474033734361350200902964188996923538488714615644961271863386265655804388494579456404108898159557142645993950324859997370434010675900211652602515
hint2 = 16002533045690254443068782310738871250791401936376810436026096611173997131874713692699509851125918281681857169384069919927942457745536556157358622246039791526183978099160142274123585176861714785125622520184750360992318398495677483570850818303877511375934709429355933493870164423524789358108740524580132689356745913683953583907638630199407764152341314098334360879226873052554853127798796323157550889095327658860530066789036903926800520362801333073394783514073083438782669371432525889153218716327204307527616619189943438808687186472110179071919843691902953035148876003368294450160955668114087621163981454466377784586475

while True:
    p = math.gcd((pow(3, (-power1 * power2), n3) * pow(hint2, power1, n3) - pow(5, (-power2 * power1), n3) * pow(hint1, power2, n3)) * (n3 - 6) % n3, n3)
    if p != 1:
        break
    
    hint2 += 1

p3 = p
p3 = 149980597760000270288020712564730421423970532153531109538283372659249090766781034501997790624701674901461522882220113357725378245572684453212159175961586586191733952945436353476578468558720453741235833653421187406171537615120165747876478240633282821626182454380149314563971827086993047558004886558019962996419
q3 = n3 // p3
assert p3 * q3 == n3

phi = (p3 - 1) * (q3 - 1)
d = pow(e3, -1, phi)
m = pow(c3, d, n3)
print(long_to_bytes(m))
```
```
a91411ae238_happy_hacking!!!!!!!}
```

- Kết hợp cả 3 part lại ta có được
```
W1{A_p0r_lA_15_h1hi__75f26f70b3fa1343153ea91411ae238_happy_hacking!!!!!!!}
```

# 435
- server.py
```python
from Crypto.Cipher import AES 
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from Crypto.Util.Padding import pad, unpad
import os



GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[33m'
NORM = '\033[0m'

BANNER = \
    f"""
    {YELLOW} 
 ___       __   ________  ________   ________   ________  ___       __     _____  ________      
|\  \     |\  \|\   __  \|\   ___  \|\   ___  \|\   __  \|\  \     |\  \  / __  \|\   ___  \    
\ \  \    \ \  \ \  \|\  \ \  \\\ \  \ \  \\\ \  \ \  \|\  \ \  \    \ \  \|\/_|\  \ \  \\\ \  \   
 \ \  \  __\ \  \ \   __  \ \  \\\ \  \ \  \\\ \  \ \   __  \ \  \  __\ \  \|/ \ \  \ \  \\\ \  \  
  \ \  \|\__\_\  \ \  \ \  \ \  \\\ \  \ \  \\\ \  \ \  \ \  \ \  \|\__\_\  \   \ \  \ \  \\\ \  \ 
   \ \____________\ \__\ \__\ \__\\\ \__\ \__\\\ \__\ \__\ \__\ \____________\   \ \__\ \__\\\ \__\\
    \|____________|\|__|\|__|\|__| \|__|\|__| \|__|\|__|\|__|\|____________|    \|__|\|__| \|__|

    {NORM}
Once upon a time, deep in the forest, there lies a great treasure but protected with a digital padlock. Rumor said that whoever could open the treasure would be rewarded with great riches. You, as a treasure hunter, decided to go on a trip to uncover this elusive prize. After facing countless obstacles and challenges, you finally reached the location of the treasure. Next to the treasure lies a truncated poem. You, as a master in cryptography also, will not give up easily right? Goodluck! ;)
    """



menu = \
f"""\
{NORM}
1. ECB_encrypt
2. CBC_decrypt
3. Crack Password
{"~"*100}
"""



class Riddle:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce

    def GCM_encrypt(self, plaintext):
        """
        Return encryption of AES-GCM with provided plaintext
        """
        cipher_ = AES.new(self.key, AES.MODE_GCM, self.nonce)
        return cipher_.encrypt_and_digest(plaintext)

    def ECB_encrypt(self, plaintext):
        """
        Return encryption of AES-ECB with provided plaintext
        """
        cipher_ = AES.new(self.key, AES.MODE_ECB)
        return cipher_.encrypt(plaintext)

    def CBC_decrypt(self, iv, ciphertext):
        """
        Return decryption of AES-CBC with provided (ciphertext, iv)
        """
        cipher_ = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher_.decrypt(ciphertext)



print(BANNER)

cipher = Riddle(key = os.urandom(16), nonce = os.urandom(12))


secret = os.urandom(256)
poem = \
pad(b"""\
The security code is simple, an intricate dance of numbers.
A shield against intruders, a fortress for slumbers.
Digits align in harmony, a secret melody they sing,
Guarding the treasures of a realm, where secrets take their wing : \
""", 16) + secret

print(secret.hex())


ciphertext, tag = cipher.GCM_encrypt(poem)

print(f"ct = '{ciphertext.hex()}'")
print(f"tag = '{tag.hex()}'")


while True:
    print(menu)
    option = int(input("Your choice > "))
    try:
        match option:
            case 1:
                m = bytes.fromhex(input("Please give me your message (in hex) > "))
                c = cipher.ECB_encrypt(m)
                print(c.hex())
            case 2:
                iv = bytes.fromhex(input("Please give me your iv (in hex) > "))
                c = bytes.fromhex(input("Please give me your ciphertext (in hex) > "))
                m = cipher.CBC_decrypt(iv, c)
                print(m.hex())
            case 3:
                key = bytes.fromhex(input("Give me your secret (in hex) > "))
                if key == secret:
                    FLAG = open('flag.txt', 'r').read()
                    print(f"{GREEN}Wow you did surprise me!! Here is your reward {FLAG}")
                    exit()
                else:
                    print("Ahh, try better next time :(")
                    exit()
            case _:
                print("No idea what you choose :(")
    except Exception as e: 
        print(f"{RED}An exception occurred: {str(e)}")
```

## Solution
- Bài này cho ta **ciphertext** và **tag** đã được encrypt qua AES GCM cũng với các chức năng **ECB_encrypt** và **CBC_decrypt**
- Ta biết phần encrypt của GCM hoặc động giống như Counter nên ta có thể đưa phần xor(ciphertext, plaintext) qua **CBC_decrypt** với IV = 0 để tìm lại được Counter
- Giờ ta chỉ cần cộng dần Counter lên rồi cho đi qua **ECB_encrypt** rồi lấy kết quả đó xor với ciphertext sẽ được xâu gốc
```python
from Crypto.Cipher import AES 
from Crypto.Util import Counter
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad
import os
from pwn import *

# io = process(['python3', 'server.py'])
io = remote("45.122.249.68", 20024)

context.log_level = 'debug'

secret = os.urandom(256)
poem = \
pad(b"""\
The security code is simple, an intricate dance of numbers.
A shield against intruders, a fortress for slumbers.
Digits align in harmony, a secret melody they sing,
Guarding the treasures of a realm, where secrets take their wing : \
""", 16) + secret

io.recvuntil(b'ct = ')
ct = io.recvline().strip().decode()[1:-1]
ct = bytes.fromhex(ct)


test = xor(ct, poem)

io.sendafter(b'> ', b'2\n')
io.sendafter(b'> ', b"00" * 16 + b"\n")
io.sendafter(b'> ', test.hex().encode() + b'\n')

res = io.recvline().strip().decode()

res = res[:32]
counter = bytes_to_long(bytes.fromhex(res))

payload = b""
while len(payload) != len(ct):
    payload += long_to_bytes(counter)
    counter += 1

io.sendafter(b'> ', b'1\n')
io.sendafter(b'> ', payload.hex().encode() + b'\n')

res = io.recvline().strip().decode()
res = bytes.fromhex(res)

payload = xor(res, ct)[240:]
io.sendafter(b'> ', b'3\n')
io.sendafter(b'> ', payload.hex().encode() + b'\n')

io.interactive()
```
```
Wow you did surprise me!! Here is your reward W1{7hE_S3cRe7_L13s_4m0N9_M0De5_0f_0p3r4ti0n_cddde2b1d3eec22ffcd8c871faca7639}
```

# AESSS
- server.py
```python
import os
import random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import SHA256
from secret import FLAG

flag1 = FLAG[:len(FLAG)//3].encode()
flag2 = FLAG[len(FLAG)//3:2*len(FLAG)//3].encode()
flag3 = FLAG[2*len(FLAG)//3:].encode()

assert len(flag1) == len(flag2) == len(flag3) == 48

def pad(data, block_size):
    return data + (block_size - len(data) % block_size) * bytes([block_size - len(data) % block_size])


def challenge_part1(flag):
    key = os.urandom(16)
    iv = os.urandom(16)
    options = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']
    suboptions = ['data', 'flag']

    for _ in range(3):  # you only have 3 tries, stingy huh?
        [option, suboption, *more] = input('> ').split(' ')
        if option not in options:
            print('invalid option!')
            continue 
        if suboption not in suboptions:
            print('invalid suboption!')
            continue
        options.remove(option)

        if suboption == 'data':
            message = bytes.fromhex(more[0])
        else:
            message = flag

        if option == 'ecb':
            cipher = AES.new(key, AES.MODE_ECB)
        elif option == 'cbc':
            cipher = AES.new(key, AES.MODE_CBC, iv)
        elif option == 'cfb':
            cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        elif option == 'ofb':
            cipher = AES.new(key, AES.MODE_OFB, iv)
        elif option == 'ctr':
            cipher = AES.new(key, AES.MODE_CTR,
                             counter=Counter.new(16, prefix=iv[:14]))

        ciphertext = cipher.encrypt(message)
        print(ciphertext.hex())
    else:
        print('No more options!')


def challenge_part2(flag):
    key = os.urandom(16)

    while True:
        try:
            options = input('> ').split(' ')
            if (options[0] == "encrypt_flag"):
                iv = os.urandom(16)
                cipher = AES.new(key, AES.MODE_GCM, iv)
                message = flag
                ciphertext= cipher.encrypt(message)
                print("Encrypted flag and tag, iv:", ciphertext.hex(), iv.hex())

            elif (options[0] == "encrypt_data"):
                iv = bytes.fromhex(options[1])
                cipher = AES.new(key, AES.MODE_GCM, iv)
                message = bytes.fromhex(input('input data:'))
                ciphertext= cipher.encrypt(message)
                print("Encrypted message and tag, iv:", ciphertext.hex(), iv.hex())
            else:
                print("Invalid option!")
        except Exception as e:
            print("An error occurred: ", e)
            break


def challenge_part3(flag):
    try:
        salt = os.urandom(2) # prevent rainbow table attack and ... brute force attack?
        password_file_path = os.path.join(os.path.dirname(__file__), "rockyou.txt") # rockyou.txt is a list of common passwords
        print(f"Looking for rockyou.txt at: {password_file_path}")

        if not os.path.isfile(password_file_path):
            print(f"Error: {password_file_path} not found")
            return

        with open(password_file_path, "rb") as file:
            passwords = file.readlines()[:100]

        password = random.choice(passwords).strip()
        key = SHA256.new(password + salt.hex().encode()).digest()[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(password, 16))
        print("Encrypted password:", ciphertext.hex())

        input_password = input('input password:')
        if input_password.encode() == password:
            print("Correct password!")
            print("Good job! Here is your flag:", flag)
        else:
            print("Incorrect password!")

    except FileNotFoundError:
        print("rockyou.txt not found")
        return
    except Exception as e:
        print(f"An error occurred: {e}")
        return


def main():
    chall_option = input('challenge option:')
    if chall_option == '1':
        challenge_part1(flag1)
    elif chall_option == '2':
        challenge_part2(flag2)
    elif chall_option == '3':
        challenge_part3(flag3)
    else:
        print('Invalid option!')


if __name__ == '__main__':
    main()
```
## Solution
- Part 1:
```python
import os
import random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from pwn import *


io = remote("45.122.249.68", 20026)

context.log_level = "DEBUG"

io.sendlineafter(b"option:", b'1')
io.sendline(b"cfb data " + b"00" * 48)
enc1 = io.recvline().strip()[2:].decode()
print(enc1)
io.sendline(b"ofb flag")
enc2 = io.recvline().strip()[2:].decode()
print(enc2)
enc1 = bytes.fromhex(enc1)
enc2 = bytes.fromhex(enc2)
print(xor(enc1, enc2))
```
```
W1{AES_1s_w1d3ly_us3d_1n_r3al_w0rld_applic4t10ns
```
- Part 2:
```python
import os
import random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from pwn import *

io = remote("45.122.249.68", 20026)

context.log_level = "DEBUG"

io.sendlineafter(b"option:", b'2')
io.sendlineafter(b"> ", b"encrypt_flag")
io.recvuntil(b"iv: ")
enc1, iv = io.recvline().strip().decode().split(" ")
enc1 = bytes.fromhex(enc1)

io.sendlineafter(b"> ", b"encrypt_data" + b" " + iv.encode())
io.sendlineafter(b"input data:", b"00" * 48)
io.recvuntil(b"iv: ")
enc2, iv = io.recvline().strip().decode().split(" ")

enc2 = bytes.fromhex(enc2)
print(xor(enc1, enc2))
```
```
_4nd_1s_c0ns1d3r3d_t0_b3_0n3_0f_th3_m0st_s3cur3_
```
- Part 3:
```python
import os
import random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from pwn import *

io = remote("45.122.249.68", 20026)

context.log_level = "DEBUG"

io.sendlineafter(b"option:", b'3')
io.recvuntil(b"password: ")
enc = io.recvline().strip().decode()
print(enc)
with open("rockyou.txt", "rb") as file:
    passwords = file.readlines()[:100]

for password in passwords:
    password = password.strip()
    print(password)
    for bf1 in range(256):
        for bf2 in range(256):
            salt = bytes([bf1]) + bytes([bf2])
            key = SHA256.new(password + salt.hex().encode()).digest()[:16]
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(password, 16))
            if ciphertext.hex() in enc or enc in ciphertext.hex():
                print("True")
                io.sendlineafter(b"input password:", password)
                io.interactive()
```
```
alg0r1thms_1n_pr4ct1c3_66e14a195cd4b2e9d5059ca1a
```
- Ghép cả 3 lại:
```
W1{AES_1s_w1d3ly_us3d_1n_r3al_w0rld_applic4t10ns_4nd_1s_c0ns1d3r3d_t0_b3_0n3_0f_th3_m0st_s3cur3_alg0r1thms_1n_pr4ct1c3_66e14a195cd4b2e9d5059ca1a
```

# Master of gacha
## Solution
```python
from pwn import *
from sage.all import *
import random
import json
from Crypto.Util.number import *
from hashlib import sha256 

class Twister:
    N = 624
    M = 397
    A = 0x9908b0df

    def __init__(self):
        self.state = [[(1 << (32 * i + (31 - j))) for j in range(32)] for i in range(624)]
        self.index = 0

    @staticmethod
    def _xor(a, b):
        return [x ^ y for x, y in zip(a, b)]

    @staticmethod
    def _and(a, x):
        return [v if (x >> (31 - i)) & 1 else 0 for i, v in enumerate(a)]

    @staticmethod
    def _shiftr(a, x):
        return [0] * x + a[:-x]

    @staticmethod
    def _shiftl(a, x):
        return a[x:] + [0] * x

    def get32bits(self):
        if self.index >= self.N:
            for kk in range(self.N):
                y = self.state[kk][:1] + self.state[(kk + 1) % self.N][1:]
                z = [y[-1] if (self.A >> (31 - i)) & 1 else 0 for i in range(32)]
                self.state[kk] = self._xor(self.state[(kk + self.M) % self.N], self._shiftr(y, 1))
                self.state[kk] = self._xor(self.state[kk], z)
            self.index = 0

        y = self.state[self.index]
        y = self._xor(y, self._shiftr(y, 11))
        y = self._xor(y, self._and(self._shiftl(y, 7), 0x9d2c5680))
        y = self._xor(y, self._and(self._shiftl(y, 15), 0xefc60000))
        y = self._xor(y, self._shiftr(y, 18))
        self.index += 1

        return y

    def getrandbits(self, bit):
        return self.get32bits()[:bit]


class Solver:
    def __init__(self):
        self.equations = []
        self.outputs = []

    def insert(self, equation, output):
        for eq, o in zip(self.equations, self.outputs):
            lsb = eq & -eq
            if equation & lsb:
                equation ^= eq
                output ^= o

        if equation == 0:
            return

        lsb = equation & -equation
        for i in range(len(self.equations)):
            if self.equations[i] & lsb:
                self.equations[i] ^= equation
                self.outputs[i] ^= output

        self.equations.append(equation)
        self.outputs.append(output)

    def solve(self):
        num = 0
        for i, eq in enumerate(self.equations):
            if self.outputs[i]:
                # Assume every free variable is 0
                num |= eq & -eq

        state = [(num >> (32 * i)) & 0xFFFFFFFF for i in range(624)]
        return state

def get_random_bytes(num):
    x = os.urandom(num)
    y = random.randbytes(num)
    # print(x.hex(), y.hex())
    return x + y


def inv(n, q):
    return egcd(n, q)[0] % q


def egcd(a, b):
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        pass
    return s0, t0, a


def sqrt(n, q):
    assert n < q
    for i in range(1, q):
        if i * i % q == n:
            return (i, q - i)
        pass
    raise Exception("not found")

########## ECC Implement ##########

Coord = collections.namedtuple("Coord", ["x", "y"])


class EC(object):
    """System of Elliptic Curve"""
    def __init__(self, a, b, q, n):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        self.a = a
        self.b = b
        self.q = q
        self.zero = Coord(0, 0)
        self.order = n
        pass

    def is_valid(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            return self.zero
        if p1.x == p2.x:
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * inv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        r = self.zero
        m2 = p
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
                pass
            n, m2 = n >> 1, self.add(m2, m2)
            pass
        return r

    # def order(self, g):
    #     assert self.is_valid(g) and g != self.zero
    #     for i in range(1, self.q + 1):
    #         if self.mul(g, i) == self.zero:
    #             return i
    #         pass
    #     raise Exception("Invalid order")
    # pass

class DSA(object):
    def __init__(self, ec : EC, g : Coord):
        self.ec = ec
        self.g = g
        self.n = ec.order
        pass

    def gen(self, priv):
        assert 0 < priv and priv < self.n
        return self.ec.mul(self.g, priv)

    def sign(self, hashval, priv, r):
        assert 0 < r and r < self.n
        m = self.ec.mul(self.g, r)
        return (m.x, inv(r, self.n) * (hashval + m.x * priv) % self.n)
 
    def validate(self, hashval, sig, pub):
        assert self.ec.is_valid(pub)
        assert self.ec.mul(pub, self.n) == self.ec.zero
        w = inv(sig[1], self.n)
        u1, u2 = hashval * w % self.n, sig[0] * w % self.n
        p = self.ec.add(self.ec.mul(self.g, u1), self.ec.mul(pub, u2))
        return p.x % self.n == sig[0]
    pass

##### redo this after done code
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
curve_order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = Coord(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, \
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
ec_object = EC(A, B, P, curve_order)
dsa_object = DSA(ec_object, G)

Ln = 256

num = 1500
bit = 24

twister = Twister()
output = []


# io = process(['python3', 'server.py'])
io = remote("45.122.249.68", 20025)
# Register
io.sendlineafter(b">> ", b"2")
io.sendlineafter(b"username: ", b"admin")
io.recvuntil(b"Account information:\n")
user = []
cookies = []
user.append(io.recvline().strip())
io.recvuntil(b"Cookie: ")
cookies.append(io.recvline().strip())

# login
io.sendlineafter(b">> ", b"1")
io.sendlineafter(b"information: ", user[0])
io.sendlineafter(b"cookie: ", cookies[0])

# Gacha
outputs = []
for i in range(num):
    print(i)
    io.sendlineafter(b">> ", b"4")
    io.sendlineafter(b"number: ", b"1")
    io.recvuntil(b"Lucky number is: ")
    res = io.recvline().strip()
    res = int(res)
    res = res & 0xffffff
    res = res.to_bytes(3, "little")
    outputs.append(int.from_bytes(res, "big"))

# io.interactive()
# outputs = [int.from_bytes(random.randbytes(3)[::-1], "big") for _ in range(num)]
equations = [twister.getrandbits(bit) for _ in range(num)]

solver = Solver()
for i in range(num):
    print(i)
    io.sendlineafter(b">>", b"3")
    for j in range(bit):
        solver.insert(equations[i][j], (outputs[i] >> (bit - 1 - j)) & 1)

state = solver.solve()
recovered_state = (3, tuple(state + [0]), None)
random.setstate(recovered_state)

for i in range(num):
    assert outputs[i] == random.getrandbits(bit)

n = 50
context.log_level = 'debug'

for i in range(n):
    # register
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"username: ", b"admin")
    user_id = get_random_bytes(8)
    io.recvuntil(b"Account information:\n")
    user.append(io.recvline().strip())
    io.recvuntil(b"Cookie: ")
    cookies.append((io.recvline().strip(), random.randbytes((curve_order).bit_length() // 16).hex()))


B = 2 ** 128

M = Matrix(QQ, n + 3, n + 3)
M[0, 0] = B
M[1, 1] = B
M[2, 2] = B / curve_order

for i in range(n):
    hashval = bytes_to_long(sha256(user[i + 1]).digest()[:Ln])
    r, s = cookies[i + 1][0].decode().split(".")
    k = int(cookies[i + 1][1], 16)
    r = int(r, 16)
    s = int(s, 16)
    M[0, i + 3] = inverse(s, curve_order) * inverse(2 ** 128, curve_order) * hashval % curve_order
    M[1, i + 3] = inverse(2 ** 128, curve_order) * (-k % curve_order) % curve_order
    M[2, i + 3] = inverse(s, curve_order) * inverse(2 ** 128, curve_order) * r % curve_order
    M[i + 3, i + 3] = curve_order

def register_account(username : str, isAdmin : bool, privkey: int):
    tmp = {"username" : username, "isAdmin" : isAdmin}

    user_id = get_random_bytes(8)
    tmp["userID"] = user_id.hex()


    while True:
        random_k = int.from_bytes(get_random_bytes((curve_order).bit_length() // 16), "big")
        if random_k < curve_order:
            break
    
    tmp_hash = bytes_to_long(sha256(json.dumps(tmp).encode()).digest()[:Ln])
    r, s = dsa_object.sign(tmp_hash, privkey, random_k)

    cookie = long_to_bytes(r).hex() + "." + long_to_bytes(s).hex()
    return tmp, cookie

M = M.LLL()
for i in M:
    if i[0] == B and i[1] == B:
        print(i[-1] * 2 ** 128 % curve_order + int(cookies[-1][1], 16))
        k = i[-1] * 2 ** 128 % curve_order + int(cookies[-1][1], 16)
        hashval = bytes_to_long(sha256(user[-1]).digest()[:Ln])
        r, s = cookies[-1][0].decode().split(".")
        r = int(r, 16)
        s = int(s, 16)
        d = (k * s - hashval) * inverse(r, curve_order) % curve_order
        print(d)
        payload1, payload2 = register_account("admin", True, d)
        print(payload1)
        io.sendlineafter(b">> ", b"1")
        io.sendlineafter(b"information: ", json.dumps(payload1).encode())
        io.sendlineafter(b"cookie: ", payload2)
        io.sendlineafter(b">> ", b"3")
        io.interactive()
        
```
```
W1{it_1s_n3v3r_saf3_t0_us3_n0n_secure_cryptogr4phic_r4nd0mizat!0n}
```