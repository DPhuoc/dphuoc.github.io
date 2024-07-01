---
title: "Hack The Box: Apocalypse 2024"
published: 2024-04-06
description: ''
image: ''
tags: ['HASH', 'AES', 'ECC']
category: 'CTF Writeups'
draft: false 
---
# 1. Dynasty (very easy)

## Attachments:
- chall.py
```python
from random import randint
from secret import FLAG

def to_identity_map(a):
    return ord(a) - 0x41


def from_identity_map(a):
    return chr(a % 26 + 0x41)


def encrypt(m):
    c = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha():
            ech = ch
        else:
            chi = to_identity_map(ch)
            ech = from_identity_map(chi + i)
        c += ech
    return c


with open('output.txt', 'w') as f:
    f.write('Make sure you wrap the decrypted text with the HTB flag format :-]\n')
    f.write(encrypt(FLAG))
```
- output.txt
```
Make sure you wrap the decrypted text with the HTB flag format :-]
DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL
```

## Solution:
Ta thấy FLAG được encrypt bằng cách:
- Nếu ký tự trong flag không thuộc bảng chữ cái thì $enc_i = FLAG_i$
- Nếu thuộc bảng chữ cái thì $enc_i = chr(ord(FLAG_i - 0x41 + i) \ \% \ 26 + 0x41)$

$\rightarrow FLAG_i = chr(ord(enc_i - 0x41 - i) \ \% \ 26 + 0x41)$

```python 
enc = "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"

FLAG = ""

for i in range(len(enc)):
    if enc[i].isalpha():
        FLAG += chr((ord(enc[i]) - 0x41 - i) % 26 + 0x41)
    else:
        FLAG += enc[i]

print(f"HTB{{{FLAG}}}")
```

## FLAG
```
HTB{DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!_IT_IS_SIMILAR_TO_CAESAR_CIPHER}
```

# 2. Make shift (very easy)

## Attachments:
- chall.py
```python
from secret import FLAG

flag = FLAG[::-1]
new_flag = ''

for i in range(0, len(flag), 3):
    new_flag += flag[i+1]
    new_flag += flag[i+2]
    new_flag += flag[i]

print(new_flag)
# "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
```

## Solution:
- Nếu các bạn tinh ý nhận ra thì code để encrypt cũng chính là code để descrypt
```python
enc = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"

enc = enc[::-1]

flag = ''

for i in range(0, len(enc), 3):
    flag += enc[i + 1]
    flag += enc[i + 2]
    flag += enc[i]

print(flag)
```

## FLAG

```
HTB{4_b3tTeR_w3apOn_i5_n3edeD!?!}
```

# 3. Primary Knowledge (very easy)

## Attachments:
- chall.py
```python
import math
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

m = bytes_to_long(FLAG)

n = math.prod([getPrime(1024) for _ in range(2 ** 0)])
e = 0x10001
c = pow(m, e, n)

with open('output.txt', 'w') as f:
    f.write(f'{n = }\n')
    f.write(f'{e = }\n')
    f.write(f'{c = }\n')
# n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
# e = 65537
# c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215
```

## Solution:
Khi đọc kỹ code thì ta thấy được rằng $n$ là một số nguyên tố
Và ta biết rằng phi hàm Euler của $n$ chính là $n - 1$ 
Dựa vào đó ta có thể 
```python
from Crypto.Util.number import long_to_bytes

n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
e = 65537
c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215

phi = n - 1

d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

## FLAG
```
HTB{0h_d4mn_4ny7h1ng_r41s3d_t0_0_1s_1!!!}
```

# 4. Blunt (easy)

## Attachments:
- chall.py
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime, long_to_bytes
from hashlib import sha256

from secret import FLAG

import random

p = getPrime(32)
print(f'p = 0x{p:x}')

g = random.randint(1, p - 1)
print(f'g = 0x{g:x}')

a = random.randint(1, p - 1)
b = random.randint(1, p - 1)

A, B = pow(g, a, p), pow(g, b, p)

print(f'A = 0x{A:x}')
print(f'B = 0x{B:x}')

C = pow(A, b, p)
assert C == pow(B, a, p)

# now use it as shared secret
hash = sha256()
hash.update(long_to_bytes(C))

key = hash.digest()[:16]
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print(f'ciphertext = {encrypted}')
# p = 0xdd6cc28d
# g = 0x83e21c05
# A = 0xcfabb6dd
# B = 0xc4a21ba9
# ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'
```

## Solution
Vì các số đều là số nguyên tố nhỏ nên có thể dùng [tool](https://www.alpertron.com.ar/DILOG.HTM) hoặc sử dụng hàm `discrete_log` trong `sage` để tính được $a$
Từ đó ta sẽ có key của AES
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import *
from hashlib import sha256
from tqdm import tqdm

p = 0xdd6cc28d
g = 0x83e21c05
A = 0xcfabb6dd
B = 0xc4a21ba9
ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'

a = 2766777741

C = pow(B, a, p)

hash = sha256()
hash.update(long_to_bytes(C))

key = hash
key = key.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)

decrypted = cipher.decrypt(ciphertext)
print(f'decrypted = {decrypted}')
```

## FLAG
```
HTB{y0u_n3ed_a_b1gGeR_w3ap0n!!}
```


# 5. Iced Tea (easy)

## Attachments
- chall.py
```python
import os
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

from secret import FLAG

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02


class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i + self.BLOCK_SIZE // 16]) for i in range(0, len(key), self.BLOCK_SIZE // 16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB

    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE // 8)
        blocks = [msg[i:i + self.BLOCK_SIZE // 8] for i in range(0, len(msg), self.BLOCK_SIZE // 8)]

        ct = b''
        print(self.mode)
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE // 2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk

        m = ((m0 << (self.BLOCK_SIZE // 2)) + m1) & ((1 << self.BLOCK_SIZE) - 1)  # m = m0 || m1

        return l2b(m)


if __name__ == '__main__':
    KEY = os.urandom(16)
    cipher = Cipher(KEY)
    ct = cipher.encrypt(FLAG)
    with open('output.txt', 'w') as f:
        f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')
        
# Key : 42ed720514532a272f972569a56f8ff0
# Ciphertext : 8850a0af3c9c09610e044b6df550e4e2bb65162e479b4ccfea201fd3533cd8
```


## Solution:
Sau khi đọc code một hồi thì mình nhận thấy rằng Block Cipher này có một nhược điểm là không có ``confusion`` và ``diffusion``
Vì vậy mình hoàn toàn có thể reverse lại code để từ đó viết hàm `descrypt_block`
```python
from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

Key = "850c1413787c389e0b34437a6828a1b2"
Ciphertext = "b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843"


class Mode(Enum):
    ECB = 0x01
    CBC = 0x02


class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i + self.BLOCK_SIZE // 16]) for i in range(0, len(key), self.BLOCK_SIZE // 16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB

    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE // 8)
        blocks = [msg[i:i + self.BLOCK_SIZE // 8] for i in range(0, len(msg), self.BLOCK_SIZE // 8)]

        ct = b''
        print(self.mode)
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def descrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE // 8)
        blocks = [msg[i:i + self.BLOCK_SIZE // 8] for i in range(0, len(msg), self.BLOCK_SIZE // 8)]

        ct = b''
        print(self.mode)
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.descrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.descrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE // 2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk

        m = ((m0 << (self.BLOCK_SIZE // 2)) + m1) & ((1 << self.BLOCK_SIZE) - 1)  # m = m0 || m1

        return l2b(m)

    def descrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE // 2)) - 1

        s = self.DELTA << 5
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA
        m = ((m0 << (self.BLOCK_SIZE // 2)) + m1) & ((1 << self.BLOCK_SIZE) - 1)

        return l2b(m)


if __name__ == '__main__':
    KEY = bytes.fromhex(Key)
    cipher = Cipher(KEY)
    ct = bytes.fromhex(Ciphertext)
    print(cipher.descrypt(ct))
```

## FLAG
```
HTB{th1s_1s_th3_t1ny_3ncryp710n_4lg0r1thm_____y0u_m1ght_h4v3_4lr34dy_s7umbl3d_up0n_1t_1f_y0u_d0_r3v3rs1ng}
```

# 6. Partial Tenacity (Medium)

## Attachments:
- chall.py
```python

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from secret import FLAG

class RSACipher:
    def __init__(self, bits):
        self.key = RSA.generate(bits)
        self.cipher = PKCS1_OAEP.new(self.key)

    def encrypt(self, m):
        return self.cipher.encrypt(m)

    def decrypt(self, c):
        return self.cipher.decrypt(c)


cipher = RSACipher(1024)

enc_flag = cipher.encrypt(FLAG)

with open('output.txt', 'w') as f:
    f.write(f'n = {cipher.key.n}\n')
    f.write(f'ct = {enc_flag.hex()}\n')
    print(cipher.key.p)
    print(str(cipher.key.p)[::2])
    print(cipher.key.q)
    print(str(cipher.key.q)[1::2])
    f.write(f'p = {str(cipher.key.p)[::2]}\n')
    f.write(f'q = {str(cipher.key.q)[1::2]}')
    
# n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
# ct = "7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476"
# p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
# q = 15624342005774166525024608067426557093567392652723175301615422384508274269305
```

## Solution:
- Sau khi đọc code ta thấy t sẽ nhận được một nửa của $p$ và $q$
- Ở bài này ta có thể xài `BFS` để tìm 2 số nguyên tố $p$ và $q$
- Để tăng tốc độ và độ chính xác ta sẽ thêm 2 điều kiện
    + Nếu $p_i$ * $q_i$ > $n$ thì sẽ skip state đó
    + Chúng ta sẽ kiểm tra xem những chữ số cuối của $p_i$ * $q_i$ có giống với những chữ số cuối của $n$ không. Nếu không ta cũng sẽ skip state đó
```python
from Crypto.Util.number import long_to_bytes, inverse

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct = "7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476"
p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
q = 15624342005774166525024608067426557093567392652723175301615422384508274269305

pstr = str(p)
qstr = str(q)
cnt = 1
nums = [(pstr[-1], "1", 1)]
while True:
    nums2 = []
    for p, q, i in nums:
        pi = int(p)
        qi = int(q)
        cnt = cnt + 1
        if pi * qi == n:
            print("found")
            assert pi * qi == n

            key = RSA.construct((n, 65537, inverse(65537, (pi - 1) * (qi - 1)), pi, qi))
            cipher = PKCS1_OAEP.new(key)

            print(cipher.decrypt(bytes.fromhex(ct)))
            exit()

        if pi * qi > n:
            continue

        if (n - pi * qi) % (10 ** i) != 0:
            continue

        for j in range(10):
            if i % 2 == 1:
                nums2.append((str(j) + p, qstr[-(i // 2 + 1)] + q, i + 1))
            else:
                nums2.append((pstr[-(i // 2 + 1)] + p, str(j) + q, i + 1))

    nums = nums2
```

## FLAG
```
HTB{v3r1fy1ng_pr1m3s_m0dul0_p0w3rs_0f_10!}
```

# 7. Arranged (Medium)
## Attachments
- chall.sage
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

from secret import FLAG, p, b, priv_a, priv_b

F = GF(p)
E = EllipticCurve(F, [726, b])
G = E(926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

A = G * priv_a
B = G * priv_b

print(A)
print(B)

C = priv_a * B

assert C == priv_b * A

# now use it as shared secret
secret = C[0]

hash = sha256()
hash.update(long_to_bytes(secret))

key = hash.digest()[16:32]
iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print(encrypted)
```
- output.txt
```python
(6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997 : 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696 : 1)
(4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734 : 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865 : 1)
b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'
```
## Solution
- Điều đầu tiên ta cần làm trong bài này là tìm là $p$ và $b$ của ECC
- Challenge cho ta 3 điểm và ta biết được rằng
$\begin{cases}
y_G ^ 2 \equiv x_G ^ 3 + 726*x_G + b \ (mod \ p) \\
y_A ^ 2 \equiv x_A ^ 3 + 726*x_A + b \ (mod \ p) \\
y_B ^ 2 \equiv x_B ^ 3 + 726*x_B + b \ (mod \ p) \\
\end{cases}$

$\rightarrow \begin{cases}
y_G ^ 2 - y_A ^ 2 - x_G ^ 3 + x_A ^ 3 - 726*x_G + 726*x_A  \equiv 0 \ (mod \ p) \\
y_A ^ 2 - y_B ^ 2 - x_A ^ 3 + x_B ^ 3 - 726*x_A + 726*x_B  \equiv 0 \ (mod \ p) \\
y_B ^ 2 - y_G ^ 2 - x_B ^ 3 + x_G ^ 3 - 726*x_B + 726*x_G  \equiv 0 \ (mod \ p) \\
\end{cases}$

Đặt lần lượt từng biểu thức trên là $x$,$y$,$z$

$\rightarrow p = gcd(x, y, z)$

$\rightarrow b = (y_A^2 - x_a^3 - 726 * x_a) \ \% \ p$

Tiếp đến khi check ta sẽ thấy được rằng `G.order() = 11`. Vì thế ta có thể bruteforce từ 1 đến 11 để tìm `secret` đúng
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
import math

A = (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997, 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696)
B = (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734, 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865)
G = (926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

enc = b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'

a = 726

tmp1 = (A[1] ^ 2 - B[1] ^ 2 - A[0] ^ 3 + B[0] ^ 3 - a * A[0] + a * B[0])
tmp2 = (G[1] ^ 2 - A[1] ^ 2 - G[0] ^ 3 + A[0] ^ 3 - a * G[0] + a * A[0])
tmp3 = (G[1] ^ 2 - B[1] ^ 2 - G[0] ^ 3 + B[0] ^ 3 - a * G[0] + a * B[0])

p = math.gcd(tmp1, tmp2, tmp3)
b = (A[1] ^ 2 - A[0] ^ 3 - a * A[0]) % p

F = GF(p)
E = EllipticCurve(F, [a, b])

G = E(G)
A = E(A)
B = E(B)

iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'

for i in range(12):
    C = A * int(i)
    secret = C[0]

    hash = sha256()
    hash.update(long_to_bytes(int(secret)))

    key = hash.digest()[16:32]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted = cipher.decrypt(enc)
    if b'HTB{' in decrypted:
        print(decrypted.decode())
        break
```
## FLAG
```
HTB{0rD3r_mUsT_b3_prEs3RveD_!!@!}
```
# 8. Tsayaky (Hard)

## Attachments
- chall.py
```python
from tea import Cipher as TEA
from secret import IV, FLAG
import os

ROUNDS = 10

def show_menu():
    print("""
============================================================================================
|| I made this decryption oracle in which I let users choose their own decryption keys.   ||
|| I think that it's secure as the tea cipher doesn't produce collisions (?) ... Right?   ||
|| If you manage to prove me wrong 10 times, you get a special gift.                      ||
============================================================================================
""")

def run():
    show_menu()

    server_message = os.urandom(20)
    print(f'Here is my special message: {server_message.hex()}')
    
    used_keys = []
    ciphertexts = []
    for i in range(ROUNDS):
        print(f'Round {i+1}/10')
        try:
            ct = bytes.fromhex(input('Enter your target ciphertext (in hex) : '))
            assert ct not in ciphertexts

            for j in range(4):
                key = bytes.fromhex(input(f'[{i+1}/{j+1}] Enter your encryption key (in hex) : '))
                assert len(key) == 16 and key not in used_keys
                used_keys.append(key)
                cipher = TEA(key, IV)
                enc = cipher.encrypt(server_message)
                if enc != ct:
                    print(f'Hmm ... close enough, but {enc.hex()} does not look like {ct.hex()} at all! Bye...')
                    exit()
        except:
            print('Nope.')
            exit()
            
        ciphertexts.append(ct)

    print(f'Wait, really? {FLAG}')


if __name__ == '__main__':
    run()
```

## Solution

Đầu tiên ta cần phải hiểu flow của chương trình. Khi netcat vào, server sẽ chả về cho chúng ta một `message` ở dạng hex.
Nhiệm vụ của ta là phải hoàn thành 10 rounds với công việc là tìm đúng `ciphertext` sau khi encrypt `message` với 4 `key` khác nhau.

Ta thấy được chương trình này dựa trên TeaCipher theo mode CBC (Một loại cipher mà chúng ta đã làm việc ở bài ICED TEA)

Trong code của bài trên thì ta thấy có 2 MODE là ECB và CBC

![image](https://hackmd.io/_uploads/B1kAxcR1C.png)

![image](https://hackmd.io/_uploads/H135ZcR10.png)


Ta thấy rằng khi ta nhập sai thì server sẽ trả lại ta chuỗi encrypt của message

Vậy nên nếu chúng ta lấy chuỗi và decrypt theo ECB thì ta sẽ có được message chưa xor với IV
Vậy ta chỉ cần xor với message ban đầu sẽ có `IV = b'\r\xdd\xd2w<\xf4\xb9\x08\'`
IV chỉ có 8 bytes thôi nhé, lúc đầu mình cũng nghĩ mãi sao chỉ có 8 mà không phải 16 bytes =)))

Giờ thì công việc của chúng ta chỉ còn làm thế nào để generate ra 4 key mà không làm thay đổi giá trị sau khi encrypt thôi

Sau một chút thời gian osint thì ta tìm thấy được với 1 key sẽ có thể tạo ra 3 equivalent keys dưới đây

![image](https://hackmd.io/_uploads/SkKuH9RJ0.png)

Giờ đến lúc ta bắt tay vào code nào:

```python
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum
from pwn import *


class Mode(Enum):
    ECB = 0x01
    CBC = 0x02


class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i + self.BLOCK_SIZE // 16]) for i in range(0, len(key), self.BLOCK_SIZE // 16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB

    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE // 8)
        blocks = [msg[i:i + self.BLOCK_SIZE // 8] for i in range(0, len(msg), self.BLOCK_SIZE // 8)]

        ct = b''
        print(self.mode)
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def descrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE // 8)
        blocks = [msg[i:i + self.BLOCK_SIZE // 8] for i in range(0, len(msg), self.BLOCK_SIZE // 8)]

        ct = b''
        print(self.mode)
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.descrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.descrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE // 2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk

        m = ((m0 << (self.BLOCK_SIZE // 2)) + m1) & ((1 << self.BLOCK_SIZE) - 1)  # m = m0 || m1

        return l2b(m)

    def descrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE // 2)) - 1

        s = self.DELTA << 5
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA
        m = ((m0 << (self.BLOCK_SIZE // 2)) + m1) & ((1 << self.BLOCK_SIZE) - 1)

        return l2b(m)

def keys(key):
    h = 0x80000000
    h = long_to_bytes(h)

    k = [key[i:i + 4] for i in range(0, 16, 4)]
    K0 = k[0] + k[1] + k[2] + k[3]
    K1 = k[0] + k[1] + xor(k[2], h) + xor(k[3], h)
    K2 = xor(k[0], h) + xor(k[1], h) + k[2] + k[3]
    K3 = xor(k[0], h) + xor(k[1], h) + xor(k[2], h) + xor(k[3], h)
    return [K0, K1, K2, K3]   

r = remote("83.136.252.62", 44483)

ROUNDS = 10
IV = b'\r\xdd\xd2w<\xf4\xb9\x08'

r.recvuntil(b': ')
msg = r.recvuntil(b'\n').split(b'\n')[0].decode()

for round in range(ROUNDS):
    key = os.urandom(16)
    ct = Cipher(key=key, iv=IV).encrypt(bytes.fromhex(msg))
    r.sendlineafter(b'x) : ', bytes.hex(ct).encode())
    temp = keys(key)
    for k in temp: 
        r.sendlineafter(b'x) : ', bytes.hex(k).encode())
        
r.interactive()

```

Tài liệu tham khảo: https://www.tayloredge.com/reference/Mathematics/VRAndem.pdf

## FLAG
```
HTB{th1s_4tt4ck_m4k3s_T34_1n4ppr0pr14t3_f0r_h4sh1ng!}
```

# 9. Permuted (Hard)

## Attachments
- chall.py
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes

from hashlib import sha256
from random import shuffle

from secret import a, b, FLAG

class Permutation:
    def __init__(self, mapping):
        self.length = len(mapping)

        assert set(mapping) == set(range(self.length))     # ensure it contains all numbers from 0 to length-1, with no repetitions
        self.mapping = list(mapping)

    def __call__(self, *args, **kwargs):
        idx, *_ = args
        assert idx in range(self.length)
        return self.mapping[idx]

    def __mul__(self, other):
        ans = []

        for i in range(self.length):
            ans.append(self(other(i)))

        return Permutation(ans)

    def __pow__(self, power, modulo=None):
        ans = Permutation.identity(self.length)
        ctr = self

        while power > 0:
            if power % 2 == 1:
                ans *= ctr
            ctr *= ctr
            power //= 2

        return ans

    def __str__(self):
        return str(self.mapping)

    def identity(length):
        return Permutation(range(length))


x = list(range(50_000))
shuffle(x)

g = Permutation(x)
print('g =', g)

A = g**a
print('A =', A)
B = g**b
print('B =', B)

C = A**b
assert C.mapping == (B**a).mapping

sec = tuple(C.mapping)
sec = hash(sec)
sec = long_to_bytes(sec)

hash = sha256()
hash.update(sec)

key = hash.digest()[16:32]
iv = b"mg'g\xce\x08\xdbYN2\x89\xad\xedlY\xb9"

cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print('c =', encrypted)
```

- [output.txt](https://drive.usercontent.google.com/u/0/uc?id=1gaB-UsN6GQohcy32CwZxakS_LGM1XqRh&export=download)


## Solution

Sau một hồi thử thì ta rút ra một nhận xét rằng với mỗi vị trí trong Permution sẽ có 1 chu trình (Chu trình của từng vị trí có thể giống nhau hoặc khác)
Ta cũng nhận xét được rằng số chu trình nhiều nhất cũng chỉ là n chu trình
Và đến sau khi hoàn thành chu trình nó sẽ trở về trạng thái ban đầu
Vậy nếu chỉ cần biết độ dài chu trình của từng vị trí ta có thể sử dụng CRT để tìm ra được số bước cần thực hiện.

Về cơ bản nó sẽ trông như thế này:
```
    G = [xG0, xG1, xG2, ... , xGn]

--> A = [xA0, xA1, xA2, ..., xAn]

Thì ta cần tìm 1 số sao cho
    x % (độ dài chu trình của xG0) = xA0
    x % (độ dài chu trình của xG1) = xA1
    x % (độ dài chu trình của xG2) = xA2
    ...
    x % (độ dài chu trình của xGn) = xAn
```

Vì trong giải mình không biết sử dụng sage nên mình đã xài C++ để tìm chu trình (Quá s4d)

```cpp
#include <bits/stdc++.h>
using namespace std;

const long long MAXN = 1e5 + 10;
const long long MOD = 1e9 + 7;

long long n, g[MAXN], a[MAXN], root[MAXN], heso[MAXN], mod[MAXN], check = 0, cnt = 0;

int main() {
    ios_base::sync_with_stdio(0);
    cin.tie(0);
    cout.tie(0);

    freopen("solve.txt", "r", stdin);
    freopen("test.txt", "w", stdout);

    cin >> n;
    for (int i = 0; i < n; i++) {
        cin >> g[i];
        root[i] = g[i];
    }
    cin >> n;
    for (int i = 0; i < n; i++) {
        cin >> a[i];
    }

    while (check < 2 * n) {
        cnt++;
        for (int i = 0; i < n; i++) {
            g[i] = root[g[i]];
            if (g[i] == a[i] && heso[i] == 0) {
                heso[i] = cnt;
                check++;
            }
            if (g[i] == root[i] && mod[i] == 0) {
                mod[i] = cnt;
                check++;
            }
        }
    }

    for (int i = 0; i < n; i++) {
        cout << heso[i] << " " << mod[i] << endl;
    }

}
```

Sau khi tìm chu trình xong mình CRT nó và tìm FLAG thôi

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes

from hashlib import sha256
from random import shuffle
import output

class Permutation:
    def __init__(self, mapping):
        self.length = len(mapping)

        assert set(mapping) == set(range(self.length))     # ensure it contains all numbers from 0 to length-1, with no repetitions
        self.mapping = list(mapping)

    def __call__(self, *args, **kwargs):
        idx, *_ = args
        assert idx in range(self.length)
        return self.mapping[idx]

    def __mul__(self, other):
        ans = []

        for i in range(self.length):
            ans.append(self(other(i)))

        return Permutation(ans)

    def __pow__(self, power, modulo=None):
        ans = Permutation.identity(self.length)
        ctr = self

        while power > 0:
            if power % 2 == 1:
                ans *= ctr
            ctr *= ctr
            power //= 2

        return ans

    def __str__(self):
        return str(self.mapping)

    def identity(length):
        return Permutation(range(length))

g = Permutation(output.g)
# print('g =', g)

VALUECRT = []
MODCRT = []

with open("test.txt", "r") as f:
    for line in f:
        a, b = map(int, line.split())
        VALUECRT.append(a)
        MODCRT.append(b)

a = CRT_list(VALUECRT, MODCRT) + 1
A = Permutation(output.A)
B = Permutation(output.B)

C = B ** a

sec = tuple(C.mapping)
sec = hash(sec)
sec = long_to_bytes(sec)

hash = sha256()
hash.update(sec)

key = hash.digest()[16:32]
iv = b"mg'g\xce\x08\xdbYN2\x89\xad\xedlY\xb9"

cipher = AES.new(key, AES.MODE_CBC, iv)

print(cipher.decrypt(output.c).decode())
```

## FLAG
```
HTB{w3lL_n0T_aLl_gRoUpS_aRe_eQUaL_!!}
```

# 10. ROT 128 (Insane) (Sau giải)

## Attachments
- chall.py
```python
import random, os, signal
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from secret import FLAG

ROUNDS = 3
USED_STATES = []
_ROL_ = lambda x, i : ((x << i) | (x >> (N-i))) & (2**N - 1)
N = 128

def handler(signum, frame):
    print("\n\nToo slow, don't try to do sneaky things.")
    exit()

def validate_state(state):
    if not all(0 < s < 2**N-1 for s in user_state[-2:]) or not all(0 <= s < N for s in user_state[:4]):
        print('Please, make sure your input satisfies the upper and lower bounds.')
        return False
    
    if sorted(state[:4]) in USED_STATES:
        print('You cannot reuse the same state')
        return False
    
    if sum(user_state[:4]) < 2:
        print('We have to deal with some edge cases...')
        return False

    return True

class HashRoll:
    def __init__(self):
        self.reset_state()

    def hash_step(self, i):
        r1, r2 = self.state[2*i], self.state[2*i+1]
        return _ROL_(self.state[-2], r1) ^ _ROL_(self.state[-1], r2)

    def update_state(self, state=None):
        if not state:
            self.state = [0] * 6
            self.state[:4] = [random.randint(0, N) for _ in range(4)]
            self.state[-2:] = [random.randint(0, 2**N) for _ in range(2)]
        else:
            self.state = state
    
    def reset_state(self):
        self.update_state()

    def digest(self, buffer):
        buffer = int.from_bytes(buffer, byteorder='big')
        m1 = buffer >> N
        m2 = buffer & (2**N - 1)
        self.h = b''
        for i in range(2):
            self.h += int.to_bytes(self.hash_step(i) ^ (m1 if not i else m2), length=N//8, byteorder='big')
        return self.h


print('Can you test my hash function for second preimage resistance? You get to select the state and I get to choose the message ... Good luck!')

hashfunc = HashRoll()

for _ in range(ROUNDS):
    print(f'ROUND {_+1}/{ROUNDS}!')

    server_msg = os.urandom(32)
    hashfunc.reset_state()
    server_hash = hashfunc.digest(server_msg)
    print(f'You know H({server_msg.hex()}) = {server_hash.hex()}')

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(2)

    user_state = input('Send your hash function state (format: a,b,c,d,e,f) :: ').split(',')

    try:
        user_state = list(map(int, user_state))

        if not validate_state(user_state):
            print("The state is not valid! Try again.")
            exit()

        hashfunc.update_state(user_state)

        if hashfunc.digest(server_msg) == server_hash:
            print(f'Moving on to the next round!')
            USED_STATES.append(sorted(user_state[:4]))
        else:
            print('Not today.')
            exit()
    except:
        print("The hash function's state must be all integers.")
        exit()
    finally:
       signal.alarm(0)

print(f'Uhm... how did you do that? I thought I had cryptanalyzed it enough ... {FLAG}')
```

## Solution

Về bài này thì server sẽ random 32 bytes `msg` sau đó với các random state $(a, b, c, d, e, f)$
Nhiệm vụ của chúng ta là tìm các $(a, b, c, d, e, f)$ sao cho xảy ra hiện tượng hash collision với $0 \leqslant a, b, c, d < N$, $0 < e, f < 2^N - 1$ và tổng của $a, b, c, d > 2$ (Để tránh TH đặt biệt)

Ta thấy rằng có thể ta sẽ lấy lại được kết quả của hàm `hash_step` bằng cách sau:
```python
# Break the plaintext (pt) into 16 byte blocks
plt0 = pt >> N
plt1 = pt & (2**N - 1)

# Recover the hash_step results
H0 = plt0 ^ ht0
H1 = plt1 ^ ht1
```

Đến đây rồi thì ta có thể sử dụng `Z3` để bruteforce các state sao cho phù hợp =))))

```python
from z3 import *
from pwn import *
import re

def findHex(text):
    pattern = r'\b[a-fA-F0-9]{64}\b'
    hex_strings = re.findall(pattern, text)
    return hex_strings

N = 128
_ROL_ = lambda x, i: ((x << i) | (x >> (N - i))) & (2 ** N - 1)

HOST = "..."
PORT = "..."


while True:
    try:
        r = remote(HOST, PORT)
        # r = process(["python3", "server.py"])
        context.log_level = 'debug'
        cntTrue = 0

        for i in range(3):
            data = r.recvuntil(b"f) ::").decode()
            data = findHex(data)
            print(data)
            plt = int(data[0], 16)
            hashStr = data[1]

            plt0 = plt >> N
            plt1 = plt & (2 ** N - 1)

            H0 = int(hashStr[:32], 16) ^ plt0
            H1 = int(hashStr[32:], 16) ^ plt1

            solver = Solver()

            e, f = BitVecs('e f', N)
            a, b, c, d = BitVecs('a b c d', 7)
            a, b, c, d = ZeroExt(128 - 7, a), ZeroExt(128 - 7, b), ZeroExt(128 - 7, c), ZeroExt(128 - 7, d)

            solver.add(_ROL_(e, a) ^ _ROL_(f, b) == H0)
            solver.add(_ROL_(e, c) ^ _ROL_(f, d) == H1)

            if solver.check() == sat:
                res = solver.model()
                res = {d.name(): res[d] for d in res.decls()}
                payload = f"{res['a']},{res['b']},{res['c']},{res['d']},{res['e']},{res['f']}"
                r.sendline(payload.encode())
                cntTrue += 1
        
        if cntTrue == 3:
            r.interactive()
            exit(0)

    except:
        pass

```

Hãy cùng cầu mong code chạy được nào hihi

## FLAG
```
HTB{k33p_r0t4t1ng_4nd_r0t4t1ng_4nd_x0r1ng_4nd_r0t4t1ng!}
```