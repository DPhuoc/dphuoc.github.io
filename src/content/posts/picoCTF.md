---
title: picoCTF - Cryptography
published: 2024-07-01
description: ''
image: ''
tags: ['FFT', 'Math']
category: 'CTF Writeups'
draft: false 
---
# Flag - printer

- [encoded.txt](https://artifacts.picoctf.net/c_titan/19/encoded.txt)
- [flag_printer.py](https://artifacts.picoctf.net/c_titan/19/flag_printer.py)

```python
import galois
import numpy as np
MOD = 7514777789

points = []

for line in open('encoded.txt', 'r').read().strip().split('\n'):
    x, y = line.split(' ')
    points.append((int(x), int(y)))

GF = galois.GF(MOD)

matrix = []
solution = []
for point in points:
    x, y = point
    solution.append(GF(y % MOD))

    row = []
    for i in range(len(points)):
        row.append(GF((x ** i) % MOD))
    
    matrix.append(GF(row))

open('output.bmp', 'wb').write(bytearray(np.linalg.solve(GF(matrix), GF(solution)).tolist()[:-1]))
```

## Solution

Ta thấy rằng file `encoded.txt` bao gồm tập hợp các điểm với $x$ nằm từ `0` --> `1769610` và giá trị y random.
Và code mẫu đề bài cho là thực hiện giải ma trận dưới đây, tuy nhiên nó chạy rất chậm và độ phức tạp là $O(n^3)$

$\begin{bmatrix}
a_0 \\
a_1 \\
a_2 \\
a_3 \\
\vdots \\
a_n \\
\end{bmatrix} \begin{bmatrix}
    0^0 & 0^1 & 0^2 & 0^3 & \dots  & 0^n \\
    1^0 & 1^1 & 1^2 & 1^3 & \dots  & 1^n \\
    2^0 & 2^1 & 2^2 & 2^3 & \dots  & 2^n \\
    3^0 & 3^1 & 3^2 & 3^3 & \dots  & 3^n \\
    \vdots & \vdots & \vdots & \vdots & \ddots  & \vdots \\
    n^0 & n^1 & n^2 & n^3 & \dots  & n^n \\
\end{bmatrix} = 
\begin{bmatrix}
y_0 \\
y_1 \\
y_2 \\
y_3 \\
\vdots \\
y_n \\
\end{bmatrix}$

Sau một lúc osint thì ta nhận thấy rằng đây là ma trận Vandermonde và nó liên quan đến Larange interpolation (nội suy larange).
Và ta có được công thức:

$f(x)=\sum_{i=1}^{n+1} f(x_i) * \prod_{j\neq i \ j = 1}^{n+1} \frac{x-x_j}{x_i-x_j}$

Cùng với đó ta cũng tìm thấy được một blog: https://codeforces.com/blog/entry/94143

Đầu tiên ta sẽ giảm độ phức tạp của việc tính $\prod_{j\neq i}(x_i-x_j)$

Thay vì với mỗi vòng lặp ta sẽ chạy lại để tính thì ta có thể làm như sau:

$\prod_{j\neq i}(x_i-x_j)$ = $\lim_{x\to x_i}\frac{\prod_{j=1}^{n+1} (x-x_j)}{x-x_i}$

Ở đây to có thể nhân hết vào và chia đi $x_i - x_i$. Điều tuyệt vời là ta có thể sử dụng lim để xử lý việc $x_i - x_i = 0$

$\lim_{x\to x_i}\frac{\prod_{j=1}^{n+1} (x-x_j)}{x-x_i}=\lim_{x\to x_i}\frac{d}{dx}(\prod_{i=1}^{n+1} x-x_j)$

Thế nên việc của ta là chỉ cần tìm $P'(x)$ với $P(x) = \prod_{i=1}^{n+1} x-x_j$ rồi thế từng $x_i$ vô.

Tiếp theo ta sẽ đến giảm độ phức tạp của việc nhân nhiều đa thức

Ta biết rằng nhân đa thức trong sage có $O(n \ log(n))$

Giả sử có m đa thức thì nếu nhân từ từ từng đa thức lại với nhau ta sẽ mất $O(m * n log(n))$

![image](https://hackmd.io/_uploads/BkANnVh1A.png)

Còn nếu ta sử dụng chia để trị để nhân đa thức thì ta sẽ mất $(nlog(n) * log(m))$

![image](https://hackmd.io/_uploads/Bk7Gp4hy0.png)

Giờ việc cuối cùng của ta là là thiết lập công thức

Đặt $v_i=\frac{y_i}{P'(x_i)}$

--> $f(x)=\sum_{i=1}^{n+1} v_i\prod_{j\neq i}(x-x_j)$

$f(x)=f_0(x)P_1(x)+f_1(x)P_0(x)$ với:

- $f_0(x)=\sum_{i=1}^{\lfloor\frac{n+1}{2}\rfloor} v_i\prod_{j\neq i,1\leq j\leq \lfloor\frac{n+1}{2}\rfloor}(x-x_j)$
- $f_1(x)=\sum_{i=\lfloor\frac{n+1}{2}+1\rfloor}^{n+1} v_i\prod_{j\neq i,\lfloor\frac{n+1}{2}\rfloor\leq j\leq n+1}(x-x_j)$
- $P_0(x)=\prod_{1\leq j\leq \lfloor\frac{n+1}{2}\rfloor}(x-x_j)$
- $P_1(x)=\prod_{\lfloor\frac{n+1}{2}\rfloor\leq j\leq n+1}(x-x_j)$

Code dưới đây đã mất tầm 6 - 7 tiếng để chạy và mình đã để chạy qua đêm để ra FLAG. (huhu)

```python
from tqdm import tqdm

MOD = 7514777789

points = []

for line in open('encoded.txt', 'r').read().strip().split('\n'):
    x, y = line.split(' ')
    points.append((int(x), int(y)))

F = GF(MOD)
R.<x> = F['x']

def multiply_poly_list(poly_list):
    if len(poly_list) == 1:
        return poly_list[0]
    n = len(poly_list) // 2
    return multiply_poly_list(poly_list[:n]) * multiply_poly_list(poly_list[n:])

P = multiply_poly_list([x - i for i in range(len(points))])
d_P = derivative(P)

def calc_poly(points, start_index, bar):
    bar.update(int(1))
    n = len(points)
    if n == 1:
        x_i = points[0][0]
        y_i = points[0][1]
        v = y_i / d_P(x_i)
        return v


    f0 = calc_poly(points[:n//2], start_index, bar)
    f1 = calc_poly(points[n//2:], start_index + n//2, bar)

    p0 = multiply_poly_list([x - (i + start_index) for i in range(n//2)])
    p1 = multiply_poly_list([x - (i + start_index) for i in range(n//2, n)])
    return f0 * p1 + f1 * p0

n = 2 * len(points) - 1
bar = tqdm(total=int(n))
poly = calc_poly(points, 0, bar)
coeffs = poly.numerator().list()

with open('out.txt', 'w') as f:
    f.write('\n'.join([str(i) for i in coeffs]))

print("Finished")
```

```python
listarr = [int(_) for _ in open("out.txt", "r").read().strip().split('\n')]

print(listarr)

open('output.bmp', 'wb').write(bytearray(listarr[:-1]))

```

![image](https://hackmd.io/_uploads/SyXKomhkA.png)
