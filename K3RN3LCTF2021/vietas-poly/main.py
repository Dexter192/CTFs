from pwn import *
import numpy as np

context.log_level = 'debug' #will print all input and output for debugging purposes
conn = remote("ctf.k3rn3l4rmy.com", 2236) #enter the address and the port here as strings. For example nc 0.0.0.0 5000 turns into remote('0.0.0.0', 5000)

def get_input(): #function to get one line from the netcat
    input = conn.recvline().strip().decode()
    return input

def parse(poly):
    #polynomial = polynomial.replace(' ', '')
    poly = poly.split()
    if len(poly)%2 == 1:
        poly = ['+'] + poly
    print(poly)
    coeffs = []
    for i in range(0,len(poly),2):
        sign = poly[i]
        term = poly[i+1]
        a, exp = term.split('x^')
        a = 1 if a == '' else int(a)
        if sign == '-':
            a = -a
        coeffs += [a]
    return coeffs
    #print(coeffs)
    '''
    TODO: Parse polynomial
    For example, parse("x^3 + 2x^2 - x + 1") should return [1,2,-1,1]
    '''

for _ in range(4):
    get_input() #ignore challenge flavortext

for i in range(100):
    type = get_input()
    coeffs = parse(get_input())
    print(coeffs)
    ans = -1
    if 'sum of the roots' in type:
        roots = np.roots(coeffs)
        ans = sum(roots)
    elif 'sum of the reciprocals of the roots' in type:
        roots = np.roots(coeffs)
        rep = np.reciprocal(roots)
        ans = sum(rep)
    elif 'sum of the squares of the roots' in type:
        roots = np.roots(coeffs)
        squares = np.square(roots)
        ans = sum(squares)
    print(ans)
    ans = np.real(ans)
    ans = np.round(ans)
    ans = int(ans)
    print("ans",ans)
    conn.sendline(str(ans)) #send answer to server
    get_input()
conn.interactive() #should print flag if you got everything right

# flag{Viet4s_f0r_th3_win}