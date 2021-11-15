from Cryptodome.Util.number import bytes_to_long, long_to_bytes

def f(n):
    q=[True]*(n + 1)
    r=2
    while r**2<=n:
        if q[r]:
            for i in range(r**2,n+1,r):
                q[i] = False
        r += 1
    return [p for p in range(2,n+1) if q[p]]
class G:
    def __init__(self, f):
        self.f = f
        self.state = 1
    def move(self):
        q=1
        for p in self.f:
            if self.state%p!=0:
                self.state=self.state*p//q #quotient reminder
                return
            q*=p

    def set_state(self, state):
        self.state = state

q = f(pow(10,6))
gen = G(q)

enc = 31101348141812078335833805605789286074261282187811930228543150731391596197753398457711668323158766354340973336627910072170464704090430596544129356812212375629361633100544710283538309695623654512578122336072914796577236081667423970014267246553110800667267853616970529812738203125516169205531952973978205310

# Find the highest prime p such that for a given number n, n%p=0
def find_highest_prime(n):
    prime_index = 0
    last_prime = 0
    for i in range(len(q)):
        if n % q[i] == 0:
            prime_index = i
            last_prime = q[i]
    return prime_index, last_prime

flag = 0
while enc > 1:
    prime_index, last_prime = find_highest_prime(enc)
    flag += 2**prime_index
    enc = enc // last_prime
    print(enc)
find_highest_prime(enc)
print('dec =',flag)
dec_flag = long_to_bytes(flag)
print(dec_flag)