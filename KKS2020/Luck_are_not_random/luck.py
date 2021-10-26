from Crypto.Util.number import bytes_to_long, long_to_bytes
import base64

byte_array = []
with open("file", "rb") as f:
    byte = f.read(1)
    byte_array.append(byte)
    while byte != b"":
        # Do stuff with byte.
        byte = f.read(1)
        byte_array.append(byte)
print("Byte Array")
print(byte_array)

after_xc3 = []
for i,byte in enumerate(byte_array):
    if i+1 <= len(byte_array) and byte == b'\xc3':
        after_xc3.append((byte_array[i+1]))

print(after_xc3)

after_xc2 = []
for i,byte in enumerate(byte_array):
    if i+1 <= len(byte_array) and byte == b'\xc2':
        after_xc2.append((byte_array[i+1]))

print(after_xc2)

print("Byte Array as long")
nr_array = []
[nr_array.append(bytes_to_long(b)) for b in byte_array]
print(nr_array)

base = []
for i,n in enumerate(nr_array):
    if n==195:
        base.append(64-(nr_array[i+1]-128))
    if n == 194:
        base.append(nr_array[i + 1]-128)
print(base)

dicta = [['0', 'A'], ['1', 'B'], ['2', 'C'], ['3', 'D'], ['4', 'E'], ['5', 'F'], ['6', 'G'], ['7', 'H'], ['8', 'I'],
         ['9', 'J'], ['A', 'K'], ['B', 'L'], ['C', 'M'], ['D', 'N'], ['E', 'O'], ['F', 'P'], ['G', 'Q'], ['H', 'R'],
         ['I', 'S'], ['J', 'T'], ['K', 'U'], ['L', 'V'], ['M', 'W'], ['N', 'X'], ['O', 'Y'], ['P', 'Z'], ['Q', 'a'],
         ['R', 'b'], ['S', 'c'], ['T', 'd'], ['U', 'e'], ['V', 'f'], ['W', 'g'], ['X', 'h'], ['Y', 'i'], ['Z', 'j'],
         ['a', 'k'], ['b', 'l'], ['c', 'm'], ['d', 'n'], ['e', 'o'], ['f', 'p'], ['g', 'q'], ['h', 'r'], ['i', 's'],
         ['j', 't'], ['k', 'u'], ['l', 'v'], ['m', 'w'], ['n', 'x'], ['o', 'y'], ['p', 'z'], ['q', '0'], ['r', '1'],
         ['s', '2'], ['t', '3'], ['u', '4'], ['v', '5'], ['w', '6'], ['x', '7'], ['y', '8'], ['z', '9'], ['z', '+']
         ,['z', '/'], ['s', '=']]

print(''.join([dicta[b][1] for b in base]))
h = [hex(b) for b in base]
base64.b64decode(h)

byte_string = b''.join(byte_array)
print("Byte String")
print(byte_string)



"""
for i,nr in enumerate(set(nr_array)):
    if list(set(nr_array))[i+1]-nr > 1:
        print(nr)


print("Byte String Decoded")
long_array = nr_array
while not all(v == 0 for v in long_array):
    long_array = [max(0, l-1) for l in long_array]
    char_array = []
    for number in long_array:
        try:
            char_array.append(chr(number))
        except:
            continue
    if('kks' in char_array):
        print(''.join(char_array))
"""