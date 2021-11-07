# One of the 60-character strings in the provided file has been encrypted by single-character XOR. The challenge is to find it, as that is the flag.
# Hint: Always operate on raw bytes, never on encoded strings. Flag must be submitted as UTF8 string.

# We have a file with 100 encoded hex-strings. Each of those strings was encoded through an XOR with a single character
# E.g. 'a' = 97; ';' = 59 -> 'a' ^ ';' = 'z'.
# We need to find the char that was used to encode the string

# Read flag file lines
with open('flags.txt') as f:
    lines = f.readlines()

# After briefly investigating the flag.txt file, we can see that the strings are in hex format
# We want to convert this hex string to an array of integers such that we can invert the XOR
# E.g. string(045c3f704f35) = hex(04 5c 3f 70 4f 35) = dez(4 92 63 112 79 53)
lines_int = []
for line in lines:
    # Remove \n ending of the line
    line = line[:-1]
    # Convert to array of hex pairs (from length 120 to 60)
    hex_line = [line[i:i + 2] for i in range(0, len(line), 2)]
    # Convert to integers such that we can apply the XOR
    int_line = [int(byte, 16) for byte in hex_line]
    lines_int.append(int_line)
# Now we have a list of integer arrays for the encodings

# Since we have single character encodings, we want to decode the line for all chars within [1,256]
for i in range(1,256):
    for line in lines_int:
        # The inverse of XOR is XOR and thus we can simply apply the XOR of the current char for every element of our line
        decoded = [chr(e^i) for e in line]
        # Convert the char array to a string
        decoded = ''.join(decoded)
        # Since we know that the flag starts with 'dam', we can ignore all other outputs.
        if 'dam' in decoded:
            print(decoded)
# Flag is dam{antman_EXPANDS_inside_tHaNoS_never_sinGLE_cHaR_xOr_yeet}