# After analysing the text we can see that the encryption is a shift of i%5 for the letter at position i
# To validate that it returns the correct result, we can write a short encrypt function and compare the outcome with the expected outcome

# We can easily spot the pattern by checking the ordinals of the first two words (for the original and encrypted text):
# [ord(c) for c in 'Lorem ipsum']
# [76, 111, 114, 101, 109, 32, 105, 112, 115, 117, 109]

# [ord(c) for c in 'Lpthq jrvym']
# [76, 112, 116, 104, 113, 32, 106, 114, 118, 121, 109]

def encrypt(text):
    encrypted_text = ''
    for i, char in enumerate(text):
        encrypted_char = chr(ord(char) + i%5)
        encrypted_text = encrypted_text + encrypted_char
    return encrypted_text

def decrypt(text):
    decrypted_text = ''
    for i, char in enumerate(text):
        decrypted_char = chr(ord(char) - i%5)
        decrypted_text = decrypted_text + decrypted_char
    return decrypted_text

test_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " \
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure " \
            "dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat " \
            "non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

# Encrypted test text
# Lpthq jrvym!frpos"vmt!cpit-"fsntgfxeuwu$aeksmsdkqk fnlx,!uhh eq#iivupsd!vhqppt#mndkgmdvpw$uu"oebpth$eu"gslpth$mbiqe bnluub0
# #Yt!gqmm!cg$mjplq wgqman.#uuju#rotvuyd!g{irdkwetjqq$umndqcp"oebptlw okvm vv#eljsxmp!g{$eb"fsmnqgs dqqwerwdx.!Fxms!cxxe!kuyrf"
# gslpt#mn!thtrfjhrdftlx jp#zomwsxaug#zemkw$etuh$cjnoym!frposg#iu!hxkibv#rumnd$pbtletvt1$Eyehttfwu$sjpw$odedicbv#guqkgetbv#
# roo"svojfhrt-"vynu"lr dwota!sxm phimcjc#hetguynu"pslmkw$aokp$ie"hwt!ndfoswp2


enc_test_text = encrypt(test_text)
print(enc_test_text)

dec_test_text = decrypt(enc_test_text)
print(dec_test_text)

flag = "bagelarenotwholewheatsometimes"
dec_flag = encrypt(flag)
print(dec_flag)