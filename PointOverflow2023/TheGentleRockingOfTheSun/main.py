crack2 = '4bd939ed2e01ed1e8540ed137763d73cd8590323'
# SHA1 Has which we can decrpyt here:
# https://md5hashing.net/hash/sha1/4bd939ed2e01ed1e8540ed137763d73cd8590323
# The password is zwischen
password = 'zwischen'

import glob
for folder in glob.glob('PointOverflow2023/TheGentleRockingOfTheSun/2023/**/*', recursive=True):
    print(folder)
flag = 'poctf{uwsp_c411f02n14_d234m1n9}'


