import requests
#x = requests.get('https://nvstgt.com/ManyKin/secret/flag.pdf')
#x = requests.get('https://nvstgt.com/Quantity/.secret/flag.txt')
x = requests.post('https://nvstgt.com/Quantity/.secret/flag.txt')
print(x.text)