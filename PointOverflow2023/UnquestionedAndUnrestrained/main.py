import base64

flag_enc = 'cG9jdGZ7dXdzcF80MTFfeTB1Ml84NDUzXzQyM184MzEwbjlfNzBfdTV9'

flag_decode = base64.b64decode(flag_enc)
print(flag_decode)