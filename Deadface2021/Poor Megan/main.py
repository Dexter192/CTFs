import base64

# Name of the girl is Megan, so we use Megan-35 encoding

import base64
import sys

b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

megan35 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5"
encoded = "j2rXjx9dkhW9eLKsnMR9cLDVjh/9dwz1QfGXm+b9=wKslL1Zpb45"


class B64weird_encodings:
    def __init__(self, translation):
        self.revlsrch = dict(zip(translation, b))

    def decode(self, code):
        global revlsrch
        b64 = "".join([self.revlsrch[x] for x in code])
        r = base64.b64decode(b64)
        return r

def decode(variant, code):
    try:
        encoder = B64weird_encodings(variant)
        return encoder.decode(code)
    except KeyError:
        return "Not valid"
    except TypeError:
        return "Padding iccorrect"

print('megan35: ', decode(megan35, encoded))
