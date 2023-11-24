from PIL import Image, ImageOps, ImageEnhance

img = Image.open('./PointOverflow2023/APettyWageInRegret/DF2.jpg')

# converter = ImageEnhance.Color(img)
# img2 = converter.enhance(50)
filter = ImageEnhance.Brightness(img)
img2 = filter.enhance(200)
img2.show()
# ::P2/2::
# 17_f1257


#im2 = ImageOps.grayscale(img) 
 
