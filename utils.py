from PIL import Image


def binarizing(img: Image, threshold):
    pixdata = img.load()
    w, h = img.size
    for y in range(h):
        for x in range(w):
            if pixdata[x, y] < threshold:
                pixdata[x, y] = 0
            else:
                pixdata[x, y] = 255
    return img


def depoint(img):  # input: gray image
    pixdata = img.load()
    w, h = img.size
    for y in range(1, h - 1):
        for x in range(1, w - 1):
            if y == 1:
                pixdata[x, 0] = 255
                pixdata[w - 1, 0] = 255
            count = 0
            if pixdata[x, y - 1] > 245:
                count = count + 1
            if pixdata[x, y + 1] > 245:
                count = count + 1
            if pixdata[x - 1, y] > 245:
                count = count + 1
            if pixdata[x + 1, y] > 245:
                count = count + 1
            if pixdata[x - 1, y - 1] > 245:
                count += 1
            if pixdata[x - 1, y + 1] > 245:
                count += 1
            if pixdata[x + 1, y - 1] > 245:
                count += 1
            if pixdata[x + 1, y + 1] > 245:
                count += 1
            if count > 4:
                pixdata[x, y] = 255
    return img
