"""
Simple script used to create a bmp by writing bytes directly in a file with possibility of drawing a circle or an ellipse using basic math.
"""


import struct
import sys


def draw_to_bmp(width, height, name="result.bmp", bits_per_pixel=32, draw='circle'):
    if bits_per_pixel % 8 != 0:
        print("Invalid bits per pixel. Should be a multiple of 8.")
        return

    if not name.endswith(".bmp") or not name.replace(".bmp", "").isalpha():
        print("Invalid bmp file name.")
        return

    if draw not in ["circle", "ellipse"]:
        print("Invalid shape to draw.")
        return

    if width != height:
        print("Width and height should have the same value!")

    if width > 1080 or height > 1080:
        print("Width or height cannot be greater than 1080.")
        return

    if width < 0 or height < 0:
        print("Width or height cannot be negative!")
        return

    with open(name, "wb") as g:
        g.write(b"\x42\x4d")  # signature - BM
        g.write(struct.pack('<L', 54+width*height*(bits_per_pixel//8))) # file size = 14 (signature, file size, reserved, offset) + 40 (info header) + number of octets used for drawing the image
        g.write(b"\x00\x00\x00\x00")  # reserved, = 0
        g.write(b"\x36\x00\x00\x00")  # offset of actual bitmap data (36h = 54)

        # info header
        g.write(b"\x28\x00\x00\x00")  # header size, 40 decimal, 28h
        g.write(struct.pack('<L', width))  # width
        g.write(struct.pack('<L', height))  # height
        g.write(b"\x01\x00")  # vertical number of planes, 1
        g.write(struct.pack("<H", bits_per_pixel))  # bits per pixel, 32
        g.write(b"\x00\x00\x00\x00")  # compression, 0
        g.write(b"\x00\x00\x00\x00")  # compressed size of image, 0 because compression = 0
        g.write(b"\x00\x00\x00\x00")  # X pixels per meter
        g.write(b"\x00\x00\x00\x00")  # Y pixels per meter
        g.write(b"\x00\x00\x00\x00")  # colors used
        g.write(b"\x00\x00\x00\x00")  # important colors, 0 = all

        if draw == 'circle':
            for i in range(width):
                for j in range(height):
                    if pow(i-width//2, 2) + pow(j-height//2, 2) < pow(width//2 + 1, 2):
                        g.write(b"\x00\x00\x00\x00")
                    else:
                        g.write(b"\xff\xff\xff\xff")
        elif draw == 'ellipse':
            for i in range(width):
                for j in range(height):
                    if pow(i-width//2, 2) / pow(width//4, 2) + pow(j-height//2, 2) / pow(width//2, 2) < 1:
                        g.write(b"\x00\x00\x00\x00")
                    else:
                        g.write(b"\xff\xff\xff\xff")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(
            "Invalid number of arguments. Use 'python create_bmp_with_shape {width} {height} {file_name} [circle|ellipse]")
    else:
        try:
            draw_to_bmp(int(sys.argv[1]), int(sys.argv[2]), name=sys.argv[3], draw=sys.argv[4])
        except ValueError:
            print("Invalid values entered. Please use integers for the width and height.")
