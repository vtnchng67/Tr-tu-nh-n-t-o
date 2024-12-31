w: int = 64
w_8 = w//8
w_4 = w//4
rounds = 12

rc5_type = 1
t = 2 * (rounds + 1)
start_key = b'secret'
en_inp_file_name, en_out_file_name = 'E:/ATBMTT/RC5-Encryption-main/mahoa.txt',\
    'E:/ATBMTT/RC5-Encryption-main/giaima.txt'
de_inp_file_name, de_out_file_name = 'E:/ATBMTT/RC5-Encryption-main/giaima.txt',\
    'E:/ATBMTT/RC5-Encryption-main/mahoa.txt'


def func_for_lo(c: int) -> int:
    count_1 = str(c).count('1')
    return count_1


def odd(n: float) -> int:
    if int(n) % 2 == 0:
        return int(n) + 1
    return int(n)


def rot_l(x: int, y: int) -> int:
    v_1 = (x << y % w) & (2**w - 1)
    v_2 = (x & (2 ** w - 1)) >> (w - (y % w))
    return v_1 | v_2


def rot_r(x: int, y: int) -> int:
    v1 = (x & (2 ** w - 1)) >> y % w
    v2 = x << (w - (y % w)) & (2 ** w - 1)
    return v1 | v2


def key_alignment(len_key: int, key: bytes) -> (int, int, int()):
    if len_key == 0:
        c = 1
    elif len_key % w_8 != 0:
        key += b'\x00' * (w_8 - (len_key % w_8))
        len_key = len(key)
        c = len_key // w_8
    else:
        c = len_key // w_8
    lo = [0] * c
    for i in range(len_key - 1, -1, -1):
        lo[i // w_8] = (lo[i // w_8] << 8) + key[i]
    return c, len_key, lo


def mas_s() -> int():
    e = 2.718281828459045235360287471352662497757247093699959574966967627724
    f = 1.618033988749894848204586834365638117720309179805762862135448622705
    p, q = odd((e - 2) * 2**w), odd((f - 1) * 2**w)
    if w == 32:
        p, q = 0xB7E15163, 0x9E3779B9
    if w == 64:
        p, q = 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15
    s = [(p + i*q) % 2**w for i in range(t)]
    return s


def mixing(c: int, s: int(), lo: int()) -> (int(), int()):
    i, j, g, h = 0, 0, 0, 0
    for k in range(max(3*c, 3*t)):
        g = s[i] = rot_l(s[i] + g + h, 3)
        h = lo[j] = rot_l((lo[j] + g + h), (g + h))
        i = (i + 1) % t
        j = (j + 1) % c
    return s, lo


def encryption_rc5p(text: str or bytes, s: int()) -> bytes:
    a = int.from_bytes(text[:w_8], byteorder='little')
    b = int.from_bytes(text[w_8:], byteorder='little')
    a = (a + s[0]) % 2 ** w
    b = (b + s[1]) % 2 ** w
    for i in range(1, rounds + 1):
        a = (rot_l(a + b, b) + s[2 * i]) % 2 ** w
        b = (rot_l(a + b, a) + s[2 * i + 1]) % 2 ** w
    print('\n')
    try:
        return a.to_bytes(w_8, byteorder='little') + b.to_bytes(w_8, byteorder='little')
    except OverflowError:
        print("Lỗi mã hóa. Hãy thử thay đổi các tham số ban đầu")


def decryption_rc5p(text: str or bytes, s: int()) -> bytes:
    a = int.from_bytes(text[:w_8], byteorder='little')
    b = int.from_bytes(text[w_8:], byteorder='little')
    for i in range(rounds, 0, -1):
        b = rot_r((b % 2**w) - s[2 * i + 1], a) - a
        a = rot_r((a % 2**w) - s[2 * i], b) - b
    b = (b - s[1]) % 2**w
    a = (a - s[0]) % 2**w
    try:
        return a.to_bytes(w_8, byteorder='little') + b.to_bytes(w_8, byteorder='little')
    except OverflowError:
        print("Lỗi giải mã. Hãy thử thay đổi các tham số ban đầu")


def encryption_rc5ra(text: str or bytes, s: int()) -> bytes:
    a = int.from_bytes(text[:w_8], byteorder='little')
    b = int.from_bytes(text[w_8:], byteorder='little')
    a = (a + s[0]) % 2 ** w
    b = (b + s[1]) % 2 ** w
    for i in range(1, rounds + 1):
        a = (rot_l(a ^ b, func_for_lo(b)) + s[2 * i]) % 2 ** w
        b = (rot_l(a ^ b, func_for_lo(a)) + s[2 * i + 1]) % 2 ** w
    try:
        return a.to_bytes(w_8, byteorder='little') + b.to_bytes(w_8, byteorder='little')
    except OverflowError:
        print("Lỗi mã hóa. Hãy thử thay đổi các tham số ban đầu")


def decryption_rc5ra(text: str or bytes, s: int()) -> bytes:
    a = int.from_bytes(text[:w_8], byteorder='little')
    b = int.from_bytes(text[w_8:], byteorder='little')
    for i in range(rounds, 0, -1):
        b = rot_r((b % 2 ** w) - s[2 * i + 1], func_for_lo(a)) ^ a
        a = rot_r((a % 2 ** w) - s[2 * i], func_for_lo(b)) ^ b
    b = (b - s[1]) % 2 ** w
    a = (a - s[0]) % 2 ** w
    try:
        return a.to_bytes(w_8, byteorder='little') + b.to_bytes(w_8, byteorder='little')
    except OverflowError:
        print("Lỗi giải mã. Hãy thử thay đổi các tham số ban đầu")


def encryption_text(s: int()) -> None:
    with open(en_inp_file_name, 'rb+') as inp, open(en_out_file_name, 'wb+') as out:
        run = True
        while run:
            text = inp.read(w_4)
            if not text:
                break
            if len(text) != w_4:
                if len(text) < 8:
                    text += b'\x00' * (8 - len(text))
                run = False
            if rc5_type == 1:
                text = encryption_rc5p(text, s)
            if rc5_type == 2:
                text = encryption_rc5ra(text, s)
            out.write(text)


def decryption_text(s: int()) -> None:
    with open(de_inp_file_name, 'rb+') as inp, open(de_out_file_name, 'wb+') as out:
        run = True
        while run:
            text = inp.read(w_4)
            if not text:
                break
            if len(text) != w_4:
                run = False
            if rc5_type == 1:
                text = decryption_rc5p(text, s)
            if rc5_type == 2:
                text = decryption_rc5ra(text, s)
            if b'\x00' in text:
                text = text.rstrip(b'\x00')
            out.write(text)


def main() -> None:
    key = start_key
    len_key = len(key)
    c, len_key, lo = key_alignment(len_key, key)
    s = mas_s()
    s, lo = mixing(c, s, lo)
    encryption_text(s)
    decryption_text(s)


if __name__ == "__main__":
    main()