class RC5C:

    def __init__(self, key, w=32, r=12):
        """
        key: bytes array
        w: word size
        r: rounds
        """
        self.key = key
        self.w = w
        self.r = r

        self.t = 2 * (r+1)
        self.c = self.w // 8
        self.b = len(key)
        self.mod = 2 ** self.w

        self.blockSize = w//8

        print("R-{}/{}/{}".format(self.w, self.b, self.r))
        print("Key:", key)

        self.initialL()
        self.initialS()
        self.mixKey()

    def ROL(self, val, r_bits):
        v1 = (val << r_bits % self.w) & (2 ** self.w - 1)
        v2 = ((val & (2 ** self.w - 1)) >> (self.w - (r_bits % self.w)))
        return v1 | v2

    def ROR(self, val, r_bits):
        v1 = ((val & (2 ** self.w - 1)) >> r_bits % self.w)
        v2 = (val << (self.w - (r_bits % self.w)) & (2 ** self.w - 1))
        return v1 | v2

    def magicConst(self):
        if self.w == 16:
            return (0xB7E1, 0x9E37)
        elif self.w == 32:
            return (0xB7E15163, 0x9E3779B9)
        elif self.w == 64:
            return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

    def initialL(self):
        if self.b % self.blockSize:
            self.key += b'\x00' * (self.blockSize - self.b % self.blockSize)
            self.b = len(self.key)
            self.c = self.b // self.blockSize
        else:
            self.c = self.b // self.blockSize
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):
            L[i // self.blockSize] = (L[i // self.blockSize]
                                      << 8) + self.key[i]
        self.L = L

    def initialS(self):
        P, Q = self.magicConst()
        self.S = [0]*self.t
        self.S[0] = P
        for i in range(1, self.t):
            self.S[i] = (self.S[i-1] + Q) % self.mod

    def mixKey(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.t)):
            A = self.S[i] = self.ROL((self.S[i] + A + B), 3)
            B = self.L[j] = self.ROL((self.L[j] + A + B), A + B)
            i = (i + 1) % self.t
            j = (j + 1) % self.c

    def encryptBlock(self, data):
        A = int.from_bytes(data[:self.blockSize], byteorder='little')
        B = int.from_bytes(data[self.blockSize:], byteorder='little')
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.r + 1):
            A = (self.ROL((A ^ B), B) + self.S[2 * i]) % self.mod
            B = (self.ROL((A ^ B), A) + self.S[2 * i + 1]) % self.mod
        return (A.to_bytes(self.blockSize, byteorder='little') + B.to_bytes(self.blockSize, byteorder='little'))

    def decryptBlock(self, data):
        A = int.from_bytes(data[:self.blockSize], byteorder='little')
        B = int.from_bytes(data[self.blockSize:], byteorder='little')
        for i in range(self.r, 0, -1):
            B = self.ROR(B - self.S[2 * i + 1], A) ^ A
            A = self.ROR(A - self.S[2 * i], B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return (A.to_bytes(self.blockSize, byteorder='little') + B.to_bytes(self.blockSize, byteorder='little'))

    def readInput(self, data):
        block = []
        while data:
            block.append(data[:self.blockSize*2])
            data = data[self.blockSize*2:]
        return block

    def encrypt(self, text):
        data = self.readInput(text)
        out = []
        for block in data:
            out.append(self.encryptBlock(block))
        return out

    def decrypt(self, text):
        data = self.readInput(text)
        out = []
        for block in data:
            out.append(self.decryptBlock(block))
        return out
