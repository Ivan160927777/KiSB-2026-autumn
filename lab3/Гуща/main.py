import string
SBOX = [
99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,
96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,
231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,
112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,
140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
]
INV_SBOX = [0] * 256
for i, value in enumerate(SBOX):
    INV_SBOX[value] = i

RCON = [0,1,2,4,8,16,32,64,128,27,54]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def xtime(x):
    x <<= 1
    if x & 256:
        x ^= 283
    return x & 255

def mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result

def expand_key(key):
    if len(key) != 16:
        raise ValueError("Ключ AES-128 должен иметь длину 16 байт.")
    words = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i-1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[x] for x in temp]
            temp[0] ^= RCON[i // 4]
        words.append([words[i-4][j] ^ temp[j] for j in range(4)])
    return [sum(words[4*r:4*r+4], []) for r in range(11)]

def add_round_key(state, round_key):
    return [state[i] ^ round_key[i] for i in range(16)]

def sub_bytes(state):
    return [SBOX[x] for x in state]

def inv_sub_bytes(state):
    return [INV_SBOX[x] for x in state]

def shift_rows(s):
    # Состояние хранится по столбцам: индекс = row + 4 * column.
    out = s[:]
    for r in range(4):
        row = [s[r + 4*c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            out[r + 4*c] = row[c]
    return out

def inv_shift_rows(s):
    out = s[:]
    for r in range(4):
        row = [s[r + 4*c] for c in range(4)]
        row = row[-r:] + row[:-r] if r else row
        for c in range(4):
            out[r + 4*c] = row[c]
    return out

def mix_columns(s):
    out = s[:]
    for c in range(4):
        i = 4*c
        a0,a1,a2,a3 = s[i:i+4]
        out[i]   = mul(a0,2) ^ mul(a1,3) ^ a2 ^ a3
        out[i+1] = a0 ^ mul(a1,2) ^ mul(a2,3) ^ a3
        out[i+2] = a0 ^ a1 ^ mul(a2,2) ^ mul(a3,3)
        out[i+3] = mul(a0,3) ^ a1 ^ a2 ^ mul(a3,2)
    return out

def inv_mix_columns(s):
    out = s[:]
    for c in range(4):
        i = 4*c
        a0,a1,a2,a3 = s[i:i+4]
        out[i]   = mul(a0,14) ^ mul(a1,11) ^ mul(a2,13) ^ mul(a3,9)
        out[i+1] = mul(a0,9) ^ mul(a1,14) ^ mul(a2,11) ^ mul(a3,13)
        out[i+2] = mul(a0,13) ^ mul(a1,9) ^ mul(a2,14) ^ mul(a3,11)
        out[i+3] = mul(a0,11) ^ mul(a1,13) ^ mul(a2,9) ^ mul(a3,14)
    return out

def encrypt(block, key):
    #Шифрует ровно один 16-байтовый блок AES-128.
    if len(block) != 16:
        raise ValueError("Блок должен иметь длину 16 байт.")
    keys = expand_key(key)
    state = add_round_key(list(block), keys[0])
    for r in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, keys[r])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, keys[10])
    return bytes(state)

def decrypt(block, key):
    #Расшифровывает ровно один 16-байтовый блок AES-128.
    if len(block) != 16:
        raise ValueError("Блок должен иметь длину 16 байт.")
    keys = expand_key(key)
    state = add_round_key(list(block), keys[10])
    for r in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, keys[r])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, keys[0])
    return bytes(state)

def padding(data):
    #PKCS#7: добавляет от 1 до 16 байтов.
    count = 16 - (len(data) % 16)
    return data + bytes([count] * count)

def unpadding(data):
    #Проверяет и удаляет PKCS#7.
    if not data or len(data) % 16 != 0:
        raise ValueError("Неверная длина данных для снятия padding.")
    count = data[-1]
    if count < 1 or count > 16 or data[-count:] != bytes([count] * count):
        raise ValueError("Неверный padding")
    return data[:-count]

def encrypt_ECB():
    filename = input("Имя исходного .txt файла: ").strip()
    key = read_key()
    with open(filename, "rb") as f:
        data = padding(f.read())
    result = b"".join(encrypt(data[i:i+16], key) for i in range(0, len(data), 16))
    out_name = filename + ".ecb"
    with open(out_name, "wb") as f:
        f.write(result)
    print("Зашифровано. Результат:", out_name)

def decrypt_ECB():
    filename = input("Имя зашифрованного файла (.ecb): ").strip()
    key = read_key()
    with open(filename, "rb") as f:
        data = f.read()
    if not data or len(data) % 16:
        raise ValueError("Размер ECB-файла должен быть кратен 16 байтам.")
    result = b"".join(decrypt(data[i:i+16], key) for i in range(0, len(data), 16))
    result = unpadding(result)
    out_name = filename + ".decrypted.txt"
    with open(out_name, "wb") as f:
        f.write(result)
    print("Расшифровано. Результат:", out_name)

def encrypt_CFB():
    filename = input("Имя исходного .txt файла: ").strip()
    key = read_key()
    iv = read_iv()
    with open(filename, "rb") as f:
        data = padding(f.read())
    result = bytearray()
    feedback = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        gamma = encrypt(feedback, key)
        cipher_block = xor_bytes(block, gamma)
        result.extend(cipher_block)
        feedback = cipher_block
    out_name = filename + ".cfb"
    with open(out_name, "wb") as f:
        f.write(iv + result)                 # IV сохраняется в начале файла
    print("Зашифровано. Результат:", out_name)

def decrypt_CFB():
    filename = input("Имя зашифрованного файла (.cfb): ").strip()
    key = read_key()
    with open(filename, "rb") as f:
        content = f.read()
    if len(content) < 32 or (len(content) - 16) % 16:
        raise ValueError("Неверный формат CFB-файла.")
    feedback = content[:16]                 # IV
    data = content[16:]
    result = bytearray()
    for i in range(0, len(data), 16):
        cipher_block = data[i:i+16]
        gamma = encrypt(feedback, key)
        plain_block = xor_bytes(cipher_block, gamma)
        result.extend(plain_block)
        feedback = cipher_block
    result = unpadding(bytes(result))
    out_name = filename + ".decrypted.txt"
    with open(out_name, "wb") as f:
        f.write(result)
    print("Расшифровано. Результат:", out_name)

def read_key():
    text = input("Введите ключ (ровно 16 символов, например abcdefgh12345678): ")
    try:
        key = text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("Для простоты используйте 16 ASCII-символов, например латинские буквы и цифры.")
    if len(key) != 16:
        raise ValueError("Ключ должен содержать ровно 16 однобайтовых символов.")
    return key

def read_iv():
    text = input("Введите IV (ровно 16 символов, например 12345678abcdefgh): ")
    try:
        iv = text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("Для простоты используйте 16 ASCII-символов, например латинские буквы и цифры.")
    if len(iv) != 16:
        raise ValueError("IV должен содержать ровно 16 однобайтовых символов.")
    return iv

def main():
    while True:
        print("\nAES-128: выберите режим")
        print("1 — Шифрование ECB")
        print("2 — Расшифрование ECB")
        print("3 — Шифрование CFB")
        print("4 — Расшифрование CFB")
        print("0 — Выход")
        choice = input("Ваш выбор: ").strip()
        try:
            if choice == "1":
                encrypt_ECB()
            elif choice == "2":
                decrypt_ECB()
            elif choice == "3":
                encrypt_CFB()
            elif choice == "4":
                decrypt_CFB()
            elif choice == "0":
                break
            else:
                print("Нет такого пункта меню.")
        except (OSError, ValueError) as error:
            print("Ошибка:", error)

if __name__ == "__main__":
    main()
