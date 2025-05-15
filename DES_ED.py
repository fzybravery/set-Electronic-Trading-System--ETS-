from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# DES加密
def des_encrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = pad(data.encode('utf-8'), DES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

# DES解密
def des_decrypt(key, encrypted_data):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
    return decrypted_data.decode('utf-8')

# 示例用法
if __name__ == '__main__':
    # 生成8字节的随机密钥
    key = get_random_bytes(8)

    # 转换为十六进制字符串形式
    key_hex = binascii.hexlify(key).decode()
    print("DES Key (hex):\n", key_hex)

    # 原始消息
    message = "你在说**啥"

    # 加密消息
    encrypted_message = des_encrypt(key, message)
    encrypted_message_hex = binascii.hexlify(encrypted_message).decode()  # 转换为十六进制字符串形式
    print("Encrypted message (hex):\n", encrypted_message_hex)

    # 解密消息
    decrypted_message = des_decrypt(key, encrypted_message)
    print("Decrypted message:\n", decrypted_message)
