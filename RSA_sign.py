from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii
from Crypto.Cipher import PKCS1_OAEP

# 生成RSA密钥对
def generate_keypair():
    key = RSA.generate(1024)
    private_key = key.export_key(format='DER')  # 导出私钥为 DER 格式的字节串
    public_key = key.publickey().export_key(format='DER')  # 导出公钥为 DER 格式的字节串
    return private_key, public_key

# RSA签名
# 对消息先使用哈希函数，然后再签名
def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return signature

# 验证RSA签名
def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode('utf-8'))
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# RSA加密
def encrypt_message(public_key, message):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return encrypted_message

# RSA解密
def decrypt_message(private_key, encrypted_message):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

# 示例用法
if __name__ == '__main__':
    # 生成密钥对
    private_key, public_key = generate_keypair()
    
    # 转换为十六进制字符串形式
    private_key_hex = binascii.hexlify(private_key).decode()
    public_key_hex = binascii.hexlify(public_key).decode()

    print("Private key (hex):\n", private_key_hex)
    print("Public key (hex):\n", public_key_hex)

    # 原始消息
    message = "这是啥"

    # 签名
    signature = sign_message(private_key, message)
    signature_hex = binascii.hexlify(signature).decode()#转换为十六进制字符串形式
    print("Signature (hex):\n", signature_hex)

    # 验证签名
    if verify_signature(public_key, message, signature):
        print("Signature is valid.")
    else:
        print("Signature is invalid.")

    # 加密消息
    encrypted_message = encrypt_message(public_key, message)
    encrypted_message_hex = binascii.hexlify(encrypted_message).decode()  # 转换为十六进制字符串形式
    print("Encrypted message (hex):\n", encrypted_message_hex)

    # 解密消息
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print("Decrypted message:\n", decrypted_message)
