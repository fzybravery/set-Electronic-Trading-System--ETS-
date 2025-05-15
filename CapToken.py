import hmac
import hashlib
import time
import binascii
from os import urandom as get_random_bytes

def generate_cap_token(secret_key, validity_period=300):
    """
    生成 CapTok.
    
    :param secret_key: 用于生成 HMAC 的密钥
    :param validity_period: 令牌有效期（秒），默认 300 秒（5 分钟）
    :return: 生成的 CapTok 和生成时间戳
    """
    timestamp = int(time.time())
    message = f"{timestamp}:{validity_period}"
    cap_token = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256).hexdigest()
    CapTok = cap_token + "##" + hex(timestamp)[2:]
    return CapTok

def verify_cap_token(secret_key,CapTok, validity_period=300):
    """
    验证 CapTok.
    
    :param secret_key: 用于生成 HMAC 的密钥
    :param cap_token: 待验证的 CapTok
    :param timestamp: 令牌生成时间戳
    :param validity_period: 令牌有效期（秒），默认 300 秒（5 分钟）
    :return: 令牌是否有效（布尔值）
    """
    cap_token, timestamp = CapTok.split("##")
    timestamp = int(timestamp, 16)
    current_time = int(time.time())
    # 检查令牌是否过期
    if current_time - timestamp > validity_period:
        return False
    
    # 生成新令牌并比较
    message = f"{timestamp}:{validity_period}"
    expected_token = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_token, cap_token)

# 示例使用
if __name__ == "__main__":
    secret_key = binascii.hexlify(get_random_bytes(8)).decode()
    
    # 生成 CapTok
    CapTok = generate_cap_token(secret_key)
    print(f"Generated CapTok: {CapTok}")
    
    # 验证 CapTok
    is_valid = verify_cap_token(secret_key, CapTok)
    print(f"Is CapTok valid? {is_valid}")
