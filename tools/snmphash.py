# Generate by Chatgpt
import hashlib
import getpass


def password_to_key(auth_password, engine_id):
    """生成用于认证的密钥 (SHA-1)"""
    # 转换为ISO-8859-1编码
    auth_password = auth_password.encode("ISO-8859-1")

    # 重复密码直到它的长度是1048576个字节
    count = 1048576 // len(auth_password)
    extended_password = (
        auth_password * count + auth_password[: 1048576 % len(auth_password)]
    )

    # 计算SHA-1
    sha1 = hashlib.sha1()
    sha1.update(extended_password)
    key = sha1.digest()

    # 根据engine_id生成本地化密钥
    sha1 = hashlib.sha1()
    sha1.update(key + engine_id + key)
    localized_key = sha1.digest()

    return localized_key


def generate_keys(engine_id, auth_password, privacy_password):
    # 将engine_id转换为字节
    engine_id = bytes.fromhex(engine_id)

    # 生成认证密钥
    auth_key = password_to_key(auth_password, engine_id)

    # 生成隐私密钥（AES-256需要32字节）
    privacy_key = password_to_key(privacy_password, engine_id)[:32]

    return auth_key, privacy_key


if __name__ == "__main__":
    # 从命令行输入
    engine_id = input("请输入engine ID (十六进制): ")
    auth_password = getpass.getpass("请输入认证密码 (Auth Password): ")
    privacy_password = getpass.getpass("请输入隐私密码 (Privacy Password): ")

    auth_key, privacy_key = generate_keys(engine_id, auth_password, privacy_password)

    print("认证密钥 (SHA-1):", auth_key.hex())
    print("隐私密钥 (AES-256):", privacy_key.hex())
