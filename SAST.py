import hashlib
import os
from pathlib import Path
import time


def get_file_time(file_path):
    """
       函数功能：输出文件的时间相关信息，输入file_path，返回create_time_str, modify_time_str

       函数参数：
        file_path:文件路径

       返回值：
        create_time_str:文件创建时间
        modify_time_str:文件修改时间
        access_time_str:文件访问时间
        file_size:文件大小
    """

    # 文件路径
    p = Path(file_path)

    # 获取文件的创建时间和修改时间
    create_time = p.stat().st_ctime
    modify_time = p.stat().st_mtime
    access_time = p.stat().st_atime

    # 转换为本地时间格式
    create_time_local = time.localtime(create_time)
    modify_time_local = time.localtime(modify_time)
    access_time_local = time.localtime(access_time)

    # 格式化时间输出
    create_time_str = time.strftime('%Y-%m-%d %H:%M:%S', create_time_local)
    modify_time_str = time.strftime('%Y-%m-%d %H:%M:%S', modify_time_local)
    access_time_str = time.strftime('%Y-%m-%d %H:%M:%S', access_time_local)

    # 返回文件的创建时间、修改时间、访问时间
    return create_time_str, modify_time_str, access_time_str

def get_file_hash(file_path):
    """
       函数功能：输出文件的散列值，输入file_path，返回md5_hash, sha1_hash, sha256_hash

       函数参数：
        file_path:文件路径

       返回值：
        md5_hash:文件md5散列值
        sha1_hash:文件sha1散列值
        sha256_hash:文件sha256散列值
    """
    # 计算md5散列值
    md5_hash_func = hashlib.new('md5')
    with open(file_path, 'rb') as f:
        # 读取文件并计算哈希
        while chunk := f.read(8192):
            md5_hash_func.update(chunk)
    md5_hash = md5_hash_func.hexdigest()

    # 计算SHA1散列值
    sha1_hash_func = hashlib.new('sha1')
    with open(file_path, 'rb') as f:
        # 读取文件并计算哈希
        while chunk := f.read(8192):
            sha1_hash_func.update(chunk)
    sha1_hash = sha1_hash_func.hexdigest()

    # 计算SHA256散列值
    sha256_hash_func = hashlib.new('sha256')
    with open(file_path, 'rb') as f:
        # 读取文件并计算哈希
        while chunk := f.read(8192):
            sha256_hash_func.update(chunk)
    sha256_hash = sha256_hash_func.hexdigest()

    # 返回十六进制的哈希值
    return md5_hash, sha1_hash, sha256_hash



def get_file_basic_information(file_path):
    """
       函数功能：输出文件的基本信息，输入filePath，返回file_basic_information

       函数参数：
        filePath:操作数

       返回值：
        file_basic_information:文件的基础信息
    """

    # 获取文件名
    file_name = os.path.basename(file_path)

    # 获取文件时间相关信息
    create_time_str, modify_time_str, access_time_str = get_file_time(file_path)

    # 获取文件大小（MB），精确到小数点后2位
    file_size = round(os.stat(file_path).st_size / (1024 * 1024), 2)

    # 获取文件的散列值
    md5_hash, sha1_hash, sha256_hash = get_file_hash(file_path)

    # 整合所有信息
    file_basic_information = {
        "file_name":file_name,
        "file_create_time": create_time_str,
        "file_modify_time": modify_time_str,
        "file_access_time": access_time_str,
        "file_size": str(file_size)+" MB",
        "md5_hash": md5_hash,
        "sha1_hash": sha1_hash,
        "sha256_hash": sha256_hash
    }

    return file_basic_information


if __name__ == "__main__":
    # 文件路径
    file_path = r"C:\Windows\System32\notepad.exe"

    # 获取文件的基础信息
    file_basic_information = get_file_basic_information(file_path)

    print(file_basic_information)
