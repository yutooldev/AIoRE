import hashlib
import os
from pathlib import Path
import time
import json
import stat
import pefile
import yara


def get_file_time(file_path):
    """
       函数功能：输出文件的时间相关信息，输入file_path，返回create_time_str, modify_time_str, access_time_str, file_size

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


def get_file_permissions(file_path):
    """
       函数功能：输出文件的读、写、执行权限信息，输入file_path，返回read_permission, write_permission, execute_permission

       函数参数：
        file_path:文件路径

       返回值：
        file_read_permission:读权限
        file_write_permission:写权限
        file_execute_permission:执行权限
    """

    # 获取文件的状态信息
    file_stat = os.stat(file_path)

    # 使用stat模块来提取权限
    permissions = file_stat.st_mode

    # 判断读、写、执行权限
    file_read_permission = bool(permissions & stat.S_IRUSR)
    file_write_permission = bool(permissions & stat.S_IWUSR)
    file_execute_permission = bool(permissions & stat.S_IXUSR)

    return file_read_permission, file_write_permission, file_execute_permission


def get_file_signature_info(file_path):
    """
       函数功能：获取文件的签名信息，输入file_path，返回file_is_signed

       函数参数：
        file_path:文件路径

       返回值：
        file_is_signed:文件是否被签名
    """
    # 解析PE文件
    pe = pefile.PE(file_path)

    # 根据IMAGE_DIRECTORY_ENTRY_SECURITY的值判断文件是否被签名
    file_is_signed = False
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress != 0:
        file_is_signed = True

    return file_is_signed


def get_file_basic_information(file_path):
    """
       函数功能：输出文件的基本信息，输入file_path，返回file_basic_information

       函数参数：
        file_path:文件路径

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

    # 获取文件的读、写、执行权限
    file_read_permission, file_write_permission, file_execute_permission = get_file_permissions(file_path)

    # 获取文件的签名信息（因多个python库提取签名信息时有问题，暂时只判断文件是否签名，后续手动实现该功能）
    file_is_signed = get_file_signature_info(file_path)

    # 整合所有信息
    file_basic_information = {
        "file_name": file_name,
        "file_is_signed": file_is_signed,
        "file_read_permission": file_read_permission,
        "file_write_permission": file_write_permission,
        "file_execute_permission": file_execute_permission,
        "file_create_time": create_time_str,
        "file_modify_time": modify_time_str,
        "file_access_time": access_time_str,
        "file_size": str(file_size) + " MB",
        "md5_hash": md5_hash,
        "sha1_hash": sha1_hash,
        "sha256_hash": sha256_hash
    }

    return file_basic_information


def get_file_string(file_path):
    """
       函数功能：输出文件的基本信息，输入file_path，返回file_string_information

       函数参数：
        file_path:文件路径

       返回值：
        file_string_information:文件中的字符串总信息，包含字符串数量、对应偏移和内容
    """

    # 编译规则文件
    rules = yara.compile(filepath=r"get_file_string.yara")

    # 从文件中读取数据
    with open(file_path, 'rb') as f:
        file_data = f.read()
    # 匹配内存中的数据
    matches = rules.match(data=file_data)

    # 创建存储匹配到的字符串数量变量
    file_string_count = 0

    # 创建存储所有字符串信息的空列表
    file_all_string = []

    for match in matches:
        # print(f"规则名称: {match.rule}")  # 打印匹配到的规则名称
        for string in match.strings:
            file_string_count = len(string.instances)
            # print(string.instances)

            # 遍历所有字符串
            for data in string.instances:
                # 将遍历到的字符串的偏移和内容存储到列表中
                file_all_string.append(dict(string_offset=data.offset, string=str(data.matched_data[:-1])[2:-1]))
                # print(string.instances[0].offset)
                # print(string.instances[0].matched_data[:-1])

    # 匹配到的字符串总信息
    file_string_information = {
        "file_string_count": file_string_count,
        "file_all_string": file_all_string
    }

    return file_string_information


if __name__ == "__main__":
    # 文件路径
    file_path = r"D:\常规软件\7-Zip\7z.exe"

    # 获取文件的基础信息
    file_basic_information = get_file_basic_information(file_path)

    # 获取文件中的字符串信息
    file_string_information = get_file_string(file_path)

    print(json.dumps(file_basic_information, indent=4))
    print(file_string_information)
