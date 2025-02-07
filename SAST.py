import datetime
import os
from pathlib import Path
import time


def get_file_time(file_path):
    """
       函数功能：输出文件的基本信息，输入file_path，返回create_time_str, modify_time_str

       函数参数：
        file_path:文件路径

       返回值：
        create_time_str:文件创建时间
        modify_time_str:文件修改时间
        access_time_str:文件访问时间
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


def get_file_basic_information(file_path):
    """
       函数功能：输出文件的基本信息，输入filePath，返回file_basic_information

       函数参数：
        filePath:操作数

       返回值：
        file_basic_information:文件的基础信息
    """

    # 获取文件时间相关信息
    create_time_str, modify_time_str, access_time_str = get_file_time(file_path)

    # 获取文件大小（MB），精确到小数点后2位
    file_size = round(os.stat(file_path).st_size / (1024 * 1024), 2)

    print(create_time_str, modify_time_str, access_time_str,file_size)




if __name__ == "__main__":
    # 文件路径
    file_path = r"C:\Windows\System32\notepad.exe"

    # 获取文件的基础信息
    get_file_basic_information(file_path)
