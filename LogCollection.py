import os
import re
import requests
import time
import logging
import configparser
import socket
from concurrent.futures import ThreadPoolExecutor

# 创建日志记录器
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
log_file = 'log_tool.log'
file_handler = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# 读取配置文件
config = configparser.ConfigParser()
config.read('config.ini')

# 获取配置参数
server = config.get('Settings', 'server')
api_url = config.get('Settings', 'api_url')
interval = int(config.get('Settings', 'interval'))

# 用于存储每个文件夹对应的included_logs的字典
folder_included_logs = {}

# 解析配置文件中的文件夹和对应的included_logs
for section in config.sections():
    if section.startswith('Logs'):
        folder = config.get(section, 'folder')
        included_logs = config.get(section, 'included_logs').split(',')
        folder_included_logs[folder] = included_logs

# 其他配置参数...
folders = list(folder_included_logs.keys())

# 用于存储已处理的文件的字典，其中键为文件路径，值为上次处理的位置
processed_files = {}

def load_processed_files():
    """从文件中加载已处理的文件记录"""
    if os.path.exists('processed_files.txt'):
        with open('processed_files.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                line = line.strip()
                if line:
                    file_path, last_processed_position = line.split('|')
                    processed_files[file_path] = int(last_processed_position)

def save_processed_files():
    """将已处理的文件记录保存到文件中"""
    with open('processed_files.txt', 'w') as file:
        for file_path, last_processed_position in processed_files.items():
            file.write(f"{file_path}|{last_processed_position}\n")

def process_log_file(file_path, included_logs):
    """处理日志文件"""
    try:
        # 检查文件的上次修改时间是否已经处理过
        last_modified = os.path.getmtime(file_path)
        if file_path in processed_files and last_modified <= processed_files[file_path]:
            return

        # 检查是否为需要记录的日志文件
        file_name = os.path.basename(file_path)
        if not any(log == '*' or log in file_name for log in included_logs):
            # 如果日志文件不在包含列表中，则不处理
            #logger.info(f'不处理日志文件 {file_path}，因为它不在包含列表中。')
            return

        # 获取上次处理后的位置
        last_processed_position = processed_files.get(file_path, 0)

        with open(file_path, 'r') as log_file:
            # 检查文件总行数是否发生变化
            log_file.seek(0, os.SEEK_END)
            current_file_size = log_file.tell()

            # 如果文件总行数减少，重置已处理位置为0
            if current_file_size < last_processed_position:
                logger.info('日志被人为清理过，重新统计')
                last_processed_position = 0

            # 将文件指针定位到上次处理的位置
            log_file.seek(last_processed_position)
            log_content = log_file.read()

            # 检查是否有新的日志内容
            if log_content:
                # 构造包含日志内容的字典
                log_data = {'from': server, 'file': file_path, 'content': log_content}

                # 发送日志数据到远程接口
                response = requests.post(api_url, json=log_data)
                result = response.json()
                if result['code'] == 0:
                    logger.info(f'已成功发送日志 {file_name} 到 API.')
                    # 更新文件的上次处理位置
                    processed_files[file_path] = log_file.tell()
                else:
                    logger.error(f'无法发送日志 {file_name} 到 API.')
            #else:
            #    logger.info(f'没有新的日志条目 {file_path}.')
    except Exception as e:
        logger.error(f'Error processing log file {file_name}: {str(e)}')

def process_logs_in_folders(folders):
    """处理文件夹中的日志文件"""
    with ThreadPoolExecutor() as executor:
        for folder in folders:
            included_logs = folder_included_logs[folder]

            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith('.log'):
                        file_path = os.path.join(root, file)

                        # 提交日志文件处理任务给线程池
                        executor.submit(process_log_file, file_path, included_logs)

def main():
    """主函数"""
    # 加载已处理的文件记录
    load_processed_files()

    while True:
        try:
            # 处理文件夹中的日志文件
            process_logs_in_folders(folders)
        except Exception as e:
            logger.error(f'主循环发生错误: {str(e)}')

        # 保存已处理的文件记录
        save_processed_files()

        # 等待指定时间间隔
        time.sleep(interval)

if __name__ == '__main__':
    main()
