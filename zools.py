import os
import sys
import shutil
import socket
import ctypes
import time
import zipfile
import hashlib
import subprocess
import platform
import winreg
import glob
import stat
from datetime import datetime

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_menu():
    clear_screen()
    print("Zools 工具箱 - 功能列表")
    print("="*40)
    print(" 1. 系统信息查看")
    print(" 2. 清理临时文件")
    print(" 3. 磁盘空间分析")
    print(" 4. 网络状态检测")
    print(" 5. 快速Ping测试")
    print(" 6. 端口扫描工具")
    print(" 7. 进程管理器")
    print(" 8. 文件加密/解密")
    print(" 9. WiFi密码查看")
    print("10. 系统激活状态")
    print("11. 关机/重启工具")
    print("12. 文件批量重命名")
    print("13. 校验文件哈希值")
    print("14. 系统代理设置")
    print("15. 计划任务管理")
    print("16. 环境变量管理")
    print("17. Hosts文件编辑")
    print("18. 系统日志查看")
    print("19. 注册表备份")
    print("20. 系统服务管理")
    print("21. 系统时间同步")
    print("22. 蓝屏记录检查")
    print("23. 系统组件检查")
    print("24. 系统更新历史")
    print("25. 系统引导修复")
    print("26. 文件权限检查")
    print("27. 系统声音控制")
    print("28. 系统字体管理")
    print("29. 系统驱动管理")
    print("30. 系统备份工具")
    print("0. 退出程序")
    print("="*40)

def get_choice():
    try:
        return int(input("请输入选项数字: "))
    except ValueError:
        return -1

# 功能实现部分
def system_info():
    print("\n系统信息：")
    print(f"操作系统: {platform.platform()}")
    print(f"处理器: {platform.processor()}")
    print(f"系统架构: {platform.architecture()[0]}")
    print(f"主机名称: {socket.gethostname()}")
    print(f"用户名: {os.getlogin()}")
    
    # 使用Windows API获取系统启动时间
    lib = ctypes.windll.kernel32
    tick = lib.GetTickCount64()
    boot_time = time.time() - (tick / 1000)
    print(f"系统启动时间: {datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S')}")
    
    input("\n按回车键返回主菜单...")

def format_size(size_bytes):
    """将字节转换为可读性更好的单位"""
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    while size_bytes >= 1024 and unit_index < len(units)-1:
        size_bytes /= 1024.0
        unit_index += 1
    return f"{size_bytes:.1f} {units[unit_index]}"

def clean_temp_files():
    total_size = 0
    cleaned_count = 0
    print("\n正在扫描并清理临时文件...")
    
    temp_paths = [
        os.environ.get('TEMP'),
        r'C:\Windows\Temp',
        os.path.join(os.environ['SYSTEMDRIVE'], 'Users', os.getlogin(), 'AppData', 'Local', 'Temp')
    ]
    
    for path in temp_paths:
        if path and os.path.exists(path):
            print(f"\n正在处理目录: {path}")
            for root, dirs, files in os.walk(path, topdown=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # 获取文件大小
                        file_size = os.path.getsize(file_path)
                        
                        # 尝试删除文件
                        os.remove(file_path)
                        
                        # 统计成功删除的文件
                        total_size += file_size
                        cleaned_count += 1
                        print(f"已清理: {file} ({format_size(file_size)})")
                        
                    except PermissionError:
                        try:
                            # 尝试解除只读属性后删除
                            os.chmod(file_path, stat.S_IWRITE)
                            os.remove(file_path)
                            total_size += os.path.getsize(file_path)
                            cleaned_count += 1
                        except Exception as e:
                            continue
                    except Exception as e:
                        continue

                # 尝试删除空目录
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    try:
                        os.rmdir(dir_path)
                    except Exception as e:
                        continue

    print(f"\n清理完成！共删除 {cleaned_count} 个文件")
    print(f"释放空间: {format_size(total_size)}")
    input("\n按回车键返回主菜单...")

def disk_usage():
    print("\n磁盘使用情况：")
    drives = [d for d in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if os.path.exists(f'{d}:\\')]
    for drive in drives:
        total, used, free = shutil.disk_usage(f'{drive}:\\')
        print(f"磁盘 {drive}: 总空间 {total//(2**30)}GB, 已用 {used//(2**30)}GB, 剩余 {free//(2**30)}GB")
    input("\n按回车键返回主菜单...")

def check_network():
    print("\n网络状态检测：")
    response = os.system("ping -n 1 8.8.8.8 > nul")
    if response == 0:
        print("互联网连接正常")
    else:
        print("无法连接互联网")
    input("\n按回车键返回主菜单...")

def quick_ping():
    host = input("请输入要ping的地址或域名: ")
    print(f"\n正在ping {host}...")
    os.system(f"ping {host}")

def port_scanner():
    target = input("请输入目标IP地址: ")
    ports = input("请输入要扫描的端口（用逗号分隔）: ").split(',')
    print(f"\n扫描 {target} 的端口...")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, int(port)))
        if result == 0:
            print(f"端口 {port} 开放")
        else:
            print(f"端口 {port} 关闭")
        sock.close()
    input("\n按回车键返回主菜单...")

def process_manager():
    print("\n正在运行的进程：")
    os.system("tasklist")
    choice = input("\n1. 结束进程 2. 返回主菜单: ")
    if choice == '1':
        pid = input("请输入要结束的进程PID: ")
        os.system(f"taskkill /F /PID {pid}")
    input("\n按回车键返回主菜单...")

def file_encrypt_decrypt():
    file_path = input("请输入文件路径: ")
    key = input("请输入加密密钥: ")
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted = bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data)])
    with open(file_path, 'wb') as f:
        f.write(encrypted)
    print("文件处理完成！")
    input("\n按回车键返回主菜单...")

def wifi_passwords():
    print("\n已保存的WiFi密码：")
    try:
        profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('gbk').split('\n')
        profiles = [line.split(':')[1].strip() for line in profiles if '所有用户配置文件' in line]
        
        for profile in profiles:
            try:
                results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode('gbk').split('\n')
                password = [line.split(':')[1].strip() for line in results if '关键内容' in line]
                print(f"网络名称: {profile:<20} 密码: {password[0] if password else '无'}")
            except:
                continue
    except Exception as e:
        print("需要管理员权限！")
    input("\n按回车键返回主菜单...")

def activation_status():
    print("\n系统激活状态：")
    os.system("slmgr /xpr")
    input("\n按回车键返回主菜单...")

def shutdown_tool():
    choice = input("\n1. 关机 2. 重启 3. 取消操作: ")
    if choice == '1':
        os.system("shutdown /s /t 0")
    elif choice == '2':
        os.system("shutdown /r /t 0")
    elif choice == '3':
        os.system("shutdown /a")

def batch_rename():
    print("\n文件批量重命名工具")
    try:
        # 获取并验证路径
        while True:
            path = input("请输入目录路径（例如C:\\Users\\test）: ").strip()
            if not os.path.isabs(path):
                path = os.path.abspath(path)
            
            if not os.path.exists(path):
                print("错误：路径不存在！")
                continue
                
            if not os.path.isdir(path):
                print("错误：输入的不是目录！")
                continue
                
            break

        # 获取匹配模式
        pattern = input("请输入文件名匹配模式（默认*.*）: ").strip()
        if not pattern:
            pattern = "*.*"

        # 获取新模板
        while True:
            new_name = input("请输入新文件名模板（必须包含{num}，例如file_{num}）: ").strip()
            if "{num}" not in new_name:
                print("错误：模板必须包含{num}占位符！")
                continue
            break

        files = glob.glob(os.path.join(path, pattern))
        files = [f for f in files if os.path.isfile(f)]  # 过滤掉目录
        
        print(f"找到 {len(files)} 个匹配文件")
        if not files:
            input("\n没有可重命名的文件，按回车返回...")
            return

        # 预览修改
        print("\n预览修改：")
        for i, file in enumerate(files[:5]):  # 显示前5个预览
            ext = os.path.splitext(file)[1]
            new_file = os.path.join(path, new_name.format(num=i+1) + ext)
            print(f"{os.path.basename(file)} -> {os.path.basename(new_file)}")
        if len(files) > 5:
            print(f"... 以及另外 {len(files)-5} 个文件")

        # 确认操作
        confirm = input("\n确认要执行重命名吗？(y/n): ").lower()
        if confirm != 'y':
            print("操作已取消")
            input("\n按回车键返回主菜单...")
            return

        # 执行重命名
        success = 0
        for i, file in enumerate(files):
            try:
                ext = os.path.splitext(file)[1]
                new_file = os.path.join(path, new_name.format(num=i+1) + ext)
                
                # 避免重复
                if os.path.exists(new_file):
                    base = new_name.format(num=i+1)
                    counter = 1
                    while os.path.exists(new_file):
                        new_file = os.path.join(path, f"{base}_{counter}{ext}")
                        counter += 1
                
                os.rename(file, new_file)
                success += 1
            except Exception as e:
                print(f"重命名失败：{os.path.basename(file)} -> {str(e)}")

        print(f"\n操作完成！成功重命名 {success}/{len(files)} 个文件")
        
    except Exception as e:
        print(f"发生错误：{str(e)}")
    
    input("\n按回车键返回主菜单...")

def file_hash():
    file_path = input("请输入文件路径: ")
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    print(f"SHA256哈希值: {h.hexdigest()}")
    input("\n按回车键返回主菜单...")

def proxy_settings():
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                        r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                        0, winreg.KEY_ALL_ACCESS)
    current = winreg.QueryValueEx(key, 'ProxyEnable')[0]
    print(f"\n当前代理状态: {'启用' if current else '禁用'}")
    action = input("1. 启用代理 2. 禁用代理: ")
    if action == '1':
        server = input("输入代理服务器（例如127.0.0.1:8080）: ")
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, server)
    else:
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
    winreg.CloseKey(key)
    print("设置已更新！")
    input("\n按回车键返回主菜单...")

def task_scheduler():
    print("\n计划任务列表：")
    os.system('schtasks /query /fo LIST /v')
    input("\n按回车键返回主菜单...")

def env_manager():
    print("\n当前环境变量：")
    for k, v in os.environ.items():
        print(f"{k}={v}")
    input("\n按回车键返回主菜单...")

def hosts_editor():
    hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    with open(hosts_path, 'r') as f:
        print("\n当前Hosts文件内容：")
        print(f.read())
    action = input("\n1. 添加条目 2. 删除条目 3. 返回: ")
    if action == '1':
        ip = input("输入IP地址: ")
        hostname = input("输入主机名: ")
        with open(hosts_path, 'a') as f:
            f.write(f"\n{ip}\t{hostname}")
    elif action == '2':
        line_num = int(input("输入要删除的行号: "))
        with open(hosts_path, 'r') as f:
            lines = f.readlines()
        with open(hosts_path, 'w') as f:
            for i, line in enumerate(lines):
                if i != line_num-1:
                    f.write(line)
    input("\n按回车键返回主菜单...")

def system_logs():
    print("\n系统日志（最近5条应用程序日志）：")
    log = subprocess.check_output(['powershell', 'Get-EventLog -LogName Application -Newest 5'])
    print(log.decode('gbk'))
    input("\n按回车键返回主菜单...")

def reg_backup():
    backup_path = input("输入备份文件保存路径: ")
    subprocess.call(f'reg export HKLM "{backup_path}\\HKLM.reg"', shell=True)
    subprocess.call(f'reg export HKCU "{backup_path}\\HKCU.reg"', shell=True)
    print("注册表备份完成！")
    input("\n按回车键返回主菜单...")

def service_manager():
    print("\n系统服务列表：")
    os.system('sc query state= all')
    action = input("\n1. 启动服务 2. 停止服务 3. 查询状态: ")
    service = input("输入服务名称: ")
    if action == '1':
        os.system(f'sc start {service}')
    elif action == '2':
        os.system(f'sc stop {service}')
    elif action == '3':
        os.system(f'sc query {service}')
    input("\n按回车键返回主菜单...")

def time_sync():
    print("\n正在检查时间服务状态...")
    try:
        # 检查Windows Time服务状态
        status = subprocess.check_output('sc query W32Time', shell=True).decode('gbk')
        if 'RUNNING' not in status:
            print("时间服务未运行，正在尝试启动服务...")
            os.system('net start W32Time')
            time.sleep(2)

        # 强制重新同步时间
        print("\n正在同步时间...")
        result = subprocess.run('w32tm /resync', shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("时间同步成功！")
        else:
            print("同步失败，尝试修复服务配置：")
            # 重新注册时间服务
            os.system('w32tm /unregister')
            os.system('w32tm /register')
            os.system('net start W32Time')
            # 设置默认时间服务器
            os.system('w32tm /config /update /manualpeerlist:"time.windows.com" /syncfromflags:manual /reliable:yes')
            # 再次尝试同步
            os.system('w32tm /resync')
            
    except Exception as e:
        print(f"操作失败：{str(e)}")
        if "Access is denied" in str(e):
            print("需要管理员权限！请右键以管理员身份运行本程序")
        else:
            print("""请尝试以下手动步骤：
1. 打开服务管理器（services.msc）
2. 找到并启动 "Windows Time" 服务
3. 设置启动类型为 "自动"
4. 检查防火墙是否放行NTP协议（UDP 123端口）""")
    
    input("\n按回车键返回主菜单...")

def bluescreen_check():
    print("\n蓝屏记录（最近5次）：")
    log = subprocess.check_output(['powershell', 'Get-WinEvent -FilterHashtable @{LogName="System"; ID=41} -MaxEvents 5'])
    print(log.decode('gbk'))
    input("\n按回车键返回主菜单...")

def component_check():
    print("\n检查系统组件...")
    os.system('DISM /Online /Cleanup-Image /CheckHealth')
    input("\n按回车键返回主菜单...")

def update_history():
    print("\n系统更新历史：")
    os.system('wmic qfe list brief /format:table')
    input("\n按回车键返回主菜单...")

def boot_repair():
    print("\n正在修复系统引导...")
    try:
        # 检查是否管理员权限
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("需要管理员权限！")
            return

        # 尝试使用bcdboot修复引导
        system_root = os.environ.get('SystemRoot', r'C:\Windows')
        os_drive = os.environ.get('SystemDrive', 'C:')

        commands = [
            f'bcdboot {system_root} /s {os_drive} /f UEFI',
            'bcdedit /deletevalue {default} safeboot',
            'bcdedit /set {default} bootstatuspolicy ignoreallfailures',
            'bcdedit /set {default} recoveryenabled no'
        ]

        for cmd in commands:
            print(f"执行命令: {cmd}")
            result = subprocess.run(
                cmd, 
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode != 0:
                print(f"命令执行失败: {result.stderr.strip()}")
            else:
                print("执行成功")

        print("\n引导修复操作已完成，建议重启系统确认效果")
        
    except FileNotFoundError:
        print("错误：未找到引导修复工具，请确认：")
        print("1. 当前系统为Windows 8及以上版本")
        print("2. 在管理员命令提示符中运行本程序")
    except Exception as e:
        print(f"发生未知错误: {str(e)}")
    
    input("\n按回车键返回主菜单...")

def file_permissions():
    path = input("输入文件或目录路径: ")
    os.system(f'icacls "{path}"')
    input("\n按回车键返回主菜单...")

def volume_control():
    def get_volume():
        try:
            cmd = "$vol = (Get-AudioDevice -PlaybackVolume).Volume; Write-Output $vol"
            result = subprocess.run(['powershell', '-Command', cmd], capture_output=True, text=True)
            return int(result.stdout.strip())
        except:
            return -1

def volume_control():
    def get_volume():
        try:
            cmd = "$vol = (Get-AudioDevice -PlaybackVolume).Volume; Write-Output $vol"
            result = subprocess.run(['powershell', '-Command', cmd], capture_output=True, text=True)
            return int(result.stdout.strip())
        except:
            return -1

    # 定义Windows API函数和常量
    winmm = ctypes.WinDLL('winmm.dll')
    WAVE_MAPPER = -1
    
    VOLUME_UP = 0xAF
    VOLUME_DOWN = 0xAE
    VOLUME_MUTE = 0xAD
    
    # 尝试通过SendInput模拟键盘事件
    KEYEVENTF_EXTENDEDKEY = 0x1
    KEYEVENTF_KEYUP = 0x0
    
    # 结构体定义
    class KeyboardInput(ctypes.Structure):
        _fields_ = [
            ("wVk", ctypes.c_ushort),
            ("wScan", ctypes.c_ushort),
            ("dwFlags", ctypes.c_ulong),
            ("time", ctypes.c_ulong),
            ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
        ]

    class Input(ctypes.Structure):
        _fields_ = [
            ("type", ctypes.c_ulong),
            ("ki", KeyboardInput),
            ("padding", ctypes.c_ubyte * 8)
        ]

def volume_control():
    def install_audio_module():
        try:
            check_module = subprocess.run(
                ['powershell', 'Get-Module -ListAvailable AudioDeviceCmdlets'],
                capture_output=True,
                text=True
            )
            if "AudioDeviceCmdlets" not in check_module.stdout:
                print("正在安装音频控制模块...")
                result = subprocess.run(
                    ['powershell', 'Install-Module -Name AudioDeviceCmdlets -Force -Scope CurrentUser'],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    print("模块安装失败，部分功能可能受限")
                    return False
            return True
        except Exception as e:
            print(f"模块检查失败: {str(e)}")
            return False

    def get_audio_info():
        try:
            cmd = "$device = Get-AudioDevice -Playback; " \
                  "$vol = $device.Volume; " \
                  "$mute = $device.Mute; " \
                  "Write-Output \"$vol,$mute\""
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True,
                text=True,
                check=True
            )
            vol, mute = result.stdout.strip().split(',')
            return int(vol), mute == 'True'
        except Exception as e:
            print("无法获取音频信息，请检查：")
            print("1. 是否以管理员权限运行")
            print("2. PowerShell执行策略是否允许（Set-ExecutionPolicy RemoteSigned）")
            return None, None

    def set_volume(level):
        try:
            subprocess.run(
                ['powershell', f'(Get-AudioDevice -Playback).Volume = {level}'],
                check=True
            )
        except Exception as e:
            print(f"音量设置失败: {str(e)}")

    def toggle_mute():
        try:
            subprocess.run(
                ['powershell', '$d = Get-AudioDevice -Playback; $d.Mute = (-not $d.Mute)'],
                check=True
            )
        except Exception as e:
            print(f"静音操作失败: {str(e)}")

    print("\n系统声音控制")
    print("="*40)
    
    if not install_audio_module():
        print("警告：基础功能可能不可用")
    
    current_vol, is_muted = get_audio_info()
    
    if current_vol is not None:
        status = "静音" if is_muted else "正常"
        print(f"当前状态: {status}")
        print(f"音量级别: {current_vol}%")
    else:
        print("无法获取当前音频状态")
    
    print("\n1. 增大音量 (+10%)")
    print("2. 减小音量 (-10%)")
    print("3. 切换静音")
    print("4. 设置精确音量")
    print("5. 返回主菜单")
    
    choice = input("\n请选择操作: ")
    
    try:
        if choice == '1':
            new_vol = min(100, current_vol + 10)
            set_volume(new_vol)
            print(f"音量已设置为 {new_vol}%")
        elif choice == '2':
            new_vol = max(0, current_vol - 10)
            set_volume(new_vol)
            print(f"音量已设置为 {new_vol}%")
        elif choice == '3':
            toggle_mute()
            print("静音状态已切换")
        elif choice == '4':
            new_vol = int(input("请输入音量值 (0-100): "))
            if 0 <= new_vol <= 100:
                set_volume(new_vol)
                print(f"音量已设置为 {new_vol}%")
            else:
                print("无效的输入值")
        elif choice == '5':
            return
    except Exception as e:
        print(f"操作失败: {str(e)}")
    
    input("\n按回车键返回主菜单...")

def font_manager():
    font_dir = os.path.join(os.environ['WINDIR'], 'Fonts')
    print(f"\n系统字体目录: {font_dir}")
    os.startfile(font_dir)
    input("\n按回车键返回主菜单...")

def driver_manager():
    print("\n已安装驱动列表：")
    os.system('driverquery /v')
    input("\n按回车键返回主菜单...")

def system_backup():
    try:
        backup_dir = input("输入备份目录（留空使用桌面）: ").strip()
        if not backup_dir:
            backup_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir, exist_ok=True)
            
        backup_path = os.path.join(backup_dir, 'system_backup.zip')
        
        print(f"\n正在备份系统配置到: {backup_path}")
        skipped_files = []
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            config_path = r'C:\Windows\System32\config'
            
            for root, dirs, files in os.walk(config_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # 尝试打开文件以验证可访问性
                        with open(file_path, 'rb') as test_file:
                            pass
                        zipf.write(file_path, 
                                 os.path.relpath(file_path, os.path.dirname(config_path)))
                    except PermissionError:
                        skipped_files.append(file_path)
                    except Exception as e:
                        print(f"无法备份 {file_path}: {str(e)}")
                        skipped_files.append(file_path)
        
        print(f"\n备份完成！已备份文件数量: {len(zipf.filelist)}")
        if skipped_files:
            print("\n以下文件因权限问题未能备份:")
            for f in skipped_files[:5]:  # 最多显示5个
                print(f" - {os.path.basename(f)}")
            if len(skipped_files) > 5:
                print(f"（共 {len(skipped_files)} 个文件未备份）")
                
    except Exception as e:
        print(f"备份过程中发生错误: {str(e)}")
        if "Access is denied" in str(e):
            print("请确保：1. 以管理员身份运行程序 2. 备份路径有效且可写")
    
    input("\n按回车键返回主菜单...")

def main():
    while True:
        show_menu()
        choice = get_choice()
        
        if choice == 0:
            print("感谢使用Zools工具箱，再见！")
            break
        elif choice == 1:
            system_info()
        elif choice == 2:
            clean_temp_files()
        elif choice == 3:
            disk_usage()
        elif choice == 4:
            check_network()
        elif choice == 5:
            quick_ping()
        elif choice == 6:
            port_scanner()
        elif choice == 7:
            process_manager()
        elif choice == 8:
            file_encrypt_decrypt()
        elif choice == 9:
            wifi_passwords()
        elif choice == 10:
            activation_status()
        elif choice == 11:
            shutdown_tool()
        elif choice == 12:
            batch_rename()
        elif choice == 13:
            file_hash()
        elif choice == 14:
            proxy_settings()
        elif choice == 15:
            task_scheduler()
        elif choice == 16:
            env_manager()
        elif choice == 17:
            hosts_editor()
        elif choice == 18:
            system_logs()
        elif choice == 19:
            reg_backup()
        elif choice == 20:
            service_manager()
        elif choice == 21:
            time_sync()
        elif choice == 22:
            bluescreen_check()
        elif choice == 23:
            component_check()
        elif choice == 24:
            update_history()
        elif choice == 25:
            boot_repair()
        elif choice == 26:
            file_permissions()
        elif choice == 27:
            volume_control()
        elif choice == 28:
            font_manager()
        elif choice == 29:
            driver_manager()
        elif choice == 30:
            system_backup()
        else:
            print("无效的输入，请重新选择！")
            time.sleep(1)

if __name__ == "__main__":
    if ctypes.windll.shell32.IsUserAnAdmin():
        main()
    else:
        print("请以管理员权限运行此程序！")
        time.sleep(3)