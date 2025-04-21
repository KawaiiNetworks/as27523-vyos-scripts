import re
import subprocess
import urllib.request

script_start = r"""#!/bin/vbash

if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

source /opt/vyatta/etc/functions/script-template
"""

managed_fields = [
    "as-path-list",
    "prefix-list",
    "prefix-list6",
    "large-community-list",
    "route-map",
]


def download_default_config(url: str) -> str:
    """
    从远程下载 defaultconfig.sh 文件内容
    """
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


# url = "https://github.com/KawaiiNetworks/as27523-vyos-scripts/releases/download/nightly/defaultconfig.sh"
# default_config = download_default_config(url)
default_config = """
${default_config}
"""


def find_unused_definitions(config_text: str, entry_type: str):
    """
    在配置字符串中查找未被使用的定义名称。

    参数：
        config_text: 配置文件内容的字符串
        entry_type: 要查找的定义类型（如 "as-path-list", "prefix-list"）等

    返回：
        未被使用的名称列表（只出现一次）
    """
    # 匹配定义行，例如 "as-path-list AUTOGEN-AS-China {"
    pattern = r"\b" + re.escape(entry_type) + r"\s+([^\s{]+)\s*\{"
    define_pattern = re.compile(pattern)

    # 找到所有定义的名字
    defined_names = define_pattern.findall(config_text)

    # 统计每个名称在整个配置中出现的次数
    unused = []
    for defined_name in defined_names:
        count = len(re.findall(rf"\b{re.escape(defined_name)}\b", config_text))
        count_default = len(
            re.findall(rf"\b{re.escape(defined_name)}\b", default_config)
        )
        if count == 1 and count_default == 0:
            unused.append(defined_name)

    return unused


def generate_delete_commands(unused_names: list, entry_type: str):
    """
    生成删除未使用定义的命令。

    参数：
        unused_names: 未使用的名称列表
        entry_type: 要删除的定义类型（如 "as-path-list", "prefix-list"）等

    返回：
        删除命令的字符串列表
    """
    cmdprefix_map = {
        "as-path-list": "delete policy as-path-list",
        "prefix-list": "delete policy prefix-list",
        "prefix-list6": "delete policy prefix-list6",
        "large-community-list": "delete policy large-community-list",
        "route-map": "delete policy route-map",
    }
    cmd = ""
    for defined_name in unused_names:
        cmd += f"{cmdprefix_map[entry_type]} {defined_name}\n"
    return cmd


def generate_delete_commands_all(config_text: str):
    """
    生成删除所有未使用定义的命令。

    参数：
        config_text: 配置文件内容的字符串

    返回：
        删除命令的字符串列表
    """
    cmd_all = ""
    all_unused = {}
    for entry_type in managed_fields:
        unused_names = find_unused_definitions(config_text, entry_type)
        all_unused[entry_type] = unused_names
        delete_cmds = generate_delete_commands(unused_names, entry_type)
        cmd_all += delete_cmds

    return cmd_all, all_unused


def run_shell_script(script_str: str) -> str:
    """
    用 bash 执行一段 shell 脚本字符串，并返回输出结果（标准输出）。

    参数：
        script_str: 要执行的 shell 脚本内容（字符串）

    返回：
        输出字符串（标准输出）
    """
    result = subprocess.run(["bash", "-c", script_str], capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":

    show_config_shell_str = (
        script_start
        + """
configure
show
exit
"""
    )
    config_text = run_shell_script(show_config_shell_str)

    vyos_cmd, _ = generate_delete_commands_all(config_text)

    print(vyos_cmd)
