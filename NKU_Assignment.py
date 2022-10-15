import os
import hashlib
import csv
import yara

names = []


def get_path(p, x):
    return os.path.join(p, x)


def get_rules(path):  # 获取并编译目录内的yara规则
    filepath = {}
    for index, file in enumerate(os.listdir(path)):
        rulepath = os.path.join(path, file)
        key = "rule" + str(index)
        filepath[key] = rulepath
    yararule = yara.compile(filepaths=filepath)
    return yararule


def scan(rule, name):
    try:
        fp = open(name, 'rb')
        matches = rule.match(data=fp.read())
        if len(matches) > 0:
            return (name, matches)  # 输出匹配到的文件路径和字符串
        else:
            return
    except (PermissionError, OSError):
        print("无法打开文件 " + name)



def get_sha256(name):
    with open(name, 'rb') as f:
        sha256obj = hashlib.sha256()
        sha256obj.update(f.read())
        hash_value = sha256obj.hexdigest()
        return hash_value


def get_md5(name):
    with open(name, 'rb') as f:
        md5obj = hashlib.md5()
        md5obj.update(f.read())
        hash_value = md5obj.hexdigest()
        return hash_value


def get_files(paths, filenames):
    try:
        file_list = os.listdir(paths)
        file_list = list(map(lambda x: get_path(paths, x), file_list))  # 找到所有文件的绝对路径
        f_names = list(filter(os.path.isfile, file_list))  # 找到当前目录下的文件
        names.extend(f_names)  # 存入names
        d_names = list(filter(os.path.isdir, file_list))  # 找出当前目录下文件夹名
        go = list(map(lambda x: get_files(get_path(paths, x), filenames), d_names))
    except (PermissionError, FileNotFoundError):
        print("无法打开文件夹 " + paths)


def main(names):
    path = 'C:\\'
    my_file = get_files(path, [])

    # names = list(filter(lambda x: x.endswith(".exe"), names))

    # print(names)
    # f = open('1.csv','w',encoding='utf-8e')
    # csv_writer = csv.writer(f)
    # csv_writer.writerow(["文件","md5","sha256"])
    # ex =list( map(lambda x:csv_writer.writerow([x,get_md5(x),get_sha256(x)]) ,names))
    # f.close()
    rulepath = "./rules"  # yara规则目录
    yararule = get_rules(rulepath)  # 得到编译后的规则
    ans = list(filter(lambda x: scan(yararule, x), names))  # 扫描names中的文件
    for item in ans:
        print(item)


if __name__ == '__main__':
    main(names)
