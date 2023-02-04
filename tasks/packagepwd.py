import execjs

package_pwd_script = open("tasks/packagepwd.js").read()
script = execjs.compile(package_pwd_script)


def package_pwd(password, random_num, key):
    pwd = script.call("encrypt", password, random_num, key)
    return pwd
