# EXSync With WebUI

## 去中心化跨设备数据同步系统(EXSync)

### 简介：

1. 它可以**系统不同**、**远程无感**、**多台设备**进行同步数据（例如：**同步工作目录**、**同步消息列表**）。
2. 使用命令**远程控制**设备行为。
3. **加密**传输消息内容。
4. 去中心化，**拒绝**无条件信任第三者。
5. 远程**控制桌面**(实验性)。


目前贡献者： 

    Bt（Bt_Asker）

**状态：制作中未完成, 而且也没有test**

PS:
这只是一个练习网络编程顺带制作的小程序啦...~~希望会有人喜欢~~。 您可以自由开发（~~**但是Bt更希望您能带带它||ヽ(*￣▽￣*)ノミ|Ю**~~）
。而且想让它成为一个在同一网络下无感高性能地同步文件的工具。

* 客户端：
* 指令发送端口：`[随机可用端口]`
* 数据传输端口：`[随机可用端口]`


* 服务端：
* 数据传输端口：`[server_port]`
* 指令端口：`[server_port + 1]`
* 监听端口：`[server_port + 2]`

内部Socket传输指令规范：

客户端发送至服务端指令套接字：

    指令以 /_com: 开头，以 :_ 结尾，并且用 : 作为分隔符，又使用 | 作为值的分隔符。

    ——————————————————————————————————————————————————

    Data操作指令说明：
    data: 使用data套接字
    file/folder: 传输文件或文件夹
    get/post: 对方客户端接收或发送文件到服务端
    filepath: 文件(或文件夹)路径
    size: 文件(或文件夹)大小
    hash: 文件的xxhash128值
    mode：对文件(或文件夹)的操作模式

    文件与文件夹的传输指令:
        /_com:data:file:get:path|hash|size|filemark:_
        /_com:data:file:post:path|size|hash|mode|filemark:_

        /_com:data:file(folder):get:filepath|size|hash|mode|filemark:_
        /_com:data:file(folder):post:filepath|size|hash|mode|filemark:_
    ——————————————————————————————————————————————————
    EXSync通讯指令:

    会话id确认：
        /_com:comm:sync:post:session|True:_
        /_com:comm:sync:post:session|False:_

    获取密码:

        密码哈希值操作指令
        /_com:comm:sync:get:password_hash|local_hash:_
        /_com:comm:sync:post:password_hash|local_hash:_

        密码指令
        /_com:comm:sync:get:password|local_password:_
        /_com:comm:sync:post:password|local_password:_

    获取客户端信息:
        /_com:comm:sync:get:version:_
        /_com:comm:sync:post:version:_

    ——————————————————————————————————————————————————

服务端答复至客户端指令套接字：

    ——————————————————————————————————————————————————
    Data操作答复说明：
    data：使用data套接字
    reply：服务端答复
    True/False：服务端是否允许接下来的指令执行
    Value：服务端返回的数据

    /_com:data:reply:True:Value:_

    ——————————————————————————————————————————————————



_最后：有一部分是故意重造轮子，用于练习的_
