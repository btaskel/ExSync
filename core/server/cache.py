import json
import logging
import threading
import time


class IndexReadCache:
    def __init__(self, config: dict):
        self.indexDict = {}
        self.config = config
        self._close = False
        threading.Thread(target=self._release, daemon=True).start()

    def _release(self):
        """
        indexDict = {
            'A-index-path': [index-object, index-json, time-stamp]
            ...
        }
        :return:
        """
        while True:
            time.sleep(5)

            if self._close:
                return

            for indexPath, indexStatus in self.indexDict.items():
                if time.time() - indexStatus[-1] > 10:
                    indexStatus[0].close()
                    del self.indexDict[indexPath]

    def getIndex(self, path: str) -> dict:
        """
        获取一个索引文件, 并返回它的json对象;
        如果存在实例: 更新实例时间戳
        如果不存在实例: 创建实例附上时间戳
        :param path: 索引文件路径
        :return: 文件json实例
        """
        if path in self.indexDict:
            self.indexDict[path][-1] = time.time()
            return self.indexDict[path][1]

        index_file = open(path, mode='r', encoding='utf-8')
        try:
            index_json = json.load(index_file)
        except json.JSONDecodeError as e:
            logging.error(
                f'JSON parsing error at position {e.doc}, the incorrect content is {e.doc[e.pos:e.pos + 10]}')
            index_file.close()
            return {}
        except Exception as e:
            index_file.close()
            logging.error(f'JSON parsing error: {e}')
            return {}

        self.indexDict[path] = [index_file, index_json, time.time()]
        return self.indexDict[path][1]

    def closeIndex(self):
        """
        关闭索引管理
        :return:
        """
        self._close = True
        for indexPath, indexStatus in self.indexDict.items():
            indexStatus[0].close()
        del self.indexDict


if __name__ == '__main__':
    # print(time.time())
    # ls= [1,2,30]
    # print(ls[-1])
    pass
