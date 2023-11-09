from core.api.gitcode import GitcodeAPI


class Updater(GitcodeAPI):
    """
    更新器
    """

    def __init__(self, url):
        super().__init__(url)


if __name__ == '__main__':
    pass
