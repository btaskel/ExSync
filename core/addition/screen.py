import time

import mss.tools


class Screen:
    def __init__(self):
        self.mode = None
        self.cache = None

    def screenshot(self):
        """
        获取当前屏幕图片比特数据，如果画面静止则不返回比特数据
        """
        with mss.mss() as sct:
            # 获取屏幕截图
            sct_img = sct.grab(sct.monitors[1])
            # 将截图保存到比特数据
            png_bytes = mss.tools.to_png(sct_img.rgb, sct_img.size)
            if self.cache == png_bytes:
                return None
            else:
                self.cache = png_bytes
            return png_bytes


s = Screen()
while True:
    # 0.03 30fps
    # 0.017 60fps
    time.sleep(0.017)
    s.screenshot()
