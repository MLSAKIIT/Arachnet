from wafw00f.main import WAFW00F
# import os
# print(os.getcwd())

class Waf_Detect:
    def __init__(self,url):
        self.url = url

    def waf_detect(self):
        wafw00f = WAFW00F(self.url)
        result = wafw00f.identwaf()
        # print("\n")
        # print(result)
        # if result:
        #     result = result[0].lower()
        # else:
        #     return None

        # if result:
        if result and len(result[0]) > 0:
            print("in result")
            result = result[0][0].lower()
            print("Result done")
        else:
            return None

        #print(result)
        # sometimes the file runs in the main arachnet folder so be careful to change the folder to xss
        wafs = self.fetch_names('waf_list.txt')
        for waf in wafs:
            if waf in result:
                print(waf)
                return waf
        return None

    @staticmethod
    def fetch_names(filename):
        with open(filename,'r') as waf_list:
            return waf_list.read().split()

if __name__ == "__main__":
    Waf_Detect('https://kiit.ac.in').waf_detect()
