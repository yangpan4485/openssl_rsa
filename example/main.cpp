#include <iostream>

#include "openssl_utils.h"

int main(void) {
    // 长度272
    std::string public_key =
        "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw/YJVyXIVh7Vh0DAFqASWB8x/\n\
XXrzF2yuto3iZkkqBFasojN9R94FFHhT7AFHWwvXGFdXsUPLxq3R6GXoqdynqAX6\n\
UxROZD/CWBXRSIQL6c9S4+qsDH8MnXYYQmZZRSsDt5zpzukSU0nEr9+qq+GMBPAQ\n\
scRim6wTV6STOXuEhQIDAQAB\n\
-----END PUBLIC KEY-----\n";

    std::string private_key =
        "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXAIBAAKBgQCw/YJVyXIVh7Vh0DAFqASWB8x/XXrzF2yuto3iZkkqBFasojN9\n\
R94FFHhT7AFHWwvXGFdXsUPLxq3R6GXoqdynqAX6UxROZD/CWBXRSIQL6c9S4+qs\n\
DH8MnXYYQmZZRSsDt5zpzukSU0nEr9+qq+GMBPAQscRim6wTV6STOXuEhQIDAQAB\n\
AoGACPEV152wzNOpX0K0WmTNroLAWyLu5j8lt4Hzkx+VzLChbGFZdpfd6KXLGnpO\n\
6jr4UyqgpwaGpVHpUDSMiX+jbSNbqNNkwAL8cv8wYlQBvZhe4NoqTi+e99dwH1iD\n\
McwjIR8IEDYxCSdplGWPN5hKkSoP6OWXNYguDDK0y8V52OECQQDrHhrJxRI89sM5\n\
vrOk7FBCbMV2T2foF2dcdf7j4gLT7p5Be8plI11P4KD0ZHY4gzjLJU/NdmX96EOk\n\
KDaZjnfNAkEAwLXBw8t0JvCzX/Qvn7izht/x8C85yYtUqDkFmqDr31era/yIUGSR\n\
pPLblXh8oFrjTEPp/H86mGKX5YLR0VyXmQJAXyjvFKzzhcMmHtAFa4HNtiTKAul+\n\
l5wpVG3ZfSgzls1kNgLBVw/qK3MyEdg7VQIfUXFHjFQYUZzZC67O8nWMHQJARwn5\n\
jtLOU5iBl0qtz6RH0d12E4NlOw24vHagwTq3GNL5p0olefVI11SLa9NJpdc7WR7j\n\
/6drE0etFPcfn50RaQJBAKaYjlQMlY4mF7TPxjkaCqc2sezfYYAIKtY9ipXovMG/\n\
SjLcXRy1Q3wpLtSRBAoo0K6GdiJnjEwH1WC1csWO54I=\n\
-----END RSA PRIVATE KEY-----\n";

    std::string pub_filename = "./rsa_public_key.pem";
    std::string pri_filename = "./rsa_private_key.pem";

    // 文件MD5
    std::string str = "6708120ab2f56928980555033baca13d";

    // 使用私钥文件生成签名，公钥文件验证签名
    std::vector<char> data = GenerateRsaSignByFile(str, pri_filename);
    std::cout << data.size() << std::endl;
    std::cout << VerifyRsaSignByFile(data.data(), data.size(), pub_filename,
                                     str)
              << std::endl;
    std::cout << VerifyRsaSignByString(data.data(), data.size(), public_key,
                                       str)
              << std::endl;

    // 使用私钥字符串生成签名，公钥文件、公钥字符串验证签名
    data = GenerateRsaSignByString(str, private_key);
    std::cout << data.size() << std::endl;
    std::cout << VerifyRsaSignByFile(data.data(), data.size(), pub_filename,
                                     str)
              << std::endl;
    std::cout << VerifyRsaSignByString(data.data(), data.size(), public_key,
                                       str)
              << std::endl;

    // 私钥文件加密，公钥文件，公钥字符串解密
    data = EncryptByPrikeyFile(str, pri_filename);
    std::cout << data.size() << std::endl;
    std::cout << DecryptByPubkeyFile(data.data(), data.size(), pub_filename)
              << std::endl;
    std::cout << DecryptByPubkeyString(data.data(), data.size(), public_key)
              << std::endl;

    // 私钥字符串加密，公钥文件，公钥字符串解密
    data = EncryptByPrikeyString(str, private_key);
    std::cout << data.size() << std::endl;
    std::cout << DecryptByPubkeyFile(data.data(), data.size(), pub_filename)
              << std::endl;
    std::cout << DecryptByPubkeyString(data.data(), data.size(), public_key)
              << std::endl;

    // 公钥文件加密，私钥文件，私钥字符串解密
    data = EncryptByPubkeyFile(str, pub_filename);
    std::cout << data.size() << std::endl;
    std::cout << DecryptByPrikeyFile(data.data(), data.size(), pri_filename)
              << std::endl;
    std::cout << DecryptByPrikeyString(data.data(), data.size(), private_key)
              << std::endl;

    data = EncryptByPubkeyString(str, public_key);
    std::cout << data.size() << std::endl;
    std::cout << DecryptByPrikeyFile(data.data(), data.size(), pri_filename)
              << std::endl;
    std::cout << DecryptByPrikeyString(data.data(), data.size(), private_key)
              << std::endl;

    return 0;
}
