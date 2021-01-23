# openssl_rsa
使用openssl rsa进行数据加密解密和生成签名和验证签名

# 编译步骤
git clone https://github.com/yangpan4485/openssl_rsa.git
cd openssl_rsa
md build
cd build
conan install ..
cmake ..
start .
打开 openssl_test.sln 编译运行（注意设置 rsa_public_key.pem 和 rsa_private_key.pem 两个文件的位置）
