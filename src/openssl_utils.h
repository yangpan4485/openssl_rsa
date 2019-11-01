#pragma once

#include <cstdint>

#include <string>
#include <vector>

// 生成签名通过私钥文件
std::vector<char> GenerateRsaSignByFile(const std::string& message,
                                        const std::string& pri_filename);

// 生成签名通过私钥字符串
std::vector<char> GenerateRsaSignByString(const std::string& message,
                                          const std::string& prikey);

// 验证签名通过公钥文件
bool VerifyRsaSignByFile(char* sign, uint32_t sign_len,
                         const std::string& pub_filename,
                         const std::string& verify_str);

// 验证签名通过公钥字符串
bool VerifyRsaSignByString(char* sign, uint32_t sign_len,
                           const std::string& pubkey,
                           const std::string& verify_str);

// 使用公钥字符串加密
std::vector<char> EncryptByPubkeyString(const std::string& message,
                                        const std::string& pubkey);

// 使用公钥文件加密
std::vector<char> EncryptByPubkeyFile(const std::string& message,
                                      const std::string& pub_filename);

// 使用私钥字符串加密
std::vector<char> EncryptByPrikeyString(const std::string& message,
                                        const std::string& prikey);

// 使用私钥字符串加密
std::vector<char> EncryptByPrikeyFile(const std::string& message,
                                      const std::string& pri_file);

// 使用公钥字符串解密
std::string DecryptByPubkeyString(char* cipher, uint32_t len,
                                  const std::string& pubkey);

// 使用公钥文件解密
std::string DecryptByPubkeyFile(char* cipher, uint32_t len,
                                const std::string& pub_filename);

// 使用私钥字符串解密
std::string DecryptByPrikeyString(char* cipher, uint32_t len,
                                  const std::string prikey);

// 使用私钥文件解密
std::string DecryptByPrikeyFile(char* cipher, uint32_t len,
                                const std::string& pri_file);
