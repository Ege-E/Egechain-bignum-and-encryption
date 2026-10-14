#pragma once

#include "Block.h"

#include <array>
#include <string>

struct WalletKeyPair {
    std::string privateKey;
    std::string publicKey;
    std::string address;
};

class Wallet {
public:
    static WalletKeyPair generateKeyPair();

    static std::string deriveAddress(const std::string& publicKey);
    static std::string signingPayload(const Transaction& transaction);

    static bool signTransaction(Transaction& transaction,
                                const std::string& privateKey,
                                std::string* error = nullptr);

    static bool verifyTransactionSignature(const Transaction& transaction,
                                           std::string* error = nullptr);

private:
    static constexpr size_t kSignatureBits = 64;
    using SecretPair = std::array<std::string, 2>;
    using SecretPairs = std::array<SecretPair, kSignatureBits>;

    static std::string randomHex(size_t bytes);
    static std::string hashHex(const std::string& text);
    static std::array<uint8_t, kSignatureBits> digestBits(const std::string& payload);

    static std::string serializePrivateKey(const SecretPairs& secretPairs);
    static std::string serializePublicKey(const SecretPairs& secretPairs);
    static bool parsePrivateKey(const std::string& privateKey, SecretPairs& secretPairs);
    static bool parsePublicKey(const std::string& publicKey, SecretPairs& hashedPairs);

    static std::string serializeSignature(const std::array<std::string, kSignatureBits>& values);
    static bool parseSignature(const std::string& signature, std::array<std::string, kSignatureBits>& values);
};
