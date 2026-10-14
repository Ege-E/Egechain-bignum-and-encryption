#pragma once

#include "LightweightCrypto.h"

#include <cstdint>
#include <string>
#include <vector>

class LispParser;

struct Transaction {
    std::string sender;
    std::string receiver;
    std::string amountExpression;
    std::string resolvedAmount;
    std::string transactionHash;
    std::string encryptedTransactionHash;
};

struct BlockHeader {
    uint64_t index = 0;
    std::string previousBlockHash;
    std::string merkleRoot;
    uint64_t timestampUnix = 0;
    uint64_t nonce = 0;
    uint32_t difficulty = 0;
};

struct BlockBody {
    std::vector<Transaction> transactions;
};

class Block {
public:
    explicit Block(BlockHeader header = {});

    [[nodiscard]] const BlockHeader& header() const;
    [[nodiscard]] BlockHeader& mutableHeader();
    [[nodiscard]] const BlockBody& body() const;
    [[nodiscard]] BlockBody& mutableBody();
    [[nodiscard]] size_t transactionCount() const;
    [[nodiscard]] const HashEncryptionProfile& hashEncryptionProfile() const;

    void setHashEncryptionProfile(HashEncryptionProfile profile);
    void addHashEncryptionPhase(HashEncryptionPhase phase);

    bool acceptTransaction(Transaction transaction, LispParser& parser, std::string* rejectionReason = nullptr);
    [[nodiscard]] std::string computeMerkleRoot() const;
    [[nodiscard]] std::string computeBlockHash() const;

    static bool finalizeTransaction(Transaction& transaction,
                                    LispParser& parser,
                                    const LightweightCrypto& hashCrypto,
                                    std::string* rejectionReason = nullptr);
    static bool verifyTransaction(const Transaction& transaction, LispParser& parser, std::string* rejectionReason = nullptr);

private:
    static std::string canonicalTransactionText(const Transaction& transaction);
    static std::string trim(const std::string& text);
    static bool isStrictlyPositiveAmount(const std::string& amount);

    BlockHeader header_;
    BlockBody body_;
    LightweightCrypto hashCrypto_;
};