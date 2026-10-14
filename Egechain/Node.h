#pragma once

#include "Block.h"

#include <cstddef>
#include <iosfwd>
#include <string>
#include <unordered_map>
#include <vector>

struct ConsensusConfig {
    uint32_t powDifficulty = 2;
    std::string miningReward = "50";
    size_t maxTransactionsPerBlock = 128;
};

class EgechainNode {
public:
    explicit EgechainNode(ConsensusConfig config = {});

    [[nodiscard]] const ConsensusConfig& config() const;
    [[nodiscard]] size_t mempoolSize() const;
    [[nodiscard]] uint64_t chainHeight() const;
    [[nodiscard]] std::string tipHash() const;
    [[nodiscard]] std::string balanceOf(const std::string& account) const;
    [[nodiscard]] std::vector<Block> canonicalChain() const;

    bool createGenesis(const std::string& recipient,
                       const std::string& amountExpression,
                       uint64_t timestampUnix,
                       std::string* rejectionReason = nullptr);

    bool submitTransaction(Transaction transaction, std::string* rejectionReason = nullptr);

    bool mineBlock(const std::string& minerAccount,
                   uint64_t timestampUnix,
                   Block* minedBlock = nullptr,
                   std::string* rejectionReason = nullptr);

    bool acceptBlock(const Block& block, std::string* rejectionReason = nullptr);

    bool saveToDisk(const std::string& path, std::string* error = nullptr) const;
    bool loadFromDisk(const std::string& path, std::string* error = nullptr);

private:
    struct BlockRecord {
        Block block;
        std::string hash;
        std::string parentHash;
        uint64_t height = 0;
        uint64_t cumulativeWork = 0;
        uint64_t timestampUnix = 0;
    };

    static std::string trim(const std::string& text);
    static bool isValidAccountName(const std::string& account);
    static bool parseUnsignedDecimal(const std::string& text, std::string& normalized);
    static bool parseStrictPositiveDecimal(const std::string& text, std::string& normalized);
    static int compareUnsignedDecimal(const std::string& left, const std::string& right);
    static std::string addUnsignedDecimal(const std::string& left, const std::string& right);
    static std::string subtractUnsignedDecimal(const std::string& left, const std::string& right);
    static bool hasRequiredPoWPrefix(const std::string& blockHash, uint32_t difficulty);
    static uint64_t workForDifficulty(uint32_t difficulty);

    static bool writeSizedField(std::ostream& output, const std::string& value);
    static bool readSizedField(std::istream& input, std::string& value);

    [[nodiscard]] std::string bestTipHashOrEmpty() const;
    [[nodiscard]] std::unordered_map<std::string, std::string> balancesAt(const std::string& blockHash) const;
    [[nodiscard]] bool chooseBetterTip(const std::string& candidateHash, const std::string& currentHash) const;

    bool validateAndApplyTransaction(const Transaction& transaction,
                                     std::unordered_map<std::string, std::string>& balances,
                                     std::string* rejectionReason) const;

    bool validateAndApplyBlock(const Block& block,
                               const std::unordered_map<std::string, std::string>& parentBalances,
                               std::unordered_map<std::string, std::string>& resultingBalances,
                               std::string* rejectionReason) const;

    bool addKnownBlock(const Block& block,
                       const std::string& blockHash,
                       const std::unordered_map<std::string, std::string>& resultingBalances,
                       uint64_t parentHeight,
                       uint64_t parentWork,
                       std::string* rejectionReason);

    void revalidateMempool();
    [[nodiscard]] std::vector<Transaction> selectTransactionsForMining(std::string* rejectionReason) const;

    ConsensusConfig config_;
    std::unordered_map<std::string, BlockRecord> knownBlocks_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> blockBalances_;
    std::vector<std::string> canonicalOrder_;
    std::vector<Transaction> mempool_;
    std::unordered_map<std::string, std::string> mempoolByHash_;
    std::string bestTipHash_;
};
