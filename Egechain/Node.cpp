#include "Node.h"

#include "LispParser.h"
#include "Wallet.h"

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace {
constexpr const char* kSystemAccount = "SYSTEM";
constexpr const char* kPersistenceMagic = "EGECHAIN_PHASE2_V1";
}

EgechainNode::EgechainNode(ConsensusConfig config)
    : config_(std::move(config)) {
    std::string reward;
    if (!parseStrictPositiveDecimal(config_.miningReward, reward)) {
        config_.miningReward = "50";
    } else {
        config_.miningReward = reward;
    }
    if (config_.maxTransactionsPerBlock == 0) {
        config_.maxTransactionsPerBlock = 1;
    }
}

const ConsensusConfig& EgechainNode::config() const {
    return config_;
}

size_t EgechainNode::mempoolSize() const {
    return mempool_.size();
}

uint64_t EgechainNode::chainHeight() const {
    if (bestTipHash_.empty()) {
        return 0;
    }

    const auto it = knownBlocks_.find(bestTipHash_);
    if (it == knownBlocks_.end()) {
        return 0;
    }

    return it->second.height;
}

std::string EgechainNode::tipHash() const {
    return bestTipHash_;
}

std::string EgechainNode::balanceOf(const std::string& account) const {
    if (bestTipHash_.empty()) {
        return "0";
    }

    const auto balancesIt = blockBalances_.find(bestTipHash_);
    if (balancesIt == blockBalances_.end()) {
        return "0";
    }

    const auto accountIt = balancesIt->second.find(account);
    if (accountIt == balancesIt->second.end()) {
        return "0";
    }

    return accountIt->second;
}

std::vector<Block> EgechainNode::canonicalChain() const {
    std::vector<Block> chain;
    chain.reserve(canonicalOrder_.size());

    for (const std::string& hash : canonicalOrder_) {
        const auto it = knownBlocks_.find(hash);
        if (it != knownBlocks_.end()) {
            chain.push_back(it->second.block);
        }
    }

    return chain;
}

bool EgechainNode::createGenesis(const std::string& recipient,
                                 const std::string& amountExpression,
                                 uint64_t timestampUnix,
                                 std::string* rejectionReason) {
    if (!knownBlocks_.empty()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Genesis already exists.";
        }
        return false;
    }

    Transaction grant;
    grant.sender = kSystemAccount;
    grant.receiver = recipient;
    grant.amountExpression = amountExpression;

    BlockHeader header;
    header.index = 0;
    header.previousBlockHash = "";
    header.timestampUnix = timestampUnix;
    header.difficulty = config_.powDifficulty;

    Block genesis(header);
    LispParser parser;
    if (!genesis.acceptTransaction(grant, parser, rejectionReason)) {
        return false;
    }

    genesis.mutableHeader().merkleRoot = genesis.computeMerkleRoot();

    while (!hasRequiredPoWPrefix(genesis.computeBlockHash(), genesis.header().difficulty)) {
        genesis.mutableHeader().nonce++;
    }

    return acceptBlock(genesis, rejectionReason);
}

bool EgechainNode::submitTransaction(Transaction transaction, std::string* rejectionReason) {
    if (bestTipHash_.empty()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Genesis block must be created before submitting transactions.";
        }
        return false;
    }

    if (trim(transaction.sender) == kSystemAccount) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Only mined coinbase transactions may use SYSTEM as sender.";
        }
        return false;
    }

    if (trim(transaction.nonce).empty()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Signed transaction nonce cannot be empty.";
        }
        return false;
    }

    LispParser parser;
    LightweightCrypto crypto;
    if (!Block::finalizeTransaction(transaction, parser, crypto, rejectionReason)) {
        return false;
    }

    if (mempoolByHash_.find(transaction.transactionHash) != mempoolByHash_.end()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction is already in mempool.";
        }
        return false;
    }

    const auto balancesIt = blockBalances_.find(bestTipHash_);
    if (balancesIt == blockBalances_.end()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Internal state error: missing tip balances.";
        }
        return false;
    }

    std::unordered_map<std::string, std::string> balances = balancesIt->second;
    for (const Transaction& pending : mempool_) {
        std::string ignoredReason;
        if (!validateAndApplyTransaction(pending, balances, &ignoredReason)) {
            continue;
        }
    }

    if (!validateAndApplyTransaction(transaction, balances, rejectionReason)) {
        return false;
    }

    mempoolByHash_.insert_or_assign(transaction.transactionHash, transaction.transactionHash);
    mempool_.push_back(std::move(transaction));
    if (rejectionReason != nullptr) {
        rejectionReason->clear();
    }
    return true;
}

bool EgechainNode::mineBlock(const std::string& minerAccount,
                             uint64_t timestampUnix,
                             Block* minedBlock,
                             std::string* rejectionReason) {
    if (bestTipHash_.empty()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Cannot mine before genesis exists.";
        }
        return false;
    }

    if (!isValidAccountName(trim(minerAccount))) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Miner account name is invalid.";
        }
        return false;
    }

    std::vector<Transaction> selected = selectTransactionsForMining(rejectionReason);

    Transaction reward;
    reward.sender = kSystemAccount;
    reward.receiver = trim(minerAccount);
    reward.amountExpression = config_.miningReward;
    reward.nonce = "0";

    LispParser parser;
    LightweightCrypto crypto;

    if (!Block::finalizeTransaction(reward, parser, crypto, rejectionReason)) {
        return false;
    }

    BlockHeader header;
    header.index = knownBlocks_.at(bestTipHash_).height + 1;
    header.previousBlockHash = bestTipHash_;
    header.timestampUnix = timestampUnix;
    header.difficulty = config_.powDifficulty;

    Block candidate(header);
    candidate.mutableBody().transactions.push_back(reward);
    for (const Transaction& tx : selected) {
        candidate.mutableBody().transactions.push_back(tx);
    }

    candidate.mutableHeader().merkleRoot = candidate.computeMerkleRoot();

    while (!hasRequiredPoWPrefix(candidate.computeBlockHash(), candidate.header().difficulty)) {
        candidate.mutableHeader().nonce++;
    }

    if (!acceptBlock(candidate, rejectionReason)) {
        return false;
    }

    if (minedBlock != nullptr) {
        *minedBlock = candidate;
    }

    return true;
}

bool EgechainNode::acceptBlock(const Block& block, std::string* rejectionReason) {
    const BlockHeader& header = block.header();

    if (header.difficulty != config_.powDifficulty) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Block difficulty does not match configured node difficulty.";
        }
        return false;
    }

    if (header.timestampUnix == 0) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Block timestamp must be non-zero.";
        }
        return false;
    }

    std::unordered_map<std::string, std::string> parentBalances;
    uint64_t parentHeight = 0;
    uint64_t parentWork = 0;
    uint64_t parentTimestamp = 0;

    if (knownBlocks_.empty()) {
        if (header.index != 0 || !header.previousBlockHash.empty()) {
            if (rejectionReason != nullptr) {
                *rejectionReason = "First block must be genesis with index 0 and empty previous hash.";
            }
            return false;
        }
    } else {
        const auto parentIt = knownBlocks_.find(header.previousBlockHash);
        if (parentIt == knownBlocks_.end()) {
            if (rejectionReason != nullptr) {
                *rejectionReason = "Previous block hash is unknown.";
            }
            return false;
        }

        parentHeight = parentIt->second.height;
        parentWork = parentIt->second.cumulativeWork;
        parentTimestamp = parentIt->second.timestampUnix;

        const auto parentBalancesIt = blockBalances_.find(header.previousBlockHash);
        if (parentBalancesIt == blockBalances_.end()) {
            if (rejectionReason != nullptr) {
                *rejectionReason = "Internal state error: previous block balances are unavailable.";
            }
            return false;
        }

        parentBalances = parentBalancesIt->second;

        if (header.index != parentHeight + 1) {
            if (rejectionReason != nullptr) {
                *rejectionReason = "Block index does not follow its parent.";
            }
            return false;
        }

        if (header.timestampUnix < parentTimestamp) {
            if (rejectionReason != nullptr) {
                *rejectionReason = "Block timestamp is older than parent timestamp.";
            }
            return false;
        }
    }

    if (header.merkleRoot != block.computeMerkleRoot()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Merkle root does not match block transactions.";
        }
        return false;
    }

    const std::string blockHash = block.computeBlockHash();
    if (!hasRequiredPoWPrefix(blockHash, header.difficulty)) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Block does not satisfy proof-of-work difficulty.";
        }
        return false;
    }

    if (knownBlocks_.find(blockHash) != knownBlocks_.end()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Block already known.";
        }
        return false;
    }

    std::unordered_map<std::string, std::string> resultingBalances;
    if (!validateAndApplyBlock(block, parentBalances, resultingBalances, rejectionReason)) {
        return false;
    }

    return addKnownBlock(block, blockHash, resultingBalances, parentHeight, parentWork, rejectionReason);
}

bool EgechainNode::saveToDisk(const std::string& path, std::string* error) const {
    const std::filesystem::path target(path);
    const std::filesystem::path temporary = target.string() + ".tmp";

    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        if (error != nullptr) {
            *error = "Unable to open temporary persistence file for writing.";
        }
        return false;
    }

    output << kPersistenceMagic << '\n';
    if (!writeSizedField(output, std::to_string(config_.powDifficulty)) ||
        !writeSizedField(output, config_.miningReward) ||
        !writeSizedField(output, std::to_string(config_.maxTransactionsPerBlock))) {
        if (error != nullptr) {
            *error = "Unable to write consensus configuration.";
        }
        return false;
    }

    std::vector<Block> chain = canonicalChain();
    if (!writeSizedField(output, std::to_string(chain.size()))) {
        if (error != nullptr) {
            *error = "Unable to write chain size.";
        }
        return false;
    }

    for (const Block& block : chain) {
        const BlockHeader& header = block.header();

        if (!writeSizedField(output, std::to_string(header.index)) ||
            !writeSizedField(output, header.previousBlockHash) ||
            !writeSizedField(output, header.merkleRoot) ||
            !writeSizedField(output, std::to_string(header.timestampUnix)) ||
            !writeSizedField(output, std::to_string(header.nonce)) ||
            !writeSizedField(output, std::to_string(header.difficulty)) ||
            !writeSizedField(output, std::to_string(block.body().transactions.size()))) {
            if (error != nullptr) {
                *error = "Unable to write block header/body metadata.";
            }
            return false;
        }

        for (const Transaction& transaction : block.body().transactions) {
            if (!writeSizedField(output, transaction.sender) ||
                !writeSizedField(output, transaction.receiver) ||
                !writeSizedField(output, transaction.amountExpression) ||
                !writeSizedField(output, transaction.nonce) ||
                !writeSizedField(output, transaction.senderPublicKey) ||
                !writeSizedField(output, transaction.signature) ||
                !writeSizedField(output, transaction.resolvedAmount) ||
                !writeSizedField(output, transaction.transactionHash) ||
                !writeSizedField(output, transaction.encryptedTransactionHash)) {
                if (error != nullptr) {
                    *error = "Unable to write transaction payload.";
                }
                return false;
            }
        }
    }

    if (!writeSizedField(output, std::to_string(mempool_.size()))) {
        if (error != nullptr) {
            *error = "Unable to write mempool size.";
        }
        return false;
    }

    for (const Transaction& transaction : mempool_) {
        if (!writeSizedField(output, transaction.sender) ||
            !writeSizedField(output, transaction.receiver) ||
            !writeSizedField(output, transaction.amountExpression) ||
            !writeSizedField(output, transaction.nonce) ||
            !writeSizedField(output, transaction.senderPublicKey) ||
            !writeSizedField(output, transaction.signature) ||
            !writeSizedField(output, transaction.resolvedAmount) ||
            !writeSizedField(output, transaction.transactionHash) ||
            !writeSizedField(output, transaction.encryptedTransactionHash)) {
            if (error != nullptr) {
                *error = "Unable to write mempool transaction.";
            }
            return false;
        }
    }

    output.flush();
    if (!output.good()) {
        if (error != nullptr) {
            *error = "Failed while flushing persistence data to disk.";
        }
        return false;
    }
    output.close();

    std::error_code renameError;
    std::filesystem::rename(temporary, target, renameError);
    if (renameError) {
        std::filesystem::remove(temporary);
        if (error != nullptr) {
            *error = "Atomic rename failed: " + renameError.message();
        }
        return false;
    }

    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool EgechainNode::loadFromDisk(const std::string& path, std::string* error) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        if (error != nullptr) {
            *error = "Persistence file is missing or cannot be opened.";
        }
        return false;
    }

    std::string magic;
    std::getline(input, magic);
    if (magic != kPersistenceMagic) {
        if (error != nullptr) {
            *error = "Persistence file magic header is invalid.";
        }
        return false;
    }

    try {
        EgechainNode loaded;

        std::string field;
        if (!readSizedField(input, field)) {
            if (error != nullptr) {
                *error = "Failed to read persisted difficulty.";
            }
            return false;
        }
        loaded.config_.powDifficulty = static_cast<uint32_t>(std::stoul(field));

        if (!readSizedField(input, field)) {
            if (error != nullptr) {
                *error = "Failed to read persisted mining reward.";
            }
            return false;
        }
        std::string normalizedReward;
        if (!parseStrictPositiveDecimal(field, normalizedReward)) {
            if (error != nullptr) {
                *error = "Persisted mining reward is invalid.";
            }
            return false;
        }
        loaded.config_.miningReward = normalizedReward;

        if (!readSizedField(input, field)) {
            if (error != nullptr) {
                *error = "Failed to read persisted max block transaction count.";
            }
            return false;
        }
        loaded.config_.maxTransactionsPerBlock = static_cast<size_t>(std::stoull(field));
        if (loaded.config_.maxTransactionsPerBlock == 0) {
            loaded.config_.maxTransactionsPerBlock = 1;
        }

        if (!readSizedField(input, field)) {
            if (error != nullptr) {
                *error = "Failed to read persisted chain size.";
            }
            return false;
        }

        const size_t chainSize = static_cast<size_t>(std::stoull(field));
        for (size_t i = 0; i < chainSize; i++) {
            BlockHeader header;

            if (!readSizedField(input, field)) {
                if (error != nullptr) {
                    *error = "Failed to read block index.";
                }
                return false;
            }
            header.index = std::stoull(field);

            if (!readSizedField(input, header.previousBlockHash) ||
                !readSizedField(input, header.merkleRoot)) {
                if (error != nullptr) {
                    *error = "Failed to read block hash linkage fields.";
                }
                return false;
            }

            if (!readSizedField(input, field)) {
                if (error != nullptr) {
                    *error = "Failed to read block timestamp.";
                }
                return false;
            }
            header.timestampUnix = std::stoull(field);

            if (!readSizedField(input, field)) {
                if (error != nullptr) {
                    *error = "Failed to read block nonce.";
                }
                return false;
            }
            header.nonce = std::stoull(field);

            if (!readSizedField(input, field)) {
                if (error != nullptr) {
                    *error = "Failed to read block difficulty.";
                }
                return false;
            }
            header.difficulty = static_cast<uint32_t>(std::stoul(field));

            if (!readSizedField(input, field)) {
                if (error != nullptr) {
                    *error = "Failed to read transaction count.";
                }
                return false;
            }
            const size_t transactionCount = static_cast<size_t>(std::stoull(field));

            Block block(header);

            for (size_t txIndex = 0; txIndex < transactionCount; txIndex++) {
                Transaction tx;
                if (!readSizedField(input, tx.sender) ||
                    !readSizedField(input, tx.receiver) ||
                    !readSizedField(input, tx.amountExpression) ||
                    !readSizedField(input, tx.nonce) ||
                    !readSizedField(input, tx.senderPublicKey) ||
                    !readSizedField(input, tx.signature) ||
                    !readSizedField(input, tx.resolvedAmount) ||
                    !readSizedField(input, tx.transactionHash) ||
                    !readSizedField(input, tx.encryptedTransactionHash)) {
                    if (error != nullptr) {
                        *error = "Failed to read transaction payload from persisted block.";
                    }
                    return false;
                }
                block.mutableBody().transactions.push_back(std::move(tx));
            }

            std::string rejectionReason;
            if (!loaded.acceptBlock(block, &rejectionReason)) {
                if (error != nullptr) {
                    *error = "Persisted block is invalid: " + rejectionReason;
                }
                return false;
            }
        }

        if (!readSizedField(input, field)) {
            if (error != nullptr) {
                *error = "Failed to read persisted mempool size.";
            }
            return false;
        }

        const size_t mempoolSize = static_cast<size_t>(std::stoull(field));
        for (size_t i = 0; i < mempoolSize; i++) {
            Transaction tx;
            if (!readSizedField(input, tx.sender) ||
                !readSizedField(input, tx.receiver) ||
                !readSizedField(input, tx.amountExpression) ||
                !readSizedField(input, tx.nonce) ||
                !readSizedField(input, tx.senderPublicKey) ||
                !readSizedField(input, tx.signature) ||
                !readSizedField(input, tx.resolvedAmount) ||
                !readSizedField(input, tx.transactionHash) ||
                !readSizedField(input, tx.encryptedTransactionHash)) {
                if (error != nullptr) {
                    *error = "Failed to read persisted mempool transaction.";
                }
                return false;
            }

            std::string rejectionReason;
            if (!loaded.submitTransaction(std::move(tx), &rejectionReason)) {
                if (error != nullptr) {
                    *error = "Persisted mempool transaction is invalid: " + rejectionReason;
                }
                return false;
            }
        }

        std::string trailing;
        if (readSizedField(input, trailing)) {
            if (error != nullptr) {
                *error = "Persistence file has unexpected trailing data.";
            }
            return false;
        }

        *this = std::move(loaded);
        if (error != nullptr) {
            error->clear();
        }
        return true;
    } catch (const std::exception& e) {
        if (error != nullptr) {
            *error = std::string("Malformed persistence content: ") + e.what();
        }
        return false;
    }
}

std::string EgechainNode::trim(const std::string& text) {
    const size_t begin = text.find_first_not_of(" \t\n\r\f\v");
    if (begin == std::string::npos) {
        return "";
    }

    const size_t end = text.find_last_not_of(" \t\n\r\f\v");
    return text.substr(begin, end - begin + 1);
}

bool EgechainNode::isValidAccountName(const std::string& account) {
    if (account.empty()) {
        return false;
    }

    for (const char ch : account) {
        const unsigned char value = static_cast<unsigned char>(ch);
        if ((value >= 'a' && value <= 'z') ||
            (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') ||
            ch == '_' || ch == '-' || ch == '.') {
            continue;
        }
        return false;
    }

    return true;
}

bool EgechainNode::parseUnsignedDecimal(const std::string& text, std::string& normalized) {
    if (text.empty()) {
        return false;
    }

    size_t begin = 0;
    if (text[0] == '+') {
        begin = 1;
    }

    if (begin >= text.size()) {
        return false;
    }

    for (size_t i = begin; i < text.size(); i++) {
        const char ch = text[i];
        if (ch < '0' || ch > '9') {
            return false;
        }
    }

    size_t firstNonZero = text.find_first_not_of('0', begin);
    if (firstNonZero == std::string::npos) {
        normalized = "0";
    } else {
        normalized = text.substr(firstNonZero);
    }

    return true;
}

bool EgechainNode::parseStrictPositiveDecimal(const std::string& text, std::string& normalized) {
    if (!parseUnsignedDecimal(text, normalized)) {
        return false;
    }
    return normalized != "0";
}

int EgechainNode::compareUnsignedDecimal(const std::string& left, const std::string& right) {
    if (left.size() < right.size()) {
        return -1;
    }
    if (left.size() > right.size()) {
        return 1;
    }
    if (left < right) {
        return -1;
    }
    if (left > right) {
        return 1;
    }
    return 0;
}

std::string EgechainNode::addUnsignedDecimal(const std::string& left, const std::string& right) {
    std::string result;
    result.reserve(std::max(left.size(), right.size()) + 1);

    int i = static_cast<int>(left.size()) - 1;
    int j = static_cast<int>(right.size()) - 1;
    int carry = 0;

    while (i >= 0 || j >= 0 || carry > 0) {
        const int lv = i >= 0 ? left[static_cast<size_t>(i)] - '0' : 0;
        const int rv = j >= 0 ? right[static_cast<size_t>(j)] - '0' : 0;
        const int sum = lv + rv + carry;
        result.push_back(static_cast<char>('0' + (sum % 10)));
        carry = sum / 10;
        i--;
        j--;
    }

    return std::string(result.rbegin(), result.rend());
}

std::string EgechainNode::subtractUnsignedDecimal(const std::string& left, const std::string& right) {
    std::string result;
    result.reserve(left.size());

    int i = static_cast<int>(left.size()) - 1;
    int j = static_cast<int>(right.size()) - 1;
    int borrow = 0;

    while (i >= 0) {
        int lv = (left[static_cast<size_t>(i)] - '0') - borrow;
        const int rv = (j >= 0) ? right[static_cast<size_t>(j)] - '0' : 0;

        if (lv < rv) {
            lv += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }

        result.push_back(static_cast<char>('0' + (lv - rv)));
        i--;
        j--;
    }

    while (result.size() > 1 && result.back() == '0') {
        result.pop_back();
    }

    return std::string(result.rbegin(), result.rend());
}

bool EgechainNode::hasRequiredPoWPrefix(const std::string& blockHash, uint32_t difficulty) {
    if (difficulty > blockHash.size()) {
        return false;
    }

    for (uint32_t i = 0; i < difficulty; i++) {
        if (blockHash[i] != '0') {
            return false;
        }
    }

    return true;
}

uint64_t EgechainNode::workForDifficulty(uint32_t difficulty) {
    return static_cast<uint64_t>(difficulty) + 1ULL;
}

bool EgechainNode::writeSizedField(std::ostream& output, const std::string& value) {
    output << value.size() << ':';
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    output.put('\n');
    return output.good();
}

bool EgechainNode::readSizedField(std::istream& input, std::string& value) {
    std::string lengthText;
    char ch = '\0';

    while (input.get(ch)) {
        if (ch == ':') {
            break;
        }

        if (ch < '0' || ch > '9') {
            return false;
        }
        lengthText.push_back(ch);
    }

    if (!input.good() && !input.eof()) {
        return false;
    }

    if (lengthText.empty() || ch != ':') {
        return false;
    }

    size_t length = 0;
    try {
        length = static_cast<size_t>(std::stoull(lengthText));
    } catch (...) {
        return false;
    }

    value.assign(length, '\0');
    if (length > 0) {
        input.read(value.data(), static_cast<std::streamsize>(length));
        if (input.gcount() != static_cast<std::streamsize>(length)) {
            return false;
        }
    }

    if (!input.get(ch) || ch != '\n') {
        return false;
    }

    return true;
}

std::string EgechainNode::bestTipHashOrEmpty() const {
    return bestTipHash_;
}

std::unordered_map<std::string, std::string> EgechainNode::balancesAt(const std::string& blockHash) const {
    const auto it = blockBalances_.find(blockHash);
    if (it == blockBalances_.end()) {
        return {};
    }
    return it->second;
}

bool EgechainNode::chooseBetterTip(const std::string& candidateHash, const std::string& currentHash) const {
    if (currentHash.empty()) {
        return true;
    }

    const auto candidateIt = knownBlocks_.find(candidateHash);
    const auto currentIt = knownBlocks_.find(currentHash);

    if (candidateIt == knownBlocks_.end() || currentIt == knownBlocks_.end()) {
        return false;
    }

    const BlockRecord& candidate = candidateIt->second;
    const BlockRecord& current = currentIt->second;

    if (candidate.cumulativeWork != current.cumulativeWork) {
        return candidate.cumulativeWork > current.cumulativeWork;
    }

    if (candidate.height != current.height) {
        return candidate.height > current.height;
    }

    return candidate.hash < current.hash;
}

bool EgechainNode::validateAndApplyTransaction(const Transaction& transaction,
                                               std::unordered_map<std::string, std::string>& balances,
                                               std::string* rejectionReason) const {
    LispParser parser;
    std::string txReason;
    if (!Block::verifyTransaction(transaction, parser, &txReason)) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction integrity check failed: " + txReason;
        }
        return false;
    }

    const std::string sender = trim(transaction.sender);
    const std::string receiver = trim(transaction.receiver);

    if (sender == receiver) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction sender and receiver must differ.";
        }
        return false;
    }

    if (sender != kSystemAccount && !isValidAccountName(sender)) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction sender account is invalid.";
        }
        return false;
    }

    if (!isValidAccountName(receiver)) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction receiver account is invalid.";
        }
        return false;
    }

    std::string amount;
    if (!parseStrictPositiveDecimal(transaction.resolvedAmount, amount)) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction resolved amount is not a positive decimal value.";
        }
        return false;
    }

    if (sender == kSystemAccount) {
        balances[receiver] = addUnsignedDecimal(balances[receiver].empty() ? "0" : balances[receiver], amount);
        return true;
    }

    std::string normalizedNonce;
    if (!parseStrictPositiveDecimal(transaction.nonce, normalizedNonce)) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction nonce must be a strictly positive decimal value.";
        }
        return false;
    }

    if (transaction.senderPublicKey.empty()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction sender public key is missing.";
        }
        return false;
    }

    const std::string derivedSender = Wallet::deriveAddress(transaction.senderPublicKey);
    if (derivedSender != sender) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction sender does not match sender public key.";
        }
        return false;
    }

    std::string signatureReason;
    if (!Wallet::verifyTransactionSignature(transaction, &signatureReason)) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction signature verification failed: " + signatureReason;
        }
        return false;
    }

    const std::string currentSenderBalance = balances[sender].empty() ? "0" : balances[sender];
    if (compareUnsignedDecimal(currentSenderBalance, amount) < 0) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Sender has insufficient balance.";
        }
        return false;
    }

    balances[sender] = subtractUnsignedDecimal(currentSenderBalance, amount);
    balances[receiver] = addUnsignedDecimal(balances[receiver].empty() ? "0" : balances[receiver], amount);

    return true;
}

bool EgechainNode::validateAndApplyBlock(const Block& block,
                                         const std::unordered_map<std::string, std::string>& parentBalances,
                                         std::unordered_map<std::string, std::string>& resultingBalances,
                                         std::string* rejectionReason) const {
    resultingBalances = parentBalances;
    const bool isGenesis = (block.header().index == 0 && block.header().previousBlockHash.empty());

    if (block.body().transactions.empty()) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Block must include at least a coinbase transaction.";
        }
        return false;
    }

    bool seenCoinbase = false;

    for (size_t i = 0; i < block.body().transactions.size(); i++) {
        const Transaction& tx = block.body().transactions[i];
        const bool isCoinbase = trim(tx.sender) == kSystemAccount;

        if (isCoinbase) {
            if (!isGenesis) {
                if (i != 0) {
                    if (rejectionReason != nullptr) {
                        *rejectionReason = "Coinbase transaction must be the first transaction in block.";
                    }
                    return false;
                }
                if (seenCoinbase) {
                    if (rejectionReason != nullptr) {
                        *rejectionReason = "Block contains multiple coinbase transactions.";
                    }
                    return false;
                }
                if (tx.resolvedAmount != config_.miningReward) {
                    if (rejectionReason != nullptr) {
                        *rejectionReason = "Coinbase reward does not match node consensus reward.";
                    }
                    return false;
                }
            }
            seenCoinbase = true;
        } else if (isGenesis) {
            if (rejectionReason != nullptr) {
                *rejectionReason = "Genesis block may only contain SYSTEM-funded allocation transactions.";
            }
            return false;
        }

        std::string txReason;
        if (!validateAndApplyTransaction(tx, resultingBalances, &txReason)) {
            if (rejectionReason != nullptr) {
                *rejectionReason = "Block transaction " + std::to_string(i) + " invalid: " + txReason;
            }
            return false;
        }
    }

    if (!seenCoinbase) {
        if (rejectionReason != nullptr) {
            *rejectionReason = isGenesis
                                   ? "Genesis block is missing initial SYSTEM-funded allocations."
                                   : "Block is missing required coinbase transaction.";
        }
        return false;
    }

    return true;
}

bool EgechainNode::addKnownBlock(const Block& block,
                                 const std::string& blockHash,
                                 const std::unordered_map<std::string, std::string>& resultingBalances,
                                 uint64_t parentHeight,
                                 uint64_t parentWork,
                                 std::string* rejectionReason) {
    BlockRecord record;
    record.block = block;
    record.hash = blockHash;
    record.parentHash = block.header().previousBlockHash;
    record.height = knownBlocks_.empty() ? 0 : parentHeight + 1;
    record.cumulativeWork = parentWork + workForDifficulty(block.header().difficulty);
    record.timestampUnix = block.header().timestampUnix;

    knownBlocks_.insert_or_assign(blockHash, record);
    blockBalances_.insert_or_assign(blockHash, resultingBalances);

    if (chooseBetterTip(blockHash, bestTipHash_)) {
        bestTipHash_ = blockHash;

        canonicalOrder_.clear();
        std::string cursor = bestTipHash_;
        while (!cursor.empty()) {
            const auto it = knownBlocks_.find(cursor);
            if (it == knownBlocks_.end()) {
                break;
            }
            canonicalOrder_.push_back(cursor);
            cursor = it->second.parentHash;
        }
        std::reverse(canonicalOrder_.begin(), canonicalOrder_.end());

        revalidateMempool();
    }

    if (rejectionReason != nullptr) {
        rejectionReason->clear();
    }

    return true;
}

void EgechainNode::revalidateMempool() {
    if (bestTipHash_.empty()) {
        mempool_.clear();
        mempoolByHash_.clear();
        return;
    }

    const auto balancesIt = blockBalances_.find(bestTipHash_);
    if (balancesIt == blockBalances_.end()) {
        mempool_.clear();
        mempoolByHash_.clear();
        return;
    }

    std::unordered_map<std::string, std::string> workingBalances = balancesIt->second;
    std::unordered_map<std::string, std::string> confirmed;
    for (const std::string& blockHash : canonicalOrder_) {
        const auto blockIt = knownBlocks_.find(blockHash);
        if (blockIt == knownBlocks_.end()) {
            continue;
        }
        for (const Transaction& transaction : blockIt->second.block.body().transactions) {
            confirmed.insert_or_assign(transaction.transactionHash, transaction.transactionHash);
        }
    }

    std::vector<Transaction> filtered;
    std::unordered_map<std::string, std::string> filteredIndex;

    for (const Transaction& tx : mempool_) {
        if (confirmed.find(tx.transactionHash) != confirmed.end()) {
            continue;
        }
        if (filteredIndex.find(tx.transactionHash) != filteredIndex.end()) {
            continue;
        }

        std::string reason;
        if (!validateAndApplyTransaction(tx, workingBalances, &reason)) {
            continue;
        }

        filteredIndex.insert_or_assign(tx.transactionHash, tx.transactionHash);
        filtered.push_back(tx);
    }

    mempool_ = std::move(filtered);
    mempoolByHash_ = std::move(filteredIndex);
}

std::vector<Transaction> EgechainNode::selectTransactionsForMining(std::string* rejectionReason) const {
    std::vector<Transaction> selected;
    if (bestTipHash_.empty()) {
        return selected;
    }

    const auto balancesIt = blockBalances_.find(bestTipHash_);
    if (balancesIt == blockBalances_.end()) {
        return selected;
    }

    std::unordered_map<std::string, std::string> workingBalances = balancesIt->second;

    for (const Transaction& tx : mempool_) {
        if (selected.size() >= config_.maxTransactionsPerBlock) {
            break;
        }

        std::string reason;
        if (!validateAndApplyTransaction(tx, workingBalances, &reason)) {
            continue;
        }

        selected.push_back(tx);
    }

    if (rejectionReason != nullptr) {
        rejectionReason->clear();
    }

    return selected;
}
