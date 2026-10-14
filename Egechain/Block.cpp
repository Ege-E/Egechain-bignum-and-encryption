#include "Block.h"

#include "LispParser.h"

#include <cctype>
#include <sstream>
#include <utility>

namespace {
constexpr size_t kMaxScriptLength = 512;
constexpr size_t kMaxScriptTokens = 128;

bool isSignedIntegerToken(const std::string& token) {
    if (token.empty()) {
        return false;
    }

    size_t begin = 0;
    if (token[0] == '+' || token[0] == '-') {
        begin = 1;
    }
    if (begin >= token.size()) {
        return false;
    }

    for (size_t i = begin; i < token.size(); i++) {
        const unsigned char ch = static_cast<unsigned char>(token[i]);
        if (!std::isdigit(ch)) {
            return false;
        }
    }
    return true;
}

bool validateDeterministicScript(const std::string& expression, std::string* reason) {
    if (expression.empty()) {
        if (reason != nullptr) {
            *reason = "Transaction amount expression cannot be empty.";
        }
        return false;
    }

    if (expression.size() > kMaxScriptLength) {
        if (reason != nullptr) {
            *reason = "Transaction amount expression exceeds deterministic size limit.";
        }
        return false;
    }

    std::string expanded;
    expanded.reserve(expression.size() * 2);
    for (char ch : expression) {
        if (ch == '(' || ch == ')') {
            expanded.push_back(' ');
            expanded.push_back(ch);
            expanded.push_back(' ');
        } else {
            expanded.push_back(ch);
        }
    }

    std::istringstream stream(expanded);
    std::vector<std::string> tokens;
    std::string token;
    while (stream >> token) {
        tokens.push_back(token);
        if (tokens.size() > kMaxScriptTokens) {
            if (reason != nullptr) {
                *reason = "Transaction amount expression exceeds deterministic token bound.";
            }
            return false;
        }
    }

    if (tokens.empty()) {
        if (reason != nullptr) {
            *reason = "Transaction amount expression has no tokens.";
        }
        return false;
    }

    for (const std::string& tk : tokens) {
        if (tk == "(" || tk == ")" || tk == "simplify" || tk == "+" || tk == "-" || tk == "*") {
            continue;
        }

        if (!isSignedIntegerToken(tk)) {
            if (reason != nullptr) {
                *reason = "Transaction script contains non-deterministic or unsupported token: " + tk;
            }
            return false;
        }
    }

    return true;
}
}

Block::Block(BlockHeader header)
    : header_(std::move(header)) {
}

const BlockHeader& Block::header() const {
    return header_;
}

BlockHeader& Block::mutableHeader() {
    return header_;
}

const BlockBody& Block::body() const {
    return body_;
}

BlockBody& Block::mutableBody() {
    return body_;
}

size_t Block::transactionCount() const {
    return body_.transactions.size();
}

const HashEncryptionProfile& Block::hashEncryptionProfile() const {
    return hashCrypto_.profile();
}

void Block::setHashEncryptionProfile(HashEncryptionProfile profile) {
    hashCrypto_.setProfile(std::move(profile));
}

void Block::addHashEncryptionPhase(HashEncryptionPhase phase) {
    hashCrypto_.addPhase(phase);
}

bool Block::acceptTransaction(Transaction transaction, LispParser& parser, std::string* rejectionReason) {
    if (!finalizeTransaction(transaction, parser, hashCrypto_, rejectionReason)) {
        return false;
    }

    body_.transactions.push_back(std::move(transaction));
    return true;
}

std::string Block::computeMerkleRoot() const {
    if (body_.transactions.empty()) {
        return LightweightCrypto::hashString("empty");
    }

    std::vector<std::string> layer;
    layer.reserve(body_.transactions.size());
    for (const Transaction& transaction : body_.transactions) {
        layer.push_back(transaction.transactionHash.empty()
                            ? LightweightCrypto::hashString(canonicalTransactionText(transaction))
                            : transaction.transactionHash);
    }

    while (layer.size() > 1) {
        std::vector<std::string> nextLayer;
        nextLayer.reserve((layer.size() + 1) / 2);

        for (size_t i = 0; i < layer.size(); i += 2) {
            const std::string& left = layer[i];
            const std::string& right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];
            nextLayer.push_back(LightweightCrypto::hashString(left + "|" + right));
        }

        layer = std::move(nextLayer);
    }

    return layer.front();
}

std::string Block::computeBlockHash() const {
    std::ostringstream canonical;
    canonical << header_.index << '|'
              << header_.previousBlockHash << '|'
              << header_.merkleRoot << '|'
              << header_.timestampUnix << '|'
              << header_.nonce << '|'
              << header_.difficulty;

    for (const Transaction& transaction : body_.transactions) {
        canonical << '|'
                  << transaction.sender << '>'
                  << transaction.receiver << '>'
                  << transaction.amountExpression << '>'
                  << transaction.nonce << '>'
                  << transaction.senderPublicKey << '>'
                  << transaction.signature << '>'
                  << transaction.resolvedAmount << '>'
                  << transaction.transactionHash << '>'
                  << transaction.encryptedTransactionHash;
    }

    return LightweightCrypto::hashString(canonical.str());
}

bool Block::finalizeTransaction(Transaction& transaction,
                                LispParser& parser,
                                const LightweightCrypto& hashCrypto,
                                std::string* rejectionReason) {
    (void)parser;
    const auto reject = [&](std::string reason) {
        if (rejectionReason != nullptr) {
            *rejectionReason = std::move(reason);
        }
        return false;
    };

    transaction.sender = trim(transaction.sender);
    transaction.receiver = trim(transaction.receiver);
    transaction.amountExpression = trim(transaction.amountExpression);
    transaction.nonce = trim(transaction.nonce);
    transaction.senderPublicKey = trim(transaction.senderPublicKey);
    transaction.signature = trim(transaction.signature);

    if (transaction.sender.empty()) {
        return reject("Transaction sender cannot be empty.");
    }

    if (transaction.receiver.empty()) {
        return reject("Transaction receiver cannot be empty.");
    }

    if (transaction.amountExpression.empty()) {
        return reject("Transaction amount expression cannot be empty.");
    }

    std::string scriptPolicyReason;
    if (!validateDeterministicScript(transaction.amountExpression, &scriptPolicyReason)) {
        return reject(scriptPolicyReason);
    }

    try {
        LispParser deterministicParser;
        const Bignum evaluatedAmount = deterministicParser.parseAndEvaluate(transaction.amountExpression);
        transaction.resolvedAmount = evaluatedAmount.toSignedDecimalString();
    } catch (const std::exception& e) {
        return reject(std::string("Transaction amount expression could not be parsed: ") + e.what());
    }

    if (!isStrictlyPositiveAmount(transaction.resolvedAmount)) {
        return reject("Transaction amount must resolve to a positive number.");
    }

    try {
        transaction.transactionHash = LightweightCrypto::hashString(canonicalTransactionText(transaction));
        transaction.encryptedTransactionHash = hashCrypto.encryptHash(transaction.transactionHash);
    } catch (const std::exception& e) {
        return reject(std::string("Transaction hash encryption failed: ") + e.what());
    }

    if (rejectionReason != nullptr) {
        rejectionReason->clear();
    }

    return true;
}

bool Block::verifyTransaction(const Transaction& transaction, LispParser& parser, std::string* rejectionReason) {
    Transaction recomputed = transaction;
    recomputed.transactionHash.clear();
    recomputed.encryptedTransactionHash.clear();

    LightweightCrypto crypto;
    if (!finalizeTransaction(recomputed, parser, crypto, rejectionReason)) {
        return false;
    }

    if (recomputed.resolvedAmount != transaction.resolvedAmount) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction resolved amount does not match expression.";
        }
        return false;
    }

    if (recomputed.transactionHash != transaction.transactionHash) {
        if (rejectionReason != nullptr) {
            *rejectionReason = "Transaction hash does not match canonical payload.";
        }
        return false;
    }

    try {
        LightweightCrypto decryptor;
        const std::string decrypted = decryptor.decryptHash(transaction.encryptedTransactionHash);
        if (decrypted != transaction.transactionHash) {
            if (rejectionReason != nullptr) {
                *rejectionReason = "Encrypted transaction hash does not decrypt to transaction hash.";
            }
            return false;
        }
    } catch (const std::exception& e) {
        if (rejectionReason != nullptr) {
            *rejectionReason = std::string("Encrypted transaction hash is invalid: ") + e.what();
        }
        return false;
    }

    if (rejectionReason != nullptr) {
        rejectionReason->clear();
    }

    return true;
}

std::string Block::canonicalTransactionText(const Transaction& transaction) {
    return transaction.sender + "|" +
           transaction.receiver + "|" +
           transaction.amountExpression + "|" +
           transaction.nonce + "|" +
           transaction.senderPublicKey + "|" +
           transaction.signature + "|" +
           transaction.resolvedAmount;
}

std::string Block::trim(const std::string& text) {
    const size_t begin = text.find_first_not_of(" \t\n\r\f\v");
    if (begin == std::string::npos) {
        return "";
    }

    const size_t end = text.find_last_not_of(" \t\n\r\f\v");
    return text.substr(begin, end - begin + 1);
}

bool Block::isStrictlyPositiveAmount(const std::string& amount) {
    if (amount.empty()) {
        return false;
    }

    size_t start = 0;
    if (amount[0] == '+') {
        start = 1;
    } else if (amount[0] == '-') {
        return false;
    }

    if (start >= amount.size()) {
        return false;
    }

    bool hasNonZeroDigit = false;
    for (size_t i = start; i < amount.size(); i++) {
        const unsigned char ch = static_cast<unsigned char>(amount[i]);
        if (!std::isdigit(ch)) {
            return false;
        }

        if (amount[i] != '0') {
            hasNonZeroDigit = true;
        }
    }

    return hasNonZeroDigit;
}