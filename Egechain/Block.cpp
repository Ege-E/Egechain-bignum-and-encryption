#include "Block.h"

#include "LispParser.h"

#include <cctype>
#include <utility>

Block::Block(BlockHeader header)
    : header_(std::move(header)) {
}

const BlockHeader& Block::header() const {
    return header_;
}

const BlockBody& Block::body() const {
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
    const auto reject = [&](std::string reason) {
        if (rejectionReason != nullptr) {
            *rejectionReason = std::move(reason);
        }
        return false;
    };

    transaction.sender = trim(transaction.sender);
    transaction.receiver = trim(transaction.receiver);
    transaction.amountExpression = trim(transaction.amountExpression);

    if (transaction.sender.empty()) {
        return reject("Transaction sender cannot be empty.");
    }

    if (transaction.receiver.empty()) {
        return reject("Transaction receiver cannot be empty.");
    }

    if (transaction.amountExpression.empty()) {
        return reject("Transaction amount expression cannot be empty.");
    }

    try {
        const Bignum evaluatedAmount = parser.parseAndEvaluate(transaction.amountExpression);
        transaction.resolvedAmount = evaluatedAmount.toSignedDecimalString();
    } catch (const std::exception& e) {
        return reject(std::string("Transaction amount expression could not be parsed: ") + e.what());
    }

    if (!isStrictlyPositiveAmount(transaction.resolvedAmount)) {
        return reject("Transaction amount must resolve to a positive number.");
    }

    try {
        transaction.transactionHash = LightweightCrypto::hashString(canonicalTransactionText(transaction));
        transaction.encryptedTransactionHash = hashCrypto_.encryptHash(transaction.transactionHash);
    } catch (const std::exception& e) {
        return reject(std::string("Transaction hash encryption failed: ") + e.what());
    }

    if (rejectionReason != nullptr) {
        rejectionReason->clear();
    }

    body_.transactions.push_back(std::move(transaction));
    return true;
}

std::string Block::canonicalTransactionText(const Transaction& transaction) {
    return transaction.sender + "|" +
           transaction.receiver + "|" +
           transaction.amountExpression + "|" +
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