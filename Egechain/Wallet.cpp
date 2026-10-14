#include "Wallet.h"

#include "LightweightCrypto.h"

#include <random>
#include <sstream>

namespace {
std::vector<std::string> split(const std::string& text, char delimiter) {
    std::vector<std::string> parts;
    std::string current;
    for (const char ch : text) {
        if (ch == delimiter) {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    parts.push_back(current);
    return parts;
}
}

WalletKeyPair Wallet::generateKeyPair() {
    SecretPairs pairs;
    for (size_t i = 0; i < kSignatureBits; i++) {
        pairs[i][0] = randomHex(16);
        pairs[i][1] = randomHex(16);
    }

    WalletKeyPair keyPair;
    keyPair.privateKey = serializePrivateKey(pairs);
    keyPair.publicKey = serializePublicKey(pairs);
    keyPair.address = deriveAddress(keyPair.publicKey);
    return keyPair;
}

std::string Wallet::deriveAddress(const std::string& publicKey) {
    const std::string digest = hashHex("address|" + publicKey);
    return digest.substr(0, 24);
}

std::string Wallet::signingPayload(const Transaction& transaction) {
    return transaction.sender + "|" +
           transaction.receiver + "|" +
           transaction.amountExpression + "|" +
           transaction.nonce + "|" +
           transaction.senderPublicKey;
}

bool Wallet::signTransaction(Transaction& transaction,
                             const std::string& privateKey,
                             std::string* error) {
    SecretPairs pairs;
    if (!parsePrivateKey(privateKey, pairs)) {
        if (error != nullptr) {
            *error = "Private key format is invalid.";
        }
        return false;
    }

    if (transaction.senderPublicKey.empty()) {
        if (error != nullptr) {
            *error = "Transaction senderPublicKey cannot be empty when signing.";
        }
        return false;
    }

    const std::array<uint8_t, kSignatureBits> bits = digestBits(signingPayload(transaction));
    std::array<std::string, kSignatureBits> selected{};

    for (size_t i = 0; i < kSignatureBits; i++) {
        selected[i] = pairs[i][bits[i] == 0 ? 0 : 1];
    }

    transaction.signature = serializeSignature(selected);

    if (error != nullptr) {
        error->clear();
    }
    return true;
}

bool Wallet::verifyTransactionSignature(const Transaction& transaction,
                                        std::string* error) {
    SecretPairs hashedPairs;
    if (!parsePublicKey(transaction.senderPublicKey, hashedPairs)) {
        if (error != nullptr) {
            *error = "Transaction senderPublicKey is invalid.";
        }
        return false;
    }

    std::array<std::string, kSignatureBits> values{};
    if (!parseSignature(transaction.signature, values)) {
        if (error != nullptr) {
            *error = "Transaction signature format is invalid.";
        }
        return false;
    }

    const std::array<uint8_t, kSignatureBits> bits = digestBits(signingPayload(transaction));

    for (size_t i = 0; i < kSignatureBits; i++) {
        const uint8_t bit = bits[i] == 0 ? 0 : 1;
        const std::string expected = hashedPairs[i][bit];
        if (hashHex(values[i]) != expected) {
            if (error != nullptr) {
                *error = "Transaction signature does not match sender public key and payload.";
            }
            return false;
        }
    }

    if (error != nullptr) {
        error->clear();
    }
    return true;
}

std::string Wallet::randomHex(const size_t bytes) {
    static thread_local std::mt19937_64 engine(std::random_device{}());
    std::uniform_int_distribution<uint32_t> distribution(0, 255);

    std::ostringstream out;
    out << std::hex;

    for (size_t i = 0; i < bytes; i++) {
        const uint32_t value = distribution(engine);
        out.width(2);
        out.fill('0');
        out << value;
    }

    return out.str();
}

std::string Wallet::hashHex(const std::string& text) {
    return LightweightCrypto::hashString(text);
}

std::array<uint8_t, Wallet::kSignatureBits> Wallet::digestBits(const std::string& payload) {
    const std::string digest = hashHex(payload);

    std::array<uint8_t, kSignatureBits> bits{};
    size_t bitIndex = 0;

    for (char ch : digest) {
        uint8_t nibble = 0;
        if (ch >= '0' && ch <= '9') {
            nibble = static_cast<uint8_t>(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            nibble = static_cast<uint8_t>(10 + ch - 'a');
        } else if (ch >= 'A' && ch <= 'F') {
            nibble = static_cast<uint8_t>(10 + ch - 'A');
        }

        for (int shift = 3; shift >= 0 && bitIndex < kSignatureBits; shift--) {
            bits[bitIndex++] = static_cast<uint8_t>((nibble >> shift) & 1U);
        }

        if (bitIndex >= kSignatureBits) {
            break;
        }
    }

    return bits;
}

std::string Wallet::serializePrivateKey(const SecretPairs& secretPairs) {
    std::ostringstream out;
    out << "wpriv1:";

    for (size_t i = 0; i < secretPairs.size(); i++) {
        if (i != 0) {
            out << ';';
        }
        out << secretPairs[i][0] << ',' << secretPairs[i][1];
    }

    return out.str();
}

std::string Wallet::serializePublicKey(const SecretPairs& secretPairs) {
    std::ostringstream out;
    out << "wpub1:";

    for (size_t i = 0; i < secretPairs.size(); i++) {
        if (i != 0) {
            out << ';';
        }
        out << hashHex(secretPairs[i][0]) << ',' << hashHex(secretPairs[i][1]);
    }

    return out.str();
}

bool Wallet::parsePrivateKey(const std::string& privateKey, SecretPairs& secretPairs) {
    constexpr const char* prefix = "wpriv1:";
    if (!privateKey.starts_with(prefix)) {
        return false;
    }

    const std::vector<std::string> rows = split(privateKey.substr(7), ';');
    if (rows.size() != kSignatureBits) {
        return false;
    }

    for (size_t i = 0; i < rows.size(); i++) {
        const std::vector<std::string> columns = split(rows[i], ',');
        if (columns.size() != 2 || columns[0].empty() || columns[1].empty()) {
            return false;
        }
        secretPairs[i][0] = columns[0];
        secretPairs[i][1] = columns[1];
    }

    return true;
}

bool Wallet::parsePublicKey(const std::string& publicKey, SecretPairs& hashedPairs) {
    constexpr const char* prefix = "wpub1:";
    if (!publicKey.starts_with(prefix)) {
        return false;
    }

    const std::vector<std::string> rows = split(publicKey.substr(6), ';');
    if (rows.size() != kSignatureBits) {
        return false;
    }

    for (size_t i = 0; i < rows.size(); i++) {
        const std::vector<std::string> columns = split(rows[i], ',');
        if (columns.size() != 2 || columns[0].empty() || columns[1].empty()) {
            return false;
        }
        hashedPairs[i][0] = columns[0];
        hashedPairs[i][1] = columns[1];
    }

    return true;
}

std::string Wallet::serializeSignature(const std::array<std::string, kSignatureBits>& values) {
    std::ostringstream out;
    out << "wsig1:";
    for (size_t i = 0; i < values.size(); i++) {
        if (i != 0) {
            out << ';';
        }
        out << values[i];
    }
    return out.str();
}

bool Wallet::parseSignature(const std::string& signature, std::array<std::string, kSignatureBits>& values) {
    constexpr const char* prefix = "wsig1:";
    if (!signature.starts_with(prefix)) {
        return false;
    }

    const std::vector<std::string> rows = split(signature.substr(6), ';');
    if (rows.size() != kSignatureBits) {
        return false;
    }

    for (size_t i = 0; i < rows.size(); i++) {
        if (rows[i].empty()) {
            return false;
        }
        values[i] = rows[i];
    }

    return true;
}
