#include "LightweightCrypto.h"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

namespace {
uint64_t randomNonce() {
    static thread_local std::mt19937_64 engine(std::random_device{}());
    std::uniform_int_distribution<uint64_t> distribution;
    return distribution(engine);
}

uint8_t roundKeyByte(uint64_t nonce, uint32_t round, size_t index) {
    const uint8_t fromNonce = static_cast<uint8_t>((nonce >> (((index + round) % 8U) * 8U)) & 0xFFU);
    const uint8_t mixed = static_cast<uint8_t>((round + 1U) * 31U + (index % 251U));
    return static_cast<uint8_t>(fromNonce ^ mixed);
}

uint8_t roundShift(uint64_t nonce, uint32_t round, size_t index) {
    const uint8_t raw = static_cast<uint8_t>((nonce >> (((round + index) % 8U) * 8U)) & 0x07U);
    return static_cast<uint8_t>(raw + 1U);
}
}

LightweightCrypto::LightweightCrypto(HashEncryptionProfile profile)
    : profile_(std::move(profile)) {
    if (profile_.rounds == 0) {
        profile_.rounds = 1;
    }
    if (profile_.phases.empty()) {
        profile_.phases.push_back(HashEncryptionPhase::XorWithNonce);
    }
}

std::string LightweightCrypto::hashString(const std::string& text) {
    const uint64_t h1 = fnv1a64(text, 14695981039346656037ULL);

    std::string reversed = text;
    std::reverse(reversed.begin(), reversed.end());
    const uint64_t h2 = fnv1a64(reversed, 1099511628211ULL ^ 0xA5A5A5A5A5A5A5A5ULL);

    return toHex(h1, 16) + toHex(h2, 16);
}

std::string LightweightCrypto::encryptHash(const std::string& hashText) const {
    if (hashText.empty()) {
        throw std::invalid_argument("Hash text cannot be empty.");
    }

    const uint64_t nonce = randomNonce();
    const std::vector<uint8_t> input(hashText.begin(), hashText.end());
    const std::vector<uint8_t> encrypted = runForward(input, nonce, profile_.rounds, profile_.phases);

    std::ostringstream payload;
    payload << "v1:"
            << toHex(nonce, 16) << ":"
            << profile_.rounds << ":"
            << phasesToString(profile_.phases) << ":"
            << bytesToHex(encrypted);
    return payload.str();
}

std::string LightweightCrypto::decryptHash(const std::string& payload) const {
    const std::vector<std::string> pieces = split(payload, ':');
    if (pieces.size() != 5 || pieces[0] != "v1") {
        throw std::invalid_argument("Encrypted payload format is invalid.");
    }

    const uint64_t nonce = std::stoull(pieces[1], nullptr, 16);
    const uint32_t rounds = static_cast<uint32_t>(std::stoul(pieces[2]));
    const std::vector<HashEncryptionPhase> phases = parsePhases(pieces[3]);
    const std::vector<uint8_t> encrypted = hexToBytes(pieces[4]);

    const std::vector<uint8_t> restored = runBackward(encrypted, nonce, rounds, phases);
    return std::string(restored.begin(), restored.end());
}

void LightweightCrypto::setProfile(HashEncryptionProfile profile) {
    if (profile.rounds == 0) {
        profile.rounds = 1;
    }
    if (profile.phases.empty()) {
        profile.phases.push_back(HashEncryptionPhase::XorWithNonce);
    }
    profile_ = std::move(profile);
}

void LightweightCrypto::addPhase(HashEncryptionPhase phase) {
    profile_.phases.push_back(phase);
}

const HashEncryptionProfile& LightweightCrypto::profile() const {
    return profile_;
}

uint64_t LightweightCrypto::fnv1a64(const std::string& text, uint64_t offsetBasis) {
    constexpr uint64_t prime = 1099511628211ULL;
    uint64_t hash = offsetBasis;
    for (const unsigned char ch : text) {
        hash ^= static_cast<uint64_t>(ch);
        hash *= prime;
    }
    return hash;
}

std::string LightweightCrypto::toHex(uint64_t value, size_t width) {
    std::ostringstream out;
    out << std::hex << std::nouppercase << std::setw(static_cast<int>(width)) << std::setfill('0') << value;
    return out.str();
}

std::string LightweightCrypto::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream out;
    out << std::hex << std::nouppercase << std::setfill('0');
    for (const uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<int>(byte);
    }
    return out.str();
}

std::vector<uint8_t> LightweightCrypto::hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hex payload length must be even.");
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        const std::string byteText = hex.substr(i, 2);
        bytes.push_back(static_cast<uint8_t>(std::stoul(byteText, nullptr, 16)));
    }

    return bytes;
}

std::vector<std::string> LightweightCrypto::split(const std::string& text, char delimiter) {
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

uint8_t LightweightCrypto::rotateLeft(uint8_t value, uint8_t shift) {
    const uint8_t normalized = static_cast<uint8_t>(shift % 8U);
    if (normalized == 0) {
        return value;
    }
    return static_cast<uint8_t>((value << normalized) | (value >> (8U - normalized)));
}

uint8_t LightweightCrypto::rotateRight(uint8_t value, uint8_t shift) {
    const uint8_t normalized = static_cast<uint8_t>(shift % 8U);
    if (normalized == 0) {
        return value;
    }
    return static_cast<uint8_t>((value >> normalized) | (value << (8U - normalized)));
}

std::string LightweightCrypto::phasesToString(const std::vector<HashEncryptionPhase>& phases) {
    std::ostringstream out;
    for (size_t i = 0; i < phases.size(); i++) {
        if (i != 0) {
            out << ',';
        }
        out << static_cast<int>(phases[i]);
    }
    return out.str();
}

std::vector<HashEncryptionPhase> LightweightCrypto::parsePhases(const std::string& text) {
    std::vector<HashEncryptionPhase> phases;
    std::istringstream stream(text);
    std::string token;
    while (std::getline(stream, token, ',')) {
        if (token.empty()) {
            continue;
        }

        const int code = std::stoi(token);
        switch (code) {
            case 0:
                phases.push_back(HashEncryptionPhase::XorWithNonce);
                break;
            case 1:
                phases.push_back(HashEncryptionPhase::RotateBits);
                break;
            case 2:
                phases.push_back(HashEncryptionPhase::SwapNibbles);
                break;
            case 3:
                phases.push_back(HashEncryptionPhase::ReverseBytes);
                break;
            default:
                throw std::invalid_argument("Unknown encryption phase code.");
        }
    }

    if (phases.empty()) {
        throw std::invalid_argument("Encryption phase list is empty.");
    }

    return phases;
}

std::vector<uint8_t> LightweightCrypto::runForward(const std::vector<uint8_t>& input,
                                                   uint64_t nonce,
                                                   uint32_t rounds,
                                                   const std::vector<HashEncryptionPhase>& phases) const {
    std::vector<uint8_t> state = input;

    for (uint32_t round = 0; round < rounds; round++) {
        for (const HashEncryptionPhase phase : phases) {
            if (phase == HashEncryptionPhase::XorWithNonce) {
                for (size_t i = 0; i < state.size(); i++) {
                    state[i] ^= roundKeyByte(nonce, round, i);
                }
            } else if (phase == HashEncryptionPhase::RotateBits) {
                for (size_t i = 0; i < state.size(); i++) {
                    state[i] = rotateLeft(state[i], roundShift(nonce, round, i));
                }
            } else if (phase == HashEncryptionPhase::SwapNibbles) {
                for (uint8_t& byte : state) {
                    byte = static_cast<uint8_t>((byte << 4U) | (byte >> 4U));
                }
            } else {
                std::reverse(state.begin(), state.end());
            }
        }
    }

    return state;
}

std::vector<uint8_t> LightweightCrypto::runBackward(const std::vector<uint8_t>& input,
                                                    uint64_t nonce,
                                                    uint32_t rounds,
                                                    const std::vector<HashEncryptionPhase>& phases) const {
    std::vector<uint8_t> state = input;

    for (uint32_t round = rounds; round > 0; round--) {
        const uint32_t currentRound = round - 1;
        for (auto it = phases.rbegin(); it != phases.rend(); ++it) {
            const HashEncryptionPhase phase = *it;

            if (phase == HashEncryptionPhase::XorWithNonce) {
                for (size_t i = 0; i < state.size(); i++) {
                    state[i] ^= roundKeyByte(nonce, currentRound, i);
                }
            } else if (phase == HashEncryptionPhase::RotateBits) {
                for (size_t i = 0; i < state.size(); i++) {
                    state[i] = rotateRight(state[i], roundShift(nonce, currentRound, i));
                }
            } else if (phase == HashEncryptionPhase::SwapNibbles) {
                for (uint8_t& byte : state) {
                    byte = static_cast<uint8_t>((byte << 4U) | (byte >> 4U));
                }
            } else {
                std::reverse(state.begin(), state.end());
            }
        }
    }

    return state;
}