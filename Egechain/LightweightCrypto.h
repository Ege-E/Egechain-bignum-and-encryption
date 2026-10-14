#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class HashEncryptionPhase : uint8_t {
    XorWithNonce = 0,
    RotateBits = 1,
    SwapNibbles = 2,
    ReverseBytes = 3
};

struct HashEncryptionProfile {
    uint32_t rounds = 2;
    std::vector<HashEncryptionPhase> phases{
        HashEncryptionPhase::XorWithNonce,
        HashEncryptionPhase::RotateBits,
        HashEncryptionPhase::SwapNibbles
    };
};

class LightweightCrypto {
public:
    explicit LightweightCrypto(HashEncryptionProfile profile = {});

    [[nodiscard]] static std::string hashString(const std::string& text);
    [[nodiscard]] std::string encryptHash(const std::string& hashText) const;
    [[nodiscard]] std::string decryptHash(const std::string& payload) const;

    void setProfile(HashEncryptionProfile profile);
    void addPhase(HashEncryptionPhase phase);
    [[nodiscard]] const HashEncryptionProfile& profile() const;

private:
    static uint64_t fnv1a64(const std::string& text, uint64_t offsetBasis);
    static std::string toHex(uint64_t value, size_t width);
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> hexToBytes(const std::string& hex);
    static std::vector<std::string> split(const std::string& text, char delimiter);
    static uint8_t rotateLeft(uint8_t value, uint8_t shift);
    static uint8_t rotateRight(uint8_t value, uint8_t shift);
    static std::string phasesToString(const std::vector<HashEncryptionPhase>& phases);
    static std::vector<HashEncryptionPhase> parsePhases(const std::string& text);

    [[nodiscard]] std::vector<uint8_t> runForward(const std::vector<uint8_t>& input,
                                                  uint64_t nonce,
                                                  uint32_t rounds,
                                                  const std::vector<HashEncryptionPhase>& phases) const;
    [[nodiscard]] std::vector<uint8_t> runBackward(const std::vector<uint8_t>& input,
                                                   uint64_t nonce,
                                                   uint32_t rounds,
                                                   const std::vector<HashEncryptionPhase>& phases) const;

    HashEncryptionProfile profile_;
};