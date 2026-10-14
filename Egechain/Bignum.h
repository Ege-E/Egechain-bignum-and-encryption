#pragma once

#include <array>
#include <cstdint>
#include <string>

class Bignum {
public:
    explicit Bignum(std::string actualNumber);

    [[nodiscard]] std::string toHexString() const;
    Bignum& zeroNum(Bignum& b) const;
    Bignum& assignLSWord(int32_t a, Bignum& b) const;
    [[nodiscard]] bool thisIsZero(const Bignum& b) const;
    [[nodiscard]] Bignum leftShift(int a, const Bignum& b) const;

    static int32_t add32bit(int32_t a, int32_t b);
    static Bignum bignumAdd(const Bignum& a, const Bignum& b);
    static int32_t subtract(int32_t a, int32_t b);

    [[nodiscard]] int compareInt32(int32_t a, int32_t b) const;
    void bignum_divide_by_uint32(const Bignum& numerator, uint32_t divisor, Bignum& quotient, uint32_t& remainder) const;
    void bignum_print_decimal(const Bignum& x) const;

    [[nodiscard]] Bignum flipSign() const;
    [[nodiscard]] std::string returnsStringValue() const;
    [[nodiscard]] std::string toSignedDecimalString() const;

private:
    static std::string normalizeUnsignedDecimal(std::string number);
    static bool allZero(const std::array<int32_t, 4>& words);
    static std::string multiplyDecimalBy2(const std::string& number);
    static std::string addUnsignedDecimal(const std::string& a, const std::string& b);
    static int compareUnsignedDecimal(const std::string& a, const std::string& b);
    static std::string subtractUnsignedDecimal(const std::string& a, const std::string& b);
    static std::string addSignedDecimal(const std::string& a, const std::string& b);
    static std::string binaryToDecimal(const std::string& bits);
    static std::string binaryToHex(std::string bits);
    static std::string wordsToDecimal(const std::array<int32_t, 4>& words);

    void refreshStateFromWords();

    std::array<int32_t, 4> value{};
    std::string neededForSum;
    bool neg = false;
    bool isZero = false;
    bool Paulson = false;
    int TARP = 0;
    int size = 0;
};