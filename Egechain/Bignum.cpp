#include "Bignum.h"

#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>

Bignum::Bignum(std::string actualNumber) {
    neededForSum = actualNumber;

    if (!actualNumber.empty() && actualNumber[0] == '-') {
        neg = true;
        actualNumber = neededForSum.substr(1);
        neededForSum = actualNumber;
    }

    value.fill(0);

    actualNumber = normalizeUnsignedDecimal(actualNumber.empty() ? "0" : actualNumber);

    isZero = (actualNumber == "0");

    if (actualNumber.length() > 36) {
        Paulson = true;
        TARP = static_cast<int>(actualNumber.length()) - 36;
        actualNumber = actualNumber.substr(0, 36);
    }

    neededForSum = actualNumber;
    size = static_cast<int>(actualNumber.length());

    if (isZero) {
        value.fill(0);
        neededForSum = "0";
        size = 1;
    } else {
        try {
            int delimiter = size;
            int arrayIndex = 1;

            std::string ege;

            while (delimiter >= 10) {
                ege = actualNumber.substr(delimiter - 10, 10);

                if (ege <= "2147483647") {
                    if (ege[0] != '0') {
                        delimiter = delimiter - 10;
                    } else {
                        ege = actualNumber.substr(delimiter - 9, 9);
                        delimiter = delimiter - 9;
                    }
                } else {
                    if (ege[0] != '0') {
                        ege = actualNumber.substr(delimiter - 9, 9);
                        delimiter = delimiter - 9;
                    } else {
                        ege = actualNumber.substr(delimiter - 8, 8);
                        delimiter = delimiter - 8;
                    }
                }

                value.at(arrayIndex) = std::stoi(ege);
                arrayIndex++;
            }

            if (delimiter > 0) {
                ege = actualNumber.substr(0, delimiter);
                value[0] = std::stoi(ege);
            } else {
                value[0] = 0;
            }
        } catch (const std::out_of_range&) {
            std::cout << "This number is too big to be represented as a single bignum." << std::endl;
            throw;
        }

        if (neg) {
            for (int i = 0; i < 4; i++) {
                if (value[i] != 0) {
                    value[i] = add32bit(~value[i], 1);
                }
            }
        }
    }
}

std::string Bignum::toHexString() const {
    std::ostringstream hexString;
    hexString << std::hex << std::nouppercase;

    for (int i = static_cast<int>(value.size()) - 1; i >= 0; i--) {
        const auto chunk = static_cast<uint32_t>(value[i]);
        hexString << std::setw(8) << std::setfill('0') << chunk;
    }

    return hexString.str();
}

Bignum& Bignum::zeroNum(Bignum& b) const {
    for (int i = 0; i < 4; i++) {
        b.value[i] = 0;
    }
    b.neg = false;
    b.isZero = true;
    b.Paulson = false;
    b.TARP = 0;
    b.size = 1;
    b.neededForSum = "0";
    return b;
}

Bignum& Bignum::assignLSWord(const int32_t a, Bignum& b) const {
    std::cout << "Hexadecimal value before:" << b.toHexString() << std::endl;
    b.value[0] = a;
    b.refreshStateFromWords();
    std::cout << "Hexadecimal value after:" << b.toHexString() << std::endl;
    return b;
}

bool Bignum::thisIsZero(const Bignum& b) const {
    return b.isZero;
}

Bignum Bignum::leftShift(const int a, const Bignum& b) const {
    int shift = a;

    if (a > 128) {
        shift = a % 128;
    } else if (a == 128) {
        return b;
    }

    if (shift < 0) {
        throw std::invalid_argument("Shift must be non-negative.");
    }

    std::string binString;
    binString.reserve(128 + static_cast<size_t>(shift));

    for (int i = static_cast<int>(b.value.size()) - 1; i >= 0; i--) {
        const uint32_t chunk = static_cast<uint32_t>(b.value[i]);
        for (int bit = 31; bit >= 0; bit--) {
            binString.push_back(((chunk >> bit) & 1U) ? '1' : '0');
        }
    }

    binString.append(static_cast<size_t>(shift), '0');

    std::cout << "The binary number: " << binString << std::endl;
    std::cout << "The hexadecimal number: " << std::endl;

    const std::string hexString = binaryToHex(binString);
    std::cout << hexString << std::endl;

    return Bignum(binaryToDecimal(binString));
}

int32_t Bignum::add32bit(const int32_t a, const int32_t b) {
    if (a > 0 && b > 0 && a > std::numeric_limits<int32_t>::max() - b) {
        throw std::overflow_error("Integer overflow: the sum exceeds Integer.MAX_VALUE");
    }

    uint32_t ua = static_cast<uint32_t>(a);
    uint32_t ub = static_cast<uint32_t>(b);

    while (ub != 0) {
        const uint32_t carry = ua & ub;
        ua = ua ^ ub;
        ub = carry << 1;
    }

    return static_cast<int32_t>(ua);
}

Bignum Bignum::bignumAdd(const Bignum& a, const Bignum& b) {
    Bignum ans("0");

    try {
        if (a.Paulson) {
            if (b.size < a.TARP) {
                return a;
            }
        }

        if (b.Paulson) {
            if (a.size < b.TARP) {
                return b;
            }
        }

        if (a.Paulson && b.Paulson) {
            if (a.TARP > b.TARP) {
                if (a.TARP - b.TARP >= 36) {
                    return a;
                }

                const int Tdif = a.TARP - b.TARP;
                const std::string aValue = a.returnsStringValue();
                if (Tdif >= static_cast<int>(aValue.size())) {
                    return a;
                }

                Bignum interim(aValue.substr(static_cast<size_t>(Tdif), 36));
                Bignum c = bignumAdd(interim, b);

                ans = bignumAdd(a, c);
                ans.Paulson = true;
                ans.TARP = a.TARP;
                return ans;
            }

            if (a.TARP < b.TARP) {
                if (b.TARP - a.TARP >= 36) {
                    return b;
                }

                const int Tdif = b.TARP - a.TARP;
                const std::string bValue = b.returnsStringValue();
                if (Tdif >= static_cast<int>(bValue.size())) {
                    return b;
                }

                Bignum interim(bValue.substr(static_cast<size_t>(Tdif), 36));
                Bignum c = bignumAdd(interim, a);

                ans = bignumAdd(b, c);
                ans.Paulson = true;
                ans.TARP = b.TARP;
                return ans;
            }
        }

        const std::string signedA = a.neg ? "-" + a.returnsStringValue() : a.returnsStringValue();
        const std::string signedB = b.neg ? "-" + b.returnsStringValue() : b.returnsStringValue();
        return Bignum(addSignedDecimal(signedA, signedB));
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return ans;
}

int32_t Bignum::subtract(const int32_t a, const int32_t b) {
    int32_t result = 0;
    int32_t borrow = 0;

    for (int i = 0; i < 32; i++) {
        const int32_t a_bit = (a >> i) & 1;
        const int32_t b_bit = (b >> i) & 1;

        const int32_t diff_bit = a_bit ^ b_bit ^ borrow;
        const int32_t borrow_out = (~a_bit & b_bit) | ((~a_bit | b_bit) & borrow);

        result |= (diff_bit << i);
        borrow = borrow_out;
    }

    return result;
}

int Bignum::compareInt32(const int32_t a, const int32_t b) const {
    const uint64_t ua = static_cast<uint32_t>(a);
    const uint64_t ub = static_cast<uint32_t>(b);

    uint64_t borrow = 0;

    for (int i = 0; i < 32; i++) {
        const uint64_t bitA = (ua >> i) & 1ULL;
        const uint64_t bitB = (ub >> i) & 1ULL;

        borrow = (~bitA & bitB) | ((~bitA | bitB) & borrow);

        if (borrow == 1) {
            return -1;
        }
    }

    return 1;
}

void Bignum::bignum_divide_by_uint32(const Bignum& numerator, const uint32_t divisor, Bignum& quotient, uint32_t& remainder) const {
    if (divisor == 0) {
        throw std::invalid_argument("Divisor cannot be zero.");
    }

    remainder = 0;
    quotient.value.fill(0);

    for (int i = 3; i >= 0; i--) {
        const uint64_t current = (static_cast<uint64_t>(remainder) << 32) |
                                 static_cast<uint32_t>(numerator.value[i]);
        quotient.value[i] = static_cast<int32_t>(current / divisor);
        remainder = static_cast<uint32_t>(current % divisor);
    }

    quotient.neg = false;
    quotient.refreshStateFromWords();
}

void Bignum::bignum_print_decimal(const Bignum& x) const {
    Bignum copy = x;
    copy.neg = false;
    copy.isZero = allZero(copy.value);

    std::string digits;
    uint32_t remainder = 0;

    while (!copy.isZero) {
        Bignum quotient("0");
        bignum_divide_by_uint32(copy, 10, quotient, remainder);
        digits.push_back(static_cast<char>('0' + remainder));
        copy = quotient;
        copy.isZero = allZero(copy.value);
    }

    if (digits.empty()) {
        std::cout << '0';
        return;
    }

    if (x.neg) {
        std::cout << '-';
    }

    std::cout << std::string(digits.rbegin(), digits.rend());
}

Bignum Bignum::flipSign() const {
    const std::string s = returnsStringValue();
    if (neg) {
        return Bignum(s);
    }
    return Bignum("-" + s);
}

std::string Bignum::returnsStringValue() const {
    if (neededForSum.empty()) {
        return wordsToDecimal(value);
    }
    return normalizeUnsignedDecimal(neededForSum);
}

std::string Bignum::toSignedDecimalString() const {
    const std::string magnitude = returnsStringValue();
    if (neg && magnitude != "0") {
        return "-" + magnitude;
    }
    return magnitude;
}

std::string Bignum::normalizeUnsignedDecimal(std::string number) {
    if (number.empty()) {
        return "0";
    }

    const size_t firstNonZero = number.find_first_not_of('0');
    if (firstNonZero == std::string::npos) {
        return "0";
    }
    return number.substr(firstNonZero);
}

bool Bignum::allZero(const std::array<int32_t, 4>& words) {
    for (const auto word : words) {
        if (word != 0) {
            return false;
        }
    }
    return true;
}

std::string Bignum::multiplyDecimalBy2(const std::string& number) {
    std::string result;
    result.reserve(number.size() + 1);

    int carry = 0;
    for (int i = static_cast<int>(number.size()) - 1; i >= 0; i--) {
        const int digit = number[static_cast<size_t>(i)] - '0';
        const int doubled = digit * 2 + carry;
        result.push_back(static_cast<char>('0' + (doubled % 10)));
        carry = doubled / 10;
    }

    if (carry > 0) {
        result.push_back(static_cast<char>('0' + carry));
    }

    return std::string(result.rbegin(), result.rend());
}

std::string Bignum::addUnsignedDecimal(const std::string& a, const std::string& b) {
    std::string result;
    result.reserve((a.size() > b.size() ? a.size() : b.size()) + 1);

    int i = static_cast<int>(a.size()) - 1;
    int j = static_cast<int>(b.size()) - 1;
    int carry = 0;

    while (i >= 0 || j >= 0 || carry > 0) {
        const int da = (i >= 0) ? (a[static_cast<size_t>(i)] - '0') : 0;
        const int db = (j >= 0) ? (b[static_cast<size_t>(j)] - '0') : 0;
        const int sum = da + db + carry;

        result.push_back(static_cast<char>('0' + (sum % 10)));
        carry = sum / 10;
        i--;
        j--;
    }

    return normalizeUnsignedDecimal(std::string(result.rbegin(), result.rend()));
}

int Bignum::compareUnsignedDecimal(const std::string& a, const std::string& b) {
    const std::string na = normalizeUnsignedDecimal(a);
    const std::string nb = normalizeUnsignedDecimal(b);

    if (na.size() < nb.size()) {
        return -1;
    }
    if (na.size() > nb.size()) {
        return 1;
    }
    if (na < nb) {
        return -1;
    }
    if (na > nb) {
        return 1;
    }
    return 0;
}

std::string Bignum::subtractUnsignedDecimal(const std::string& a, const std::string& b) {
    // precondition: a >= b
    std::string result;
    result.reserve(a.size());

    int i = static_cast<int>(a.size()) - 1;
    int j = static_cast<int>(b.size()) - 1;
    int borrow = 0;

    while (i >= 0) {
        int da = (a[static_cast<size_t>(i)] - '0') - borrow;
        const int db = (j >= 0) ? (b[static_cast<size_t>(j)] - '0') : 0;

        if (da < db) {
            da += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }

        const int diff = da - db;
        result.push_back(static_cast<char>('0' + diff));
        i--;
        j--;
    }

    return normalizeUnsignedDecimal(std::string(result.rbegin(), result.rend()));
}

std::string Bignum::addSignedDecimal(const std::string& a, const std::string& b) {
    bool negA = false;
    bool negB = false;
    std::string magA = a;
    std::string magB = b;

    if (!magA.empty() && magA[0] == '-') {
        negA = true;
        magA = magA.substr(1);
    }
    if (!magB.empty() && magB[0] == '-') {
        negB = true;
        magB = magB.substr(1);
    }

    magA = normalizeUnsignedDecimal(magA);
    magB = normalizeUnsignedDecimal(magB);

    if (negA == negB) {
        const std::string sum = addUnsignedDecimal(magA, magB);
        if (sum == "0") {
            return "0";
        }
        return negA ? "-" + sum : sum;
    }

    const int cmp = compareUnsignedDecimal(magA, magB);
    if (cmp == 0) {
        return "0";
    }

    if (cmp > 0) {
        const std::string diff = subtractUnsignedDecimal(magA, magB);
        return negA ? "-" + diff : diff;
    }

    const std::string diff = subtractUnsignedDecimal(magB, magA);
    return negB ? "-" + diff : diff;
}

std::string Bignum::binaryToDecimal(const std::string& bits) {
    std::string result = "0";

    for (const char bit : bits) {
        if (bit != '0' && bit != '1') {
            throw std::invalid_argument("Binary input contains invalid character.");
        }

        result = multiplyDecimalBy2(result);
        if (bit == '1') {
            result = addUnsignedDecimal(result, "1");
        }
    }

    return normalizeUnsignedDecimal(result);
}

std::string Bignum::binaryToHex(std::string bits) {
    const size_t firstOne = bits.find('1');
    if (firstOne == std::string::npos) {
        return "0";
    }

    bits = bits.substr(firstOne);

    const size_t rem = bits.size() % 4;
    if (rem != 0) {
        bits = std::string(4 - rem, '0') + bits;
    }

    std::string hex;
    hex.reserve(bits.size() / 4);

    for (size_t i = 0; i < bits.size(); i += 4) {
        int valueOfNibble = 0;
        for (size_t j = 0; j < 4; j++) {
            valueOfNibble = (valueOfNibble << 1) + (bits[i + j] - '0');
        }

        if (valueOfNibble < 10) {
            hex.push_back(static_cast<char>('0' + valueOfNibble));
        } else {
            hex.push_back(static_cast<char>('a' + (valueOfNibble - 10)));
        }
    }

    return hex;
}

std::string Bignum::wordsToDecimal(const std::array<int32_t, 4>& words) {
    unsigned __int128 value128 = 0;
    for (int i = static_cast<int>(words.size()) - 1; i >= 0; i--) {
        value128 = (value128 << 32) | static_cast<uint32_t>(words[i]);
    }

    if (value128 == 0) {
        return "0";
    }

    std::string digits;
    while (value128 > 0) {
        const uint32_t digit = static_cast<uint32_t>(value128 % 10);
        digits.push_back(static_cast<char>('0' + digit));
        value128 /= 10;
    }

    return std::string(digits.rbegin(), digits.rend());
}

void Bignum::refreshStateFromWords() {
    isZero = allZero(value);

    if (isZero) {
        neededForSum = "0";
        size = 1;
        Paulson = false;
        TARP = 0;
        neg = false;
        return;
    }

    neededForSum = wordsToDecimal(value);
    size = static_cast<int>(neededForSum.size());

    if (size > 36) {
        Paulson = true;
        TARP = size - 36;
        neededForSum = neededForSum.substr(0, 36);
        size = 36;
    } else {
        Paulson = false;
        TARP = 0;
    }

    neg = false;
}