#pragma once

#include "Bignum.h"

#include <string>
#include <unordered_map>
#include <vector>

class LispParser {
public:
    Bignum parseAndEvaluate(const std::string& expression);

private:
    static std::string trim(const std::string& text);
    static std::string stripLeadingZeros(const std::string& number);
    static std::vector<std::string> tokenize(const std::string& expression);
    static bool isArithmeticOperation(const std::string& operation);

    Bignum evaluate(const std::string& expression);
    Bignum evaluateSimplify(const std::vector<std::string>& tokens);
    Bignum evaluateDeclareConst(const std::vector<std::string>& tokens);
    std::string evaluateSubExpression(const std::vector<std::string>& subExpression);
    Bignum resolveToken(const std::string& token) const;

    static std::string multiplyUnsignedDecimal(const std::string& left, const std::string& right);
    static std::string multiplySignedDecimal(std::string left, std::string right);
    static Bignum multiply(const Bignum& b1, const Bignum& b2);

    std::unordered_map<std::string, Bignum> symbolTable;
};