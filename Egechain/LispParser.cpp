#include "LispParser.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

Bignum LispParser::parseAndEvaluate(const std::string& expression) {
    std::string trimmed = trim(expression);
    if (trimmed.empty()) {
        throw std::invalid_argument("Expression cannot be empty.");
    }

    if (trimmed.front() == '(' && trimmed.back() == ')') {
        trimmed = trim(trimmed.substr(1, trimmed.size() - 2));
    }

    return evaluate(trimmed);
}

std::string LispParser::trim(const std::string& text) {
    const size_t begin = text.find_first_not_of(" \t\n\r\f\v");
    if (begin == std::string::npos) {
        return "";
    }

    const size_t end = text.find_last_not_of(" \t\n\r\f\v");
    return text.substr(begin, end - begin + 1);
}

std::string LispParser::stripLeadingZeros(const std::string& number) {
    const size_t first = number.find_first_not_of('0');
    if (first == std::string::npos) {
        return "0";
    }
    return number.substr(first);
}

std::vector<std::string> LispParser::tokenize(const std::string& expression) {
    std::string expanded;
    expanded.reserve(expression.size() * 2);

    for (const char ch : expression) {
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
    }
    return tokens;
}

bool LispParser::isArithmeticOperation(const std::string& operation) {
    return operation == "+" || operation == "-" || operation == "*";
}

Bignum LispParser::evaluate(const std::string& expression) {
    const std::vector<std::string> tokens = tokenize(expression);
    if (tokens.empty()) {
        throw std::invalid_argument("Expression does not contain tokens.");
    }

    if (tokens[0] == "simplify") {
        return evaluateSimplify(tokens);
    }

    if (tokens[0] == "declare-const") {
        return evaluateDeclareConst(tokens);
    }

    if (isArithmeticOperation(tokens[0])) {
        return Bignum(evaluateSubExpression(tokens));
    }

    return resolveToken(tokens[0]);
}

Bignum LispParser::evaluateSimplify(const std::vector<std::string>& tokens) {
    std::vector<std::string> stack;

    for (const std::string& token : tokens) {
        if (token == ")") {
            std::vector<std::string> subExpression;
            while (!stack.empty() && stack.back() != "(") {
                subExpression.push_back(stack.back());
                stack.pop_back();
            }

            if (stack.empty()) {
                throw std::invalid_argument("Mismatched parentheses in simplify expression.");
            }

            stack.pop_back();
            std::reverse(subExpression.begin(), subExpression.end());

            const std::string result = evaluateSubExpression(subExpression);
            stack.push_back(result);
        } else {
            stack.push_back(token);
        }
    }

    if (stack.empty()) {
        throw std::invalid_argument("Unable to evaluate simplify expression.");
    }

    return resolveToken(stack.back());
}

Bignum LispParser::evaluateDeclareConst(const std::vector<std::string>& tokens) {
    if (tokens.size() < 3) {
        throw std::invalid_argument("declare-const expects a name and a value.");
    }

    const Bignum value = resolveToken(tokens[2]);
    symbolTable.insert_or_assign(tokens[1], value);
    return value;
}

std::string LispParser::evaluateSubExpression(const std::vector<std::string>& subExpression) {
    if (subExpression.empty()) {
        throw std::invalid_argument("Sub-expression is empty.");
    }

    const std::string operation = subExpression[0];

    if (operation == "declare-const") {
        if (subExpression.size() < 3) {
            throw std::invalid_argument("declare-const sub-expression expects a name and a value.");
        }

        const Bignum tower = resolveToken(subExpression[2]);
        symbolTable.insert_or_assign(subExpression[1], tower);
        return tower.toSignedDecimalString();
    }

    if (operation == "simplify") {
        if (subExpression.size() == 1) {
            throw std::invalid_argument("simplify sub-expression requires at least one operand.");
        }

        if (subExpression.size() == 2) {
            return resolveToken(subExpression[1]).toSignedDecimalString();
        }

        std::string nestedExpression;
        for (size_t i = 1; i < subExpression.size(); i++) {
            if (!nestedExpression.empty()) {
                nestedExpression.push_back(' ');
            }
            nestedExpression += subExpression[i];
        }
        return parseAndEvaluate(nestedExpression).toSignedDecimalString();
    }

    if (!isArithmeticOperation(operation)) {
        throw std::runtime_error("Unsupported expression in " + operation);
    }

    if (subExpression.size() < 2) {
        throw std::invalid_argument("Arithmetic operation requires at least one operand.");
    }

    Bignum result = resolveToken(subExpression[1]);
    for (size_t i = 2; i < subExpression.size(); i++) {
        const Bignum next = resolveToken(subExpression[i]);

        if (operation == "+") {
            result = Bignum::bignumAdd(result, next);
        } else if (operation == "-") {
            result = Bignum::bignumAdd(result, next.flipSign());
        } else {
            result = multiply(result, next);
        }
    }

    return result.toSignedDecimalString();
}

Bignum LispParser::resolveToken(const std::string& token) const {
    const auto it = symbolTable.find(token);
    if (it != symbolTable.end()) {
        return it->second;
    }
    return Bignum(token);
}

std::string LispParser::multiplyUnsignedDecimal(const std::string& left, const std::string& right) {
    if (left == "0" || right == "0") {
        return "0";
    }

    std::vector<int> digits(left.size() + right.size(), 0);

    for (int i = static_cast<int>(left.size()) - 1; i >= 0; i--) {
        for (int j = static_cast<int>(right.size()) - 1; j >= 0; j--) {
            const int product = (left[static_cast<size_t>(i)] - '0') *
                                (right[static_cast<size_t>(j)] - '0') +
                                digits[static_cast<size_t>(i + j + 1)];

            digits[static_cast<size_t>(i + j + 1)] = product % 10;
            digits[static_cast<size_t>(i + j)] += product / 10;
        }
    }

    std::string result;
    result.reserve(digits.size());

    size_t index = 0;
    while (index < digits.size() && digits[index] == 0) {
        index++;
    }

    while (index < digits.size()) {
        result.push_back(static_cast<char>('0' + digits[index]));
        index++;
    }

    return result.empty() ? "0" : result;
}

std::string LispParser::multiplySignedDecimal(std::string left, std::string right) {
    bool leftNegative = false;
    bool rightNegative = false;

    if (!left.empty() && left[0] == '-') {
        leftNegative = true;
        left = left.substr(1);
    }

    if (!right.empty() && right[0] == '-') {
        rightNegative = true;
        right = right.substr(1);
    }

    left = stripLeadingZeros(left);
    right = stripLeadingZeros(right);

    const std::string magnitude = multiplyUnsignedDecimal(left, right);
    if (magnitude == "0") {
        return "0";
    }

    const bool negative = leftNegative ^ rightNegative;
    return negative ? "-" + magnitude : magnitude;
}

Bignum LispParser::multiply(const Bignum& b1, const Bignum& b2) {
    const std::string product = multiplySignedDecimal(b1.toSignedDecimalString(), b2.toSignedDecimalString());
    return Bignum(product);
}