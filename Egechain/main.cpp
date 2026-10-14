#include "Block.h"
#include "LightweightCrypto.h"
#include "LispParser.h"

#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

static void runSelfChecks() {
    Bignum helper("1");
    Bignum target("12345");

    helper.zeroNum(target);
    assert(helper.thisIsZero(target));
    assert(target.toHexString() == "00000000000000000000000000000000");

    helper.assignLSWord(42, target);
    assert(target.toHexString().substr(24) == "0000002a");

    assert(Bignum::add32bit(-1, 1) == 0);
    assert(Bignum::subtract(10, 3) == 7);
    assert(helper.compareInt32(3, 4) == -1);

    const Bignum sum = Bignum::bignumAdd(Bignum("123"), Bignum("456"));
    assert(sum.returnsStringValue() == "579");

    const Bignum shifted = helper.leftShift(128, Bignum("7"));
    assert(shifted.toHexString() == Bignum("7").toHexString());

    uint32_t remainder = 0;
    Bignum quotient("0");
    helper.bignum_divide_by_uint32(Bignum("100"), 10, quotient, remainder);
    assert(remainder == 0);
    assert(quotient.returnsStringValue() == "10");

    bool threw = false;
    try {
        helper.bignum_divide_by_uint32(Bignum("10"), 0, quotient, remainder);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    assert(threw);

    std::ostringstream printed;
    std::streambuf* oldBuffer = std::cout.rdbuf(printed.rdbuf());
    helper.bignum_print_decimal(Bignum("123"));
    std::cout.rdbuf(oldBuffer);
    assert(printed.str() == "123");

    const Bignum flipped = Bignum("5").flipSign();
    const Bignum unflipped = flipped.flipSign();
    assert(unflipped.returnsStringValue() == "5");

    LispParser parser;
    assert(parser.parseAndEvaluate("(declare-const tower 123)").toSignedDecimalString() == "123");
    assert(parser.parseAndEvaluate("(simplify (+ tower 7))").toSignedDecimalString() == "130");
    assert(parser.parseAndEvaluate("(simplify (- 30 5 4))").toSignedDecimalString() == "21");
    assert(parser.parseAndEvaluate("(simplify (* -12 7))").toSignedDecimalString() == "-84");

    LightweightCrypto crypto;
    const std::string digest = LightweightCrypto::hashString("alice|bob|12");
    assert(!digest.empty());

    const std::string encryptedDigestA = crypto.encryptHash(digest);
    const std::string encryptedDigestB = crypto.encryptHash(digest);
    assert(encryptedDigestA != encryptedDigestB);
    assert(crypto.decryptHash(encryptedDigestA) == digest);
    assert(crypto.decryptHash(encryptedDigestB) == digest);

    bool parserThrew = false;
    try {
        static_cast<void>(parser.parseAndEvaluate("(simplify (/ 9 3))"));
    } catch (const std::runtime_error&) {
        parserThrew = true;
    }
    assert(parserThrew);

    BlockHeader header;
    header.index = 1;
    header.previousBlockHash = "00000000genesis";
    header.timestampUnix = 1730000000;

    Block block(header);
    assert(block.header().index == 1);
    assert(block.transactionCount() == 0);

    std::string rejectionReason;
    Transaction tx1{"alice", "bob", "(simplify (+ 7 5))", "", "", ""};
    assert(block.acceptTransaction(tx1, parser, &rejectionReason));
    assert(rejectionReason.empty());
    assert(block.transactionCount() == 1);
    assert(block.body().transactions[0].resolvedAmount == "12");
    assert(!block.body().transactions[0].transactionHash.empty());
    assert(!block.body().transactions[0].encryptedTransactionHash.empty());

    const std::string expectedHash = LightweightCrypto::hashString("alice|bob|(simplify (+ 7 5))|12");
    assert(block.body().transactions[0].transactionHash == expectedHash);
    assert(crypto.decryptHash(block.body().transactions[0].encryptedTransactionHash) == expectedHash);

    Transaction tx1Clone{"alice", "bob", "(simplify (+ 7 5))", "", "", ""};
    assert(block.acceptTransaction(tx1Clone, parser, &rejectionReason));
    assert(block.transactionCount() == 2);
    assert(block.body().transactions[0].transactionHash == block.body().transactions[1].transactionHash);
    assert(block.body().transactions[0].encryptedTransactionHash != block.body().transactions[1].encryptedTransactionHash);

    Transaction tx2{"alice", "bob", "(simplify (- 1 3))", "", "", ""};
    assert(!block.acceptTransaction(tx2, parser, &rejectionReason));
    assert(!rejectionReason.empty());

    Transaction tx3{"", "bob", "5", "", "", ""};
    assert(!block.acceptTransaction(tx3, parser, &rejectionReason));

    Transaction tx4{"alice", "bob", "(simplify (/ 9 3))", "", "", ""};
    assert(!block.acceptTransaction(tx4, parser, &rejectionReason));
}

int main() {
    runSelfChecks();

    LispParser parser;
    const std::string fileName = "src/expressions.txt";

    std::ifstream input(fileName);
    if (!input.is_open()) {
        std::cerr << "Could not open " << fileName << std::endl;
        return 0;
    }

    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }

        try {
            const Bignum result = parser.parseAndEvaluate(line);
            std::cout << result.toSignedDecimalString() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << e.what() << std::endl;
        }
    }

    return 0;
}