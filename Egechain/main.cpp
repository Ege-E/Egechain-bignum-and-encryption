#include "Block.h"
#include "LightweightCrypto.h"
#include "LispParser.h"
#include "Network.h"
#include "Node.h"
#include "Wallet.h"

#include <algorithm>
#include <cassert>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

static void runPhase1SelfChecks() {
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

static void runPhase2SelfChecks() {
    ConsensusConfig config;
    config.powDifficulty = 1;
    config.miningReward = "50";
    config.maxTransactionsPerBlock = 16;

    std::string reason;
    std::string signError;

    const WalletKeyPair aliceWallet = Wallet::generateKeyPair();
    const WalletKeyPair bobWallet = Wallet::generateKeyPair();
    const WalletKeyPair carolWallet = Wallet::generateKeyPair();

    EgechainNode node(config);
    assert(node.createGenesis(aliceWallet.address, "1000", 1730000010, &reason));
    assert(reason.empty());
    assert(node.balanceOf(aliceWallet.address) == "1000");

    Transaction tx1{aliceWallet.address, bobWallet.address, "(simplify (+ 40 2))", "1", aliceWallet.publicKey, "", "", "", ""};
    assert(Wallet::signTransaction(tx1, aliceWallet.privateKey, &signError));
    assert(node.submitTransaction(tx1, &reason));

    Transaction duplicateTx{aliceWallet.address, bobWallet.address, "(simplify (+ 40 2))", "1", aliceWallet.publicKey, "", "", "", ""};
    assert(Wallet::signTransaction(duplicateTx, aliceWallet.privateKey, &signError));
    assert(!node.submitTransaction(duplicateTx, &reason));

    Transaction overspendPending{aliceWallet.address, carolWallet.address, "960", "2", aliceWallet.publicKey, "", "", "", ""};
    assert(Wallet::signTransaction(overspendPending, aliceWallet.privateKey, &signError));
    assert(!node.submitTransaction(overspendPending, &reason));

    Block mined;
    assert(node.mineBlock("miner1", 1730000020, &mined, &reason));
    assert(node.balanceOf(aliceWallet.address) == "958");
    assert(node.balanceOf(bobWallet.address) == "42");
    assert(node.balanceOf("miner1") == "50");
    assert(node.mempoolSize() == 0);

    Block invalidLink = mined;
    invalidLink.mutableHeader().previousBlockHash = "bad_hash";
    assert(!node.acceptBlock(invalidLink, &reason));

    Block invalidPow = mined;
    invalidPow.mutableHeader().previousBlockHash = node.tipHash();
    invalidPow.mutableHeader().index = node.chainHeight() + 1;
    invalidPow.mutableHeader().timestampUnix = 1730000030;
    invalidPow.mutableHeader().merkleRoot = invalidPow.computeMerkleRoot();
    invalidPow.mutableHeader().nonce = 0;
    while (invalidPow.computeBlockHash().starts_with("0")) {
        invalidPow.mutableHeader().nonce++;
    }
    assert(!node.acceptBlock(invalidPow, &reason));

    EgechainNode branchA(config);
    EgechainNode branchB(config);
    EgechainNode aggregator(config);

    assert(aggregator.createGenesis(aliceWallet.address, "1000", 1730000100, &reason));
    const Block sharedGenesis = aggregator.canonicalChain().front();
    assert(branchA.acceptBlock(sharedGenesis, &reason));
    assert(branchB.acceptBlock(sharedGenesis, &reason));

    Block a1;
    Block b1;
    Block b2;
    assert(branchA.mineBlock("minerA", 1730000110, &a1, &reason));
    assert(branchB.mineBlock("minerB", 1730000110, &b1, &reason));
    assert(branchB.mineBlock("minerB", 1730000120, &b2, &reason));

    assert(aggregator.acceptBlock(a1, &reason));
    assert(aggregator.acceptBlock(b1, &reason));
    assert(aggregator.acceptBlock(b2, &reason));
    assert(aggregator.chainHeight() == 2);

    Transaction pending{aliceWallet.address, "dave", "5", "3", aliceWallet.publicKey, "", "", "", ""};
    assert(Wallet::signTransaction(pending, aliceWallet.privateKey, &signError));
    assert(aggregator.submitTransaction(pending, &reason));

    const std::filesystem::path persistencePath =
        std::filesystem::temp_directory_path() / "egechain_phase2_state.dat";
    std::string persistenceError;
    assert(aggregator.saveToDisk(persistencePath.string(), &persistenceError));
    assert(persistenceError.empty());

    EgechainNode loaded;
    assert(loaded.loadFromDisk(persistencePath.string(), &persistenceError));
    assert(loaded.chainHeight() == aggregator.chainHeight());
    assert(loaded.balanceOf(aliceWallet.address) == aggregator.balanceOf(aliceWallet.address));
    assert(loaded.mempoolSize() == aggregator.mempoolSize());

    std::ofstream corrupted(persistencePath, std::ios::trunc);
    corrupted << "bad data";
    corrupted.close();

    EgechainNode brokenLoad;
    assert(!brokenLoad.loadFromDisk(persistencePath.string(), &persistenceError));

    std::filesystem::remove(persistencePath);
}

static void runPhase3SelfChecks() {
    ConsensusConfig config;
    config.powDifficulty = 1;
    config.miningReward = "25";
    config.maxTransactionsPerBlock = 8;

    WalletKeyPair alice = Wallet::generateKeyPair();
    WalletKeyPair bob = Wallet::generateKeyPair();
    WalletKeyPair miner = Wallet::generateKeyPair();

    EgechainNode nodeA(config);
    EgechainNode nodeB(config);
    EgechainNode nodeC(config);
    EgechainNode nodeLate(config);

    P2PNetwork network;
    assert(network.registerNode("A", &nodeA));
    assert(network.registerNode("B", &nodeB));
    assert(network.registerNode("C", &nodeC));
    assert(network.registerNode("L", &nodeLate));
    assert(network.connectPeers("A", "B"));
    assert(network.connectPeers("B", "C"));

    const std::vector<std::string> discovered = network.discoverPeers("A");
    assert(std::find(discovered.begin(), discovered.end(), "A") != discovered.end());
    assert(std::find(discovered.begin(), discovered.end(), "B") != discovered.end());
    assert(std::find(discovered.begin(), discovered.end(), "C") != discovered.end());

    std::string reason;
    assert(nodeA.createGenesis(alice.address, "500", 1731000000, &reason));
    assert(reason.empty());

    const Block genesis = nodeA.canonicalChain().front();
    std::vector<std::string> gossipErrors;
    const size_t gossipGenesisAccepted = network.gossipBlock("A", genesis, &gossipErrors);
    assert(gossipGenesisAccepted >= 2);

    Transaction signedTx{alice.address, bob.address, "(simplify (+ 6 4))", "1", alice.publicKey, "", "", "", ""};
    std::string signError;
    assert(Wallet::signTransaction(signedTx, alice.privateKey, &signError));
    assert(nodeA.submitTransaction(signedTx, &reason));

    gossipErrors.clear();
    const size_t txAccepted = network.gossipTransaction("A", signedTx, &gossipErrors);
    assert(txAccepted >= 2);

    Block minedOnC;
    assert(nodeC.mineBlock(miner.address, 1731000010, &minedOnC, &reason));
    gossipErrors.clear();
    const size_t blockAccepted = network.gossipBlock("C", minedOnC, &gossipErrors);
    assert(blockAccepted >= 2);

    assert(nodeA.balanceOf(alice.address) == "490");
    assert(nodeB.balanceOf(alice.address) == "490");
    assert(nodeC.balanceOf(alice.address) == "490");
    assert(nodeA.balanceOf(bob.address) == "10");
    assert(nodeB.balanceOf(bob.address) == "10");
    assert(nodeC.balanceOf(bob.address) == "10");

    Transaction badSignature{alice.address, bob.address, "7", "2", alice.publicKey, "wsig1:broken", "", "", ""};
    assert(!nodeA.submitTransaction(badSignature, &reason));

    Transaction nonDeterministic{alice.address, bob.address, "(declare-const tower 5)", "2", alice.publicKey, "", "", "", ""};
    assert(Wallet::signTransaction(nonDeterministic, alice.privateKey, &signError));
    assert(!nodeA.submitTransaction(nonDeterministic, &reason));

    std::string hugeExpression = "(simplify (+";
    for (int i = 0; i < 200; i++) {
        hugeExpression += " 1";
    }
    hugeExpression += "))";
    Transaction unbounded{alice.address, bob.address, hugeExpression, "2", alice.publicKey, "", "", "", ""};
    assert(Wallet::signTransaction(unbounded, alice.privateKey, &signError));
    assert(!nodeA.submitTransaction(unbounded, &reason));

    std::string syncError;
    assert(network.syncNode("L", "B", &syncError));
    assert(nodeLate.chainHeight() == nodeB.chainHeight());
    assert(nodeLate.tipHash() == nodeB.tipHash());
}

static int runParserFileMode() {
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

static int runNodeMode(const std::string& persistencePath) {
    ConsensusConfig config;
    EgechainNode node(config);

    std::string error;
    if (!persistencePath.empty()) {
        (void)node.loadFromDisk(persistencePath, &error);
    }

    std::cout << "Egechain Phase 2 node mode. Commands:\n"
              << "  genesis <recipient> <amountExpr>\n"
              << "  tx <sender> <receiver> <amountExpr>\n"
              << "  mine <miner>\n"
              << "  balance <account>\n"
              << "  chain\n"
              << "  save <path>\n"
              << "  load <path>\n"
              << "  exit\n";

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input(line);
        std::string command;
        input >> command;

        if (command == "" || command == "#") {
            continue;
        }

        if (command == "exit") {
            break;
        }

        if (command == "genesis") {
            std::string recipient;
            input >> recipient;
            std::string amountExpression;
            std::getline(input, amountExpression);
            if (!amountExpression.empty() && amountExpression.front() == ' ') {
                amountExpression.erase(amountExpression.begin());
            }

            std::string reason;
            if (node.createGenesis(recipient, amountExpression, static_cast<uint64_t>(std::time(nullptr)), &reason)) {
                std::cout << "genesis accepted: tip=" << node.tipHash() << std::endl;
            } else {
                std::cout << "genesis rejected: " << reason << std::endl;
            }
            continue;
        }

        if (command == "tx") {
            std::string sender;
            std::string receiver;
            input >> sender >> receiver;
            std::string amountExpression;
            std::getline(input, amountExpression);
            if (!amountExpression.empty() && amountExpression.front() == ' ') {
                amountExpression.erase(amountExpression.begin());
            }

            Transaction tx{sender, receiver, amountExpression, "", "", ""};
            std::string reason;
            if (node.submitTransaction(tx, &reason)) {
                std::cout << "transaction accepted, mempool=" << node.mempoolSize() << std::endl;
            } else {
                std::cout << "transaction rejected: " << reason << std::endl;
            }
            continue;
        }

        if (command == "mine") {
            std::string miner;
            input >> miner;

            std::string reason;
            Block mined;
            if (node.mineBlock(miner, static_cast<uint64_t>(std::time(nullptr)), &mined, &reason)) {
                std::cout << "block mined: index=" << mined.header().index
                          << " hash=" << mined.computeBlockHash() << std::endl;
            } else {
                std::cout << "mine failed: " << reason << std::endl;
            }
            continue;
        }

        if (command == "balance") {
            std::string account;
            input >> account;
            std::cout << account << "=" << node.balanceOf(account) << std::endl;
            continue;
        }

        if (command == "chain") {
            const std::vector<Block> chain = node.canonicalChain();
            std::cout << "height=" << node.chainHeight() << " blocks=" << chain.size() << std::endl;
            for (const Block& block : chain) {
                std::cout << "  index=" << block.header().index
                          << " hash=" << block.computeBlockHash()
                          << " prev=" << block.header().previousBlockHash
                          << " txs=" << block.transactionCount() << std::endl;
            }
            continue;
        }

        if (command == "save") {
            std::string path;
            input >> path;
            std::string saveError;
            if (node.saveToDisk(path, &saveError)) {
                std::cout << "saved: " << path << std::endl;
            } else {
                std::cout << "save failed: " << saveError << std::endl;
            }
            continue;
        }

        if (command == "load") {
            std::string path;
            input >> path;
            std::string loadError;
            if (node.loadFromDisk(path, &loadError)) {
                std::cout << "loaded: " << path << std::endl;
            } else {
                std::cout << "load failed: " << loadError << std::endl;
            }
            continue;
        }

        std::cout << "Unknown command: " << command << std::endl;
    }

    if (!persistencePath.empty()) {
        std::string saveError;
        if (!node.saveToDisk(persistencePath, &saveError)) {
            std::cerr << "Failed to save state on exit: " << saveError << std::endl;
        }
    }

    return 0;
}

int main(int argc, char** argv) {
    runPhase1SelfChecks();
    runPhase2SelfChecks();

    if (argc >= 2 && std::string(argv[1]) == "node") {
        const std::string persistencePath = (argc >= 3) ? argv[2] : "egechain_state.dat";
        return runNodeMode(persistencePath);
    }

    return runParserFileMode();
}
