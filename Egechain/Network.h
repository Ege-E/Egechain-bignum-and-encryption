#pragma once

#include "Block.h"
#include "Node.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class P2PNetwork {
public:
    bool registerNode(const std::string& peerId, EgechainNode* node);
    bool connectPeers(const std::string& leftPeerId, const std::string& rightPeerId);

    [[nodiscard]] std::vector<std::string> discoverPeers(const std::string& peerId) const;

    size_t gossipTransaction(const std::string& originPeerId,
                             const Transaction& transaction,
                             std::vector<std::string>* errors = nullptr) const;

    size_t gossipBlock(const std::string& originPeerId,
                       const Block& block,
                       std::vector<std::string>* errors = nullptr) const;

    bool syncNode(const std::string& targetPeerId,
                  const std::string& sourcePeerId,
                  std::string* error = nullptr) const;

private:
    std::unordered_map<std::string, EgechainNode*> nodes_;
    std::unordered_map<std::string, std::unordered_set<std::string>> adjacency_;
};
