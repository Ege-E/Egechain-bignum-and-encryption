#include "Network.h"

#include <algorithm>
#include <queue>

bool P2PNetwork::registerNode(const std::string& peerId, EgechainNode* node) {
    if (peerId.empty() || node == nullptr) {
        return false;
    }

    nodes_.insert_or_assign(peerId, node);
    adjacency_[peerId];
    return true;
}

bool P2PNetwork::connectPeers(const std::string& leftPeerId, const std::string& rightPeerId) {
    if (leftPeerId == rightPeerId) {
        return false;
    }

    if (!nodes_.contains(leftPeerId) || !nodes_.contains(rightPeerId)) {
        return false;
    }

    adjacency_[leftPeerId].insert(rightPeerId);
    adjacency_[rightPeerId].insert(leftPeerId);
    return true;
}

std::vector<std::string> P2PNetwork::discoverPeers(const std::string& peerId) const {
    if (!nodes_.contains(peerId)) {
        return {};
    }

    std::vector<std::string> discovered;
    std::unordered_set<std::string> visited;
    std::queue<std::string> pending;

    visited.insert(peerId);
    pending.push(peerId);

    while (!pending.empty()) {
        const std::string current = pending.front();
        pending.pop();
        discovered.push_back(current);

        const auto adjacencyIt = adjacency_.find(current);
        if (adjacencyIt == adjacency_.end()) {
            continue;
        }

        for (const std::string& neighbor : adjacencyIt->second) {
            if (visited.insert(neighbor).second) {
                pending.push(neighbor);
            }
        }
    }

    std::sort(discovered.begin(), discovered.end());
    return discovered;
}

size_t P2PNetwork::gossipTransaction(const std::string& originPeerId,
                                     const Transaction& transaction,
                                     std::vector<std::string>* errors) const {
    if (!nodes_.contains(originPeerId)) {
        if (errors != nullptr) {
            errors->push_back("Origin peer is not registered.");
        }
        return 0;
    }

    std::unordered_set<std::string> visited;
    std::queue<std::string> pending;
    visited.insert(originPeerId);
    pending.push(originPeerId);

    size_t accepted = 0;

    while (!pending.empty()) {
        const std::string current = pending.front();
        pending.pop();

        const auto adjacencyIt = adjacency_.find(current);
        if (adjacencyIt == adjacency_.end()) {
            continue;
        }

        for (const std::string& neighbor : adjacencyIt->second) {
            if (!visited.insert(neighbor).second) {
                continue;
            }

            pending.push(neighbor);

            auto nodeIt = nodes_.find(neighbor);
            if (nodeIt == nodes_.end() || nodeIt->second == nullptr) {
                continue;
            }

            std::string reason;
            if (nodeIt->second->submitTransaction(transaction, &reason)) {
                accepted++;
            } else if (errors != nullptr) {
                errors->push_back(neighbor + ": " + reason);
            }
        }
    }

    return accepted;
}

size_t P2PNetwork::gossipBlock(const std::string& originPeerId,
                               const Block& block,
                               std::vector<std::string>* errors) const {
    if (!nodes_.contains(originPeerId)) {
        if (errors != nullptr) {
            errors->push_back("Origin peer is not registered.");
        }
        return 0;
    }

    std::unordered_set<std::string> visited;
    std::queue<std::string> pending;
    visited.insert(originPeerId);
    pending.push(originPeerId);

    size_t accepted = 0;

    while (!pending.empty()) {
        const std::string current = pending.front();
        pending.pop();

        const auto adjacencyIt = adjacency_.find(current);
        if (adjacencyIt == adjacency_.end()) {
            continue;
        }

        for (const std::string& neighbor : adjacencyIt->second) {
            if (!visited.insert(neighbor).second) {
                continue;
            }

            pending.push(neighbor);

            auto nodeIt = nodes_.find(neighbor);
            if (nodeIt == nodes_.end() || nodeIt->second == nullptr) {
                continue;
            }

            std::string reason;
            if (nodeIt->second->acceptBlock(block, &reason)) {
                accepted++;
            } else if (errors != nullptr && reason != "Block already known.") {
                errors->push_back(neighbor + ": " + reason);
            }
        }
    }

    return accepted;
}

bool P2PNetwork::syncNode(const std::string& targetPeerId,
                          const std::string& sourcePeerId,
                          std::string* error) const {
    const auto targetIt = nodes_.find(targetPeerId);
    const auto sourceIt = nodes_.find(sourcePeerId);

    if (targetIt == nodes_.end() || sourceIt == nodes_.end()) {
        if (error != nullptr) {
            *error = "Source or target peer is not registered in the network.";
        }
        return false;
    }

    EgechainNode& target = *targetIt->second;
    const EgechainNode& source = *sourceIt->second;

    const std::vector<Block> chain = source.canonicalChain();
    for (const Block& block : chain) {
        std::string reason;
        if (!target.acceptBlock(block, &reason) && reason != "Block already known.") {
            if (error != nullptr) {
                *error = "Sync failed while applying block: " + reason;
            }
            return false;
        }
    }

    if (error != nullptr) {
        error->clear();
    }
    return true;
}
