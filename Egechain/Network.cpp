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

        for (const std::string& neighbor : rankedNeighbors(current)) {
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

    recordBlockAttempt(originPeerId, block.header().timestampUnix);

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

        for (const std::string& neighbor : rankedNeighbors(current)) {
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

void P2PNetwork::recordBlockAttempt(const std::string& peerId, const uint64_t timestampUnix) const {
    if (timestampUnix > latestObservedBlockTimestampUnix_) {
        latestObservedBlockTimestampUnix_ = timestampUnix;
    }
    blockAttemptTimestampsByPeer_[peerId].push_back(timestampUnix);
    pruneBlockAttempts(peerId, latestObservedBlockTimestampUnix_);
}

void P2PNetwork::pruneBlockAttempts(const std::string& peerId, const uint64_t latestTimestampUnix) const {
    auto attemptsIt = blockAttemptTimestampsByPeer_.find(peerId);
    if (attemptsIt == blockAttemptTimestampsByPeer_.end()) {
        return;
    }

    std::deque<uint64_t>& attempts = attemptsIt->second;
    while (!attempts.empty()) {
        const uint64_t oldest = attempts.front();
        if (oldest > latestTimestampUnix || latestTimestampUnix - oldest <= kBlockAttemptWindowSeconds) {
            break;
        }
        attempts.pop_front();
    }
}

uint64_t P2PNetwork::blockAttemptScore(const std::string& peerId) const {
    pruneBlockAttempts(peerId, latestObservedBlockTimestampUnix_);
    const auto attemptsIt = blockAttemptTimestampsByPeer_.find(peerId);
    if (attemptsIt == blockAttemptTimestampsByPeer_.end()) {
        return 0;
    }
    return static_cast<uint64_t>(attemptsIt->second.size());
}

std::vector<std::string> P2PNetwork::rankedNeighbors(const std::string& peerId) const {
    const auto adjacencyIt = adjacency_.find(peerId);
    if (adjacencyIt == adjacency_.end()) {
        return {};
    }

    std::vector<std::string> neighbors(adjacencyIt->second.begin(), adjacencyIt->second.end());
    std::sort(neighbors.begin(), neighbors.end(),
              [this](const std::string& left, const std::string& right) {
                  const uint64_t leftScore = blockAttemptScore(left);
                  const uint64_t rightScore = blockAttemptScore(right);
                  if (leftScore != rightScore) {
                      return leftScore > rightScore;
                  }
                  return left < right;
              });
    return neighbors;
}
