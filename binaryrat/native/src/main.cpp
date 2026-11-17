// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/cache.hpp>
#include <binaryrat/ownership.hpp>
#include <binaryrat/types.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using json = nlohmann::json;
constexpr std::size_t maximum_line = 16 * 1024 * 1024;

std::string string_field(const json& object, const char* name) {
    if (!object.contains(name) || !object.at(name).is_string())
        throw std::invalid_argument(std::string(name) + " must be a string");
    return object.at(name).get<std::string>();
}

std::uint64_t unsigned_value(const json& value, const char* name) {
    if (!value.is_number_integer() ||
        (value.is_number_integer() && !value.is_number_unsigned() && value.get<std::int64_t>() < 0))
        throw std::invalid_argument(std::string(name) + " must be a nonnegative integer");
    return value.get<std::uint64_t>();
}

std::vector<std::string> dependencies(const json& request) {
    if (!request.contains("dependencies") || !request.at("dependencies").is_array())
        throw std::invalid_argument("dependencies must be an array of strings");
    std::vector<std::string> result;
    for (const auto& value : request.at("dependencies")) {
        if (!value.is_string() || value.get_ref<const std::string&>().empty())
            throw std::invalid_argument("dependency identities must be nonempty strings");
        result.push_back(value.get<std::string>());
    }
    return result;
}

const json& cache_key(const json& request) {
    const auto& key = request.at("key");
    if (!key.is_object()) throw std::invalid_argument("key must be an object");
    for (const char* field : {"program_id", "address_space", "address", "body_sha256", "options_digest"})
        if (string_field(key, field).empty())
            throw std::invalid_argument(std::string("empty cache identity: ") + field);
    if (!key.at("schema_version").is_number_integer() ||
        unsigned_value(key.at("schema_version"), "schema_version") != 1 ||
        key.at("ghidra_version") != "12.2")
        throw std::invalid_argument("unsupported cache schema or Ghidra version");
    unsigned_value(key.at("revision"), "revision");
    return key;
}

json recover_types(const json& request) {
    if (!request.at("observations").is_array())
        throw std::invalid_argument("observations must be an array");
    std::vector<binaryrat::types::AccessObservation> observations;
    for (const auto& item : request.at("observations")) {
        const auto& offset = item.at("offset");
        if (!offset.is_number_integer() || (offset.is_number_unsigned() &&
            offset.get<std::uint64_t>() > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())))
            throw std::invalid_argument("offset must fit a signed 64-bit integer");
        binaryrat::types::AccessObservation observation;
        observation.object_id = string_field(item, "object_id");
        observation.offset = offset.get<std::int64_t>();
        observation.width = unsigned_value(item.at("width"), "width");
        observation.evidence_id = string_field(item, "evidence_id");
        if (!item.at("object_start_known").is_boolean())
            throw std::invalid_argument("object_start_known must be boolean");
        observation.object_start_known = item.at("object_start_known").get<bool>();
        if (item.contains("stride") && !item.at("stride").is_null())
            observation.stride = unsigned_value(item.at("stride"), "stride");
        observations.push_back(std::move(observation));
    }
    binaryrat::types::LayoutRecoveryOptions options;
    if (request.contains("maximum_extent"))
        options.maximum_extent = unsigned_value(request.at("maximum_extent"), "maximum_extent");
    const auto recovered = binaryrat::types::recover_layouts(observations, options);
    json result = {{"layouts", json::array()}, {"rejected", json::array()},
                   {"score_kind", "uncalibrated_evidence_strength"}};
    for (const auto& layout : recovered.layouts) {
        json fields = json::array();
        for (const auto& field : layout.fields) {
            fields.push_back({{"offset", field.offset}, {"width", field.width},
                {"stride", field.stride ? json(*field.stride) : json(nullptr)},
                {"evidence_ids", field.evidence_ids}, {"evidence_strength", field.evidence_strength},
                {"overlaps_other_fields", field.overlaps_other_fields},
                {"stride_conflict", field.stride_conflict},
                {"stride_overlaps_access", field.stride_overlaps_access}});
        }
        result["layouts"].push_back({{"object_id", layout.object_id}, {"fields", fields},
            {"minimum_extent", layout.minimum_extent}, {"has_overlaps", layout.has_overlaps},
            {"has_stride_conflicts", layout.has_stride_conflicts},
            {"has_overlapping_stride", layout.has_overlapping_stride}});
    }
    for (const auto& rejection : recovered.rejected)
        result["rejected"].push_back({{"observation_index", rejection.observation_index},
                                      {"reason", binaryrat::types::to_string(rejection.reason)}});
    return result;
}

json dispatch(const json& request, binaryrat::ArtifactCache& cache) {
    const auto op = string_field(request, "op");
    if (request.contains("protocol_version") &&
        (!request.at("protocol_version").is_number_integer() ||
         unsigned_value(request.at("protocol_version"), "protocol_version") != 1))
        throw std::invalid_argument("protocol_version must be integer 1");
    if (op == "ping") return {{"name", "BinaryRat"}, {"version", "0.1.0"},
        {"ghidra_version", "12.2"}, {"capabilities", {"artifact-cache", "layout-proposals"}}};
    if (op == "cache.put") {
        cache.put(cache_key(request), request.at("value"), dependencies(request));
        return {{"stored", true}};
    }
    if (op == "cache.get") {
        const auto value = cache.get(cache_key(request));
        return {{"hit", value.has_value()}, {"value", value ? *value : json(nullptr)}};
    }
    if (op == "cache.invalidate") return {{"removed", cache.invalidate(dependencies(request))}};
    if (op == "types.recover") return recover_types(request);
    throw std::invalid_argument("unknown operation: " + op);
}

bool read_line(std::string& line, bool& oversized) {
    line.clear();
    oversized = false;
    char c;
    bool any = false;
    while (std::cin.get(c)) {
        any = true;
        if (c == '\n') break;
        if (line.size() < maximum_line) line.push_back(c);
        else oversized = true;
    }
    return any;
}

int serve(const std::filesystem::path& directory) {
    binaryrat::CacheOwnership ownership(directory);
    binaryrat::ArtifactCache cache(directory);
    std::string line;
    bool oversized;
    while (read_line(line, oversized)) {
        json response = {{"id", nullptr}, {"protocol_version", 1}, {"ok", false}};
        try {
            if (oversized) throw std::invalid_argument("request exceeds 16 MiB");
            const auto request = json::parse(line);
            if (!request.is_object()) throw std::invalid_argument("request must be an object");
            response["id"] = string_field(request, "id");
            response["result"] = dispatch(request, cache);
            response["ok"] = true;
        } catch (const json::exception& error) {
            response["error"] = {{"code", "invalid_request"}, {"message", error.what()}};
        } catch (const std::invalid_argument& error) {
            response["error"] = {{"code", "invalid_request"}, {"message", error.what()}};
        } catch (const std::exception& error) {
            response["error"] = {{"code", "operation_failed"}, {"message", error.what()}};
        }
        std::cout << response.dump() << '\n' << std::flush;
        if (!std::cout) return 1;
    }
    return std::cin.bad() ? 1 : 0;
}
}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
#else
int main(int argc, char** argv) {
#endif
    try {
        if (argc == 2 && std::filesystem::path(argv[1]) == "--version") {
            std::cout << "BinaryRat 0.1.0 (Ghidra 12.2; protocol 1)\n";
            return 0;
        }
        if (argc < 2 || std::filesystem::path(argv[1]) != "serve") {
            std::cerr << "Usage: binaryrat-engine --version | serve [--cache DIRECTORY]\n";
            return 2;
        }
        std::filesystem::path directory = ".binaryrat-cache";
        if (argc == 4 && std::filesystem::path(argv[2]) == "--cache") directory = argv[3];
        else if (argc != 2) throw std::invalid_argument("invalid command arguments");
        return serve(directory);
    } catch (const std::exception& error) {
        std::cerr << "BinaryRat: " << error.what() << '\n';
        return 1;
    }
}
