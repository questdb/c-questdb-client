#include "qwp_mock_c.h"
#include "qwp_mock_server.hpp"

#include <memory>
#include <string>
#include <vector>

namespace qm = qwp_mock;

struct qwp_mock_c
{
    std::unique_ptr<qm::MockServer> server;
    std::string addr_cached;
};

static qwp_mock_c* start_mock(int slot_count, int frame_count)
{
    if (slot_count < 1)
        slot_count = 1;
    if (frame_count < 1)
        frame_count = 1;
    // Per-connection script: wait for client binary frames whose
    // first byte is 'Q' (the QWP1 magic byte that every ingress
    // publish frame starts with). This blocks the worker from
    // `graceful_close`ing before the client has finished writing.
    qm::Script accept_frames;
    for (int i = 0; i < frame_count; ++i)
        accept_frames.push_back(qm::ActionAwaitClientFrame{0x51});
    std::vector<qm::Script> scripts;
    scripts.reserve(static_cast<size_t>(slot_count));
    for (int i = 0; i < slot_count; ++i)
        scripts.push_back(accept_frames);

    auto holder = new qwp_mock_c{};
    try
    {
        holder->server = std::make_unique<qm::MockServer>(std::move(scripts));
        holder->addr_cached = holder->server->addr();
    }
    catch (...)
    {
        delete holder;
        return nullptr;
    }
    return holder;
}

extern "C" qwp_mock_c* qwp_mock_c_start(int slot_count)
{
    return start_mock(slot_count, 1);
}

extern "C" qwp_mock_c* qwp_mock_c_start_frames(
    int slot_count, int frame_count)
{
    return start_mock(slot_count, frame_count);
}

extern "C" const char* qwp_mock_c_addr(qwp_mock_c* mock)
{
    if (mock == nullptr)
        return nullptr;
    return mock->addr_cached.c_str();
}

extern "C" void qwp_mock_c_stop(qwp_mock_c* mock)
{
    delete mock;
}
