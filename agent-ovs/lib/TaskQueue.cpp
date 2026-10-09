/*
 * Copyright (c) 2014-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/TaskQueue.h>
#include <opflexagent/logging.h>

namespace opflexagent {

TaskQueue::TaskQueue(boost::asio::io_service& io_service_)
    : io_service(io_service_), stopped(false), generation(0) {

}

void TaskQueue::run_task(uint64_t gen, const std::string& taskId,
                         const std::function<void ()>& task) {
    {
        std::unique_lock<std::mutex> guard(queueMutex);
        // Dispatched before the most recent stop()
        if (gen != generation) return;
        queuedItems.erase(taskId);
    }
    try {
        task();
    } catch (const std::exception& e) {
        LOG(ERROR) << "Exception while executing task " << taskId
                   << ": " << e.what();
    } catch (...) {
        LOG(ERROR) << "Unknown error while executing task " << taskId;
    }
}

void TaskQueue::dispatch(const std::string& taskId,
                         const std::function<void ()>& task) {
    uint64_t gen;
    {
        std::unique_lock<std::mutex> guard(queueMutex);
        if (stopped || !queuedItems.insert(taskId).second) return;
        gen = generation;
    }
    io_service.post([=]() { TaskQueue::run_task(gen, taskId, task); });
}

void TaskQueue::start() {
    std::unique_lock<std::mutex> guard(queueMutex);
    stopped = false;
}

void TaskQueue::stop() {
    std::unique_lock<std::mutex> guard(queueMutex);
    stopped = true;
    ++generation;
    queuedItems.clear();
}

} // namespace opflexagent
