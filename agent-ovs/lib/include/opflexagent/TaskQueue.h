/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_TASK_QUEUE_H_
#define OPFLEXAGENT_TASK_QUEUE_H_

#include <boost/asio/io_service.hpp>

#include <cstdint>
#include <unordered_set>
#include <string>
#include <mutex>
#include <functional>

namespace opflexagent {

/**
 * Queue tasks using a boost::asio::io_service so that the same task
 * is not queued multiple times
 */
class TaskQueue {
public:
    /**
     * Initialize a task queue using the specified io_service
     * @param io_service the io service to use
     */
    TaskQueue(boost::asio::io_service& io_service);

    /**
     * Dispatch the given task with the specified task ID.  If a task
     * with the given task ID has already been queued and not been
     * executed, the task will not be queued again.  The task can be
     * queued again once it has begun executing.
     *
     * @param taskId a unique ID for the task
     * @param task a function to execute for the task.  This will be
     * copied onto the task queue
     */
    void dispatch(const std::string& taskId,
                  const std::function<void ()>& task);

    /**
     * Accept tasks again after a call to stop().  Tasks dispatched
     * before stop() still never run.  A new task queue accepts tasks.
     */
    void start();

    /**
     * Skip every task that has not begun executing, and drop tasks
     * dispatched until start() is called.  A task that is already
     * executing is not interrupted.
     */
    void stop();

private:
    void run_task(uint64_t gen, const std::string& taskId,
                  const std::function<void ()>& task);

    boost::asio::io_service& io_service;
    std::mutex queueMutex;
    std::unordered_set<std::string> queuedItems;
    bool stopped;
    uint64_t generation;
};

} // namespace opflexagent

#endif /* OPFLEXAGENT_TASK_QUEUE_H_ */
