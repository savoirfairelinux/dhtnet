#pragma once

#include <thread>
#include <memory>
#include <asio/io_context.hpp>

// This macro is used to validate that a code is executed from the expected
// thread. It's useful to detect unexpected race on data members.
#define CHECK_VALID_THREAD() \
    if (not isValidThread()) \
        printf("The calling thread %d is not the expected thread: %d", getCurrentThread(), threadId_);
        /*JAMI_ERR() << "The calling thread " << getCurrentThread() \
                   << " is not the expected thread: " << threadId_;*/

namespace jami {
namespace upnp {

class UpnpThreadUtil
{
protected:
    std::thread::id getCurrentThread() const { return std::this_thread::get_id(); }

    bool isValidThread() const { return threadId_ == getCurrentThread(); }

    // Upnp context execution queue (same as manager's scheduler)
    // Helpers to run tasks on upnp context queue.
    //static ScheduledExecutor* getScheduler() { return &Manager::instance().scheduler(); }
    
    template<typename Callback>
    static void runOnUpnpContextQueue(Callback&& cb)
    {
        //getScheduler()->run([cb = std::forward<Callback>(cb)]() mutable { cb(); });
        //ioContext->post(std::move(cb));
    }

    std::shared_ptr<asio::io_context> ioContext;
    std::thread::id threadId_;
};

} // namespace upnp
} // namespace jami
