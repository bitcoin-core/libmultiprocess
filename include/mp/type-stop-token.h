// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MP_PROXY_TYPE_STOP_TOKEN_H
#define MP_PROXY_TYPE_STOP_TOKEN_H

#include <mp/proxy-io.h>
#include <mp/util.h>

#include <stop_token>

namespace mp {
//! Pass the token to clientInvoke, which cancels the request if stop is
//! requested before the call returns.
inline void CustomBuildExtraParam(TypeList<std::stop_token>, ClientInvokeContext& invoke_context, std::stop_token&& value)
{
    invoke_context.stop_token = std::move(value);
}

//! Return a token that is stopped when the request is canceled. Methods that
//! run on the event loop thread can't be canceled, so they get a token where
//! stop is not possible.
template <typename ServerContext>
std::stop_token CustomReadExtraParam(TypeList<std::stop_token>, ServerContext& server_context)
{
    // This runs with request_lock held, before the method is called, so
    // request_canceled and cancel_fn can be accessed without other locking.
    if (!server_context.request_lock) return {};
    std::stop_source source;
    if (server_context.request_canceled) source.request_stop();
    server_context.cancel_fn = [source]() mutable { source.request_stop(); };
    return source.get_token();
}
} // namespace mp

#endif // MP_PROXY_TYPE_STOP_TOKEN_H
