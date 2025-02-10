// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MP_PROXY_H
#define MP_PROXY_H

#include <mp/util.h>

#include <array>
#include <cassert>
#include <functional>
#include <list>
#include <stddef.h>
#include <tuple>
#include <type_traits>
#include <utility>

namespace mp {
class Connection;
class EventLoop;
//! Mapping from capnp interface type to proxy client implementation (specializations are generated by
//! proxy-codegen.cpp).
template <typename Interface>
struct ProxyClient;
//! Mapping from capnp interface type to proxy server implementation (specializations are generated by
//! proxy-codegen.cpp).
template <typename Interface>
struct ProxyServer;
//! Mapping from capnp method params type to method traits (specializations are generated by proxy-codegen.cpp).
template <typename Params>
struct ProxyMethod;
//! Mapping from capnp struct type to struct traits (specializations are generated by proxy-codegen.cpp).
template <typename Struct>
struct ProxyStruct;
//! Mapping from local c++ type to capnp type and traits (specializations are generated by proxy-codegen.cpp).
template <typename Type>
struct ProxyType;

using CleanupList = std::list<std::function<void()>>;
using CleanupIt = typename CleanupList::iterator;

inline void CleanupRun(CleanupList& fns) {
    while (!fns.empty()) {
        auto fn = std::move(fns.front());
        fns.pop_front();
        fn();
    }
}

//! Event loop smart pointer automatically managing m_num_clients.
//! If lock pointer is passed to constructor will use the provided lock,
//! otherwise will lock EventLoop::m_mutex itself.
class EventLoopRef
{
public:
    explicit EventLoopRef(EventLoop& loop, Lock* lock = nullptr);
    EventLoopRef(EventLoopRef&& other) noexcept : m_loop(other.m_loop) { other.m_loop = nullptr; }
    EventLoopRef(const EventLoopRef&) = delete;
    EventLoopRef& operator=(const EventLoopRef&) = delete;
    EventLoopRef& operator=(EventLoopRef&&) = delete;
    ~EventLoopRef() { reset(); }
    EventLoop& operator*() const { assert(m_loop); return *m_loop; }
    EventLoop* operator->() const { assert(m_loop); return m_loop; }
    bool reset(Lock* lock = nullptr);

    EventLoop* m_loop{nullptr};
    Lock* m_lock{nullptr};
};

//! Context data associated with proxy client and server classes.
struct ProxyContext
{
    Connection* connection;
    EventLoopRef loop;
    CleanupList cleanup_fns;

    ProxyContext(Connection* connection);
};

//! Base class for generated ProxyClient classes that implement a C++ interface
//! and forward calls to a capnp interface.
template <typename Interface_, typename Impl_>
class ProxyClientBase : public Impl_
{
public:
    using Interface = Interface_;
    using Impl = Impl_;
    using Sub = ProxyClient<Interface>;
    using Super = ProxyClientBase<Interface, Impl>;

    ProxyClientBase(typename Interface::Client client, Connection* connection, bool destroy_connection);
    ~ProxyClientBase() noexcept;

    // construct/destroy methods called during client construction/destruction
    // that can optionally be defined in capnp interfaces to invoke code on the
    // server when proxy client objects are created and destroyed.
    //
    // The construct() method is not generally very useful, but can be used to
    // run custom code on the server automatically when a ProxyClient client is
    // constructed. The only current use is adding a construct method to Init
    // interfaces that is called automatically on construction, so client and
    // server exchange ThreadMap references and set Connection::m_thread_map
    // values as soon as the Init client is created.
    //
    //     construct @0 (threadMap: Proxy.ThreadMap) -> (threadMap: Proxy.ThreadMap);
    //
    // But construct() is not necessary for this, thread maps could be passed
    // through a normal method that is just called explicitly rather than
    // implicitly.
    //
    // The destroy() method is more generally useful than construct(), because
    // it ensures that the server object will be destroyed synchronously before
    // the client destructor returns, instead of asynchronously at some
    // unpredictable time after the client object is already destroyed and
    // client code has moved on. If the destroy method accepts a Context
    // parameter like:
    //
    //     destroy @0 (context: Proxy.Context) -> ();
    //
    // then it will also ensure that the destructor runs on the same thread the
    // client used to make other RPC calls, instead of running on the server
    // EventLoop thread and possibly blocking it.
    static void construct(Super&) {}
    static void destroy(Super&) {}

    typename Interface::Client m_client;
    ProxyContext m_context;
};

//! Customizable (through template specialization) base class used in generated ProxyClient implementations from
//! proxy-codegen.cpp.
template <typename Interface, typename Impl>
class ProxyClientCustom : public ProxyClientBase<Interface, Impl>
{
    using ProxyClientBase<Interface, Impl>::ProxyClientBase;
};

//! Base class for generated ProxyServer classes that implement capnp server
//! methods and forward calls to a wrapped c++ implementation class.
template <typename Interface_, typename Impl_>
struct ProxyServerBase : public virtual Interface_::Server
{
public:
    using Interface = Interface_;
    using Impl = Impl_;

    ProxyServerBase(std::shared_ptr<Impl> impl, Connection& connection);
    virtual ~ProxyServerBase();
    void invokeDestroy();

    /**
     * Implementation pointer that may or may not be owned and deleted when this
     * capnp server goes out of scope. It is owned for servers created to wrap
     * unique_ptr<Impl> method arguments, but unowned for servers created to
     * wrap Impl& method arguments.
     *
     * In the case of Impl& arguments, custom code is required on other side of
     * the connection to delete the capnp client & server objects since native
     * code on that side of the connection will just be taking a plain reference
     * rather than a pointer, so won't be able to do its own cleanup. Right now
     * this is implemented with addCloseHook callbacks to delete clients at
     * appropriate times depending on semantics of the particular method being
     * wrapped. */
    std::shared_ptr<Impl> m_impl;
    ProxyContext m_context;
};

//! Customizable (through template specialization) base class which ProxyServer
//! classes produced by generated code will inherit from. The default
//! specialization of this class just inherits from ProxyServerBase, but custom
//! specializations can be defined to control ProxyServer behavior.
//!
//! Specifically, it can be useful to specialize this class to add additional
//! state to ProxyServer classes, for example to cache state between IPC calls.
//! If this is done, however, care should be taken to ensure that the extra
//! state can be destroyed without blocking, because ProxyServer destructors are
//! called from the EventLoop thread, and if they block, it could deadlock the
//! program. One way to do avoid blocking is to clean up the state by pushing
//! cleanup callbacks to the m_context.cleanup_fns list, which run after the server
//! m_impl object is destroyed on the same thread destroying it (which will
//! either be an IPC worker thread if the ProxyServer is being explicitly
//! destroyed by a client calling a destroy() method with a Context argument and
//! Context.thread value set, or the temporary EventLoop::m_async_thread used to
//! run destructors without blocking the event loop when no-longer used server
//! objects are garbage collected by Cap'n Proto.) Alternately, if cleanup needs
//! to run before m_impl is destroyed, the specialization can override
//! invokeDestroy and destructor methods to do that.
template <typename Interface, typename Impl>
struct ProxyServerCustom : public ProxyServerBase<Interface, Impl>
{
    using ProxyServerBase<Interface, Impl>::ProxyServerBase;
};

//! Function traits class used to get method parameter and result types, used in
//! generated ProxyClient and ProxyServer classes produced by gen.cpp to get C++
//! method type information. The generated code accesses these traits via
//! intermediate ProxyClientMethodTraits and ProxyServerMethodTraits classes,
//! which it is possible to specialize to change the way method arguments and
//! return values are handled.
//!
//! Fields of the trait class are:
//!
//! Params   - TypeList of C++ ClassName::methodName parameter types
//! Result   - Return type of ClassName::method
//! Param<N> - helper to access individual parameters by index number.
//! Fields   - helper alias that appends Result type to the Params typelist if
//!            it not void.
template <class Fn>
struct FunctionTraits;

//! Specialization of above extracting result and params types assuming the
//! template argument is a pointer-to-method type,
//! decltype(&ClassName::methodName)
template <class _Class, class _Result, class... _Params>
struct FunctionTraits<_Result (_Class::*const)(_Params...)>
{
    using Params = TypeList<_Params...>;
    using Result = _Result;
    template <size_t N>
    using Param = typename std::tuple_element<N, std::tuple<_Params...>>::type;
    using Fields =
        std::conditional_t<std::is_same_v<void, Result>, Params, TypeList<_Params..., _Result>>;
};

//! Traits class for a proxy method, providing the same
//! Params/Result/Param/Fields described in the FunctionTraits class above, plus
//! an additional invoke() method that calls the C++ method which is being
//! proxied, forwarding any arguments.
//!
//! The template argument should be the InterfaceName::MethodNameParams class
//! (generated by Cap'n Proto) associated with the method.
//!
//! Note: The class definition here is just the fallback definition used when
//! the other specialization below doesn't match. The fallback is only used for
//! capnp methods which do not have corresponding C++ methods, which in practice
//! is just the two special construct() and destroy() methods described in \ref
//! ProxyClientBase. These methods don't have any C++ parameters or return
//! types, so the trait information below reflects that.
template <typename MethodParams, typename Enable = void>
struct ProxyMethodTraits
{
    using Params = TypeList<>;
    using Result = void;
    using Fields = Params;

    template <typename ServerContext>
    static void invoke(ServerContext&)
    {
    }
};

//! Specialization of above for proxy methods that have a
//! ProxyMethod<InterfaceName::MethodNameParams>::impl pointer-to-method
//! constant defined by generated code. This includes all functions defined in
//! the capnp interface except any construct() or destroy() methods, that are
//! assumed not to correspond to real member functions in the C++ class, and
//! will use the fallback traits definition above. The generated code this
//! specialization relies on looks like:
//!
//! struct ProxyMethod<InterfaceName::MethodNameParams>
//! {
//!     static constexpr auto impl = &ClassName::methodName;
//! };
template <typename MethodParams>
struct ProxyMethodTraits<MethodParams, Require<decltype(ProxyMethod<MethodParams>::impl)>>
    : public FunctionTraits<decltype(ProxyMethod<MethodParams>::impl)>
{
    template <typename ServerContext, typename... Args>
    static decltype(auto) invoke(ServerContext& server_context, Args&&... args)
    {
        return (server_context.proxy_server.m_impl.get()->*ProxyMethod<MethodParams>::impl)(std::forward<Args>(args)...);
    }
};

//! Customizable (through template specialization) traits class used in generated ProxyClient implementations from
//! proxy-codegen.cpp.
template <typename MethodParams>
struct ProxyClientMethodTraits : public ProxyMethodTraits<MethodParams>
{
};

//! Customizable (through template specialization) traits class used in generated ProxyServer implementations from
//! proxy-codegen.cpp.
template <typename MethodParams>
struct ProxyServerMethodTraits : public ProxyMethodTraits<MethodParams>
{
};

static constexpr int FIELD_IN = 1;
static constexpr int FIELD_OUT = 2;
static constexpr int FIELD_OPTIONAL = 4;
static constexpr int FIELD_REQUESTED = 8;
static constexpr int FIELD_BOXED = 16;

//! Accessor type holding flags that determine how to access a message field.
template <typename Field, int flags>
struct Accessor : public Field
{
    static const bool in = flags & FIELD_IN;
    static const bool out = flags & FIELD_OUT;
    static const bool optional = flags & FIELD_OPTIONAL;
    static const bool requested = flags & FIELD_REQUESTED;
    static const bool boxed = flags & FIELD_BOXED;
};

//! Wrapper around std::function for passing std::function objects between client and servers.
template <typename Fn>
class ProxyCallback;

//! Specialization of above to separate Result and Arg types.
template <typename Result, typename... Args>
class ProxyCallback<std::function<Result(Args...)>>
{
public:
    virtual Result call(Args&&... args) = 0;
};

} // namespace mp

#endif // MP_PROXY_H
