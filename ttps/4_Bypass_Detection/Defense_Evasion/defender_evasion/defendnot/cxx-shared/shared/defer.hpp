#pragma once
#include <utility>

template <typename Callable>
class DeferHolder {
public:
    explicit DeferHolder(Callable&& callable) noexcept: callable_(std::forward<Callable>(callable)) { }

    ~DeferHolder() {
        callable_();
    }

private:
    Callable callable_;
};

class Defer {
public:
    constexpr Defer() noexcept = default;
    constexpr ~Defer() noexcept = default;

    template <typename Callable>
    DeferHolder<Callable> operator%(Callable&& cb) {
        return DeferHolder<Callable>{std::forward<Callable>(cb)};
    }
};

#define COMMON_CAT_(x, y) x##y
#define COMMON_CAT(x, y) COMMON_CAT_(x, y)
#define defer auto COMMON_CAT(_defer_instance_, __LINE__) = Defer{} % [&]()
