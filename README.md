constexpr_cityhash
==================

Google CityHash algorithm converted to C++11 constexpr functions so it can be called at compile time.

Currently supports only CityHash64 with strings up to 64 characters.
Also provides a one argument version of CityHash64 that can take string literals:
CityHash64("Hi")

Synopsis
--------


    #include "constexpr_cityhash.hpp"
    #include <iostream>

    using constexpr_cityhash::CityHash64;

    template< uint64_t I >
    struct id
    {
      static const uint64_t value = I;
    };

    int main(int argc, char* argv[])
    {
      id<CityHash64("Hello World")> i;
      std::cout << i.value << "\n";
    }
