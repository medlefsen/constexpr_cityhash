#ifndef CONSTEXPR_CITYHASH_HPP
#define CONSTEXPR_CITYHASH_HPP

#include <cstdint>
#include <cstdlib>
#include <stdexcept>

namespace constexpr_cityhash
{
  namespace detail
  {
    static const uint64_t k0 = 0xc3a5c85c97cb3127ULL;
    static const uint64_t k1 = 0xb492b66fbe98f273ULL;
    static const uint64_t k2 = 0x9ae16a3b2f90404fULL;
    static const uint64_t k3 = 0xc949d7c7509e6557ULL;

    constexpr uint64_t shift64(uint64_t v, int b)
    {
      return v << (b*8);
    }

    constexpr uint32_t shift32(uint32_t v, int b)
    {
      return v << (b*8);
    }

    constexpr uint64_t load64(const char s[8])
    {
      return shift64(s[0],0)
           + shift64(s[1],1)
           + shift64(s[2],2)
           + shift64(s[3],3)
           + shift64(s[4],4)
           + shift64(s[5],5)
           + shift64(s[6],6)
           + shift64(s[7],7);
    }

    constexpr uint32_t load32(const char s[4]) {
      return shift32(s[0],0)
           + shift32(s[1],1)
           + shift32(s[2],2)
           + shift32(s[3],3);
    }

    constexpr uint64_t ShiftMix(uint64_t val) {
      return val ^ (val >> 47);
    }

    // Equivalent to Rotate(), but requires the second arg to be non-zero.
    // On x86-64, and probably others, it's possible for this to compile
    // to a single instruction if both args are already in registers.
    constexpr uint64_t RotateByAtLeast1(uint64_t val, int shift) {
      return (val >> shift) | (val << (64 - shift));
    }

    // Bitwise right rotate.  Normally this will compile to a single
    // instruction, especially if the shift is a manifest constant.
    constexpr uint64_t Rotate(uint64_t val, int shift) {
      // Avoid shifting by 64: doing so yields an undefined result.
      return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
    }


    constexpr uint64_t bor_shift47(uint64_t n)
    {
      return n ^ (n >> 47);
    }

    constexpr uint64_t Hash128to64_p(uint64_t low, uint64_t high, uint64_t kMul) {
      return ((bor_shift47((high ^ (bor_shift47((low ^ high) * kMul))) * kMul)) * kMul );
    }
    // Hash 128 input bits down to 64 bits of output.
    // This is intended to be a reasonably good hash function.
    constexpr uint64_t Hash128to64(uint64_t low, uint64_t high) {
      return Hash128to64_p(low,high,0x9ddfea08eb382d69ULL);
    }

    constexpr uint64_t HashLen16(uint64_t u, uint64_t v) {
      return Hash128to64(u,v);
    }

    constexpr uint64_t HashLen0to16_gt8(uint64_t a, uint64_t b, size_t len)
    {
      return HashLen16(a,RotateByAtLeast1(b + len,len)) ^ b;
    }

    constexpr uint64_t HashLen0to16(const char *s, size_t len) {
      return (
          len > 8 ?
          HashLen0to16_gt8(load64(s),load64(s + len - 8),len)
          :
            (
             len >= 4 ?
             HashLen16(len + (load32(s) << 3), load32(s + len - 4))
             :
             (len > 0 ?
              ShiftMix(
               (static_cast<uint32_t>(static_cast<uint8_t>(s[0])) + (static_cast<uint32_t>(static_cast<uint8_t>(s[len >> 1])) << 8))
               * k2 ^ (len + (static_cast<uint32_t>(static_cast<uint8_t>(s[len - 1])) << 2)) * k3) * k2
              :
              k2
             )
            )
          );
    }

    constexpr uint64_t HashLen17to32_impl(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t len) {
      return HashLen16(Rotate(a - b, 43) + Rotate(c, 30) + d,
                       a + Rotate(b ^ k3, 20) - c + len);
    }
    // This probably works well for 16-byte strings as well, but it may be overkill
    // in that case.
    constexpr uint64_t HashLen17to32(const char *s, size_t len) {
      return HashLen17to32_impl(load64(s) * k1,
                                load64(s + 8),
                                load64(s + len - 8) * k2,
                                load64(s + len - 16) * k0,
                                len);
    }

    constexpr uint64_t HashLen33to64_6(uint64_t vf, uint64_t vs, uint64_t wf, uint64_t ws) {
      return ShiftMix(ShiftMix((vf + ws) * k2 + (wf + vs) * k0) * k0 + vs) * k2;
    }

    constexpr uint64_t HashLen33to64_5(
        uint64_t z,
        uint64_t b,
        uint64_t c2,
        uint64_t a3,
        uint64_t z2,
        uint64_t b2,
        uint64_t c4,
        uint64_t a6
        ) {
      //uint64 vf = a3 + z;                 // a3, z
      //uint64 vs = b + Rotate(a3, 31) + c2; // b, a3, c2
      //uint64 wf = a6 + z2;               // a6, z2
      //uint64 ws = b2 + Rotate(a6, 31) + c4; // b2, a6, c4
      return HashLen33to64_6(a3 + z,b + Rotate(a3, 31) + c2,a6 + z2,b2 + Rotate(a6, 31) + c4);
    }

    constexpr uint64_t HashLen33to64_4(const char *s, size_t len,
        uint64_t z,
        uint64_t b,
        uint64_t c2,
        uint64_t a3,
        uint64_t z2,
        uint64_t b2,
        uint64_t c3,
        uint64_t a5
        ) {
      //uint64 c4 = c3 + Rotate(a5, 7);    // c3, a5 - c3
      //uint64 a6 = a5 + load64(s + len - 16); // a5 - a5
      return HashLen33to64_5(
          z, //z
          b, //b
          c2, //c2
          a3, //a3
          z2, //z2
          b2, //b2
          c3 + Rotate(a5, 7), //c4
          a5 + load64(s + len - 16)); //a6
    }

    constexpr uint64_t HashLen33to64_3(const char *s, size_t len,
        uint64_t z,
        uint64_t b,
        uint64_t c2,
        uint64_t a3,
        uint64_t a4,
        uint64_t z2
        ) {
      //uint64 b2 = Rotate(a4 + z2, 52);  // a4, z2
      //uint64 c3 = Rotate(a4, 37);       // a4
      //uint64 a5 = a4 + load64(s + len - 24); // a4 - a4
      return HashLen33to64_4(s,len,
          z, //z
          b, //b
          c2, //c2
          a3, //a3
          z2, //z2
          Rotate(a4 + z2, 52), //b2
          Rotate(a4, 37), //c3
          a4 + load64(s + len - 24)); //a5
    }

    constexpr uint64_t HashLen33to64_2(const char *s, size_t len,
        uint64_t z,
        uint64_t b,
        uint64_t c,
        uint64_t a2
        ) {
      //uint64 c2 = c + Rotate(a2, 7);      // c, a2 - c
      //uint64 a3 = a2 + load64(s + 16);   // a2 - a2
      //uint64 a4 = load64(s + 16) + load64(s + len - 32); //
      //uint64 z2 = load64(s + len - 8); //
      return HashLen33to64_3(s,len,
          z, //z
          b, //b
          c + Rotate(a2, 7), //c2
          a2 + load64(s + 16), //a3
          load64(s + 16) + load64(s + len - 32), //a4
          load64(s + len - 8)); //z2
    }

    constexpr uint64_t HashLen33to64_1(const char *s, size_t len,
        uint64_t z,
        uint64_t a
        ) {
      //uint64 b = Rotate(a + z, 52);       // a, z
      //uint64 c = Rotate(a, 37);           // a
      //uint64 a2 = a + load64(s + 8);     // a - a
      return HashLen33to64_2(s,len,
          z, //z
          Rotate(a + z, 52), //b
          Rotate(a, 37), //c
          a + load64(s + 8)); //a2
    }

    constexpr uint64_t HashLen33to64_0(const char *s, size_t len) {
      //uint64 z = Fetch64(s + 24);
      //uint64 a = Fetch64(s) + (len + Fetch64(s + len - 16)) * k0;
      return HashLen33to64_1(s,len,load64(s + 24),load64(s) + (len + load64(s + len - 16)) * k0);
    }

    constexpr uint64_t HashLen33to64(const char *s, size_t len) {
      return HashLen33to64_0(s,len);
    }

  }
    constexpr uint64_t CityHash64(const char *s, size_t len)
    {
      if (len <= 32) {
        if (len <= 16) {
          return detail::HashLen0to16(s, len);
        }
        else {
          return detail::HashLen17to32(s, len);
        }
      }
      else if (len <= 64) {
        return detail::HashLen33to64(s, len);
      }

      // For strings over 64 bytes we hash the end first, and then as we
      // loop we keep 56 bytes of state: v, w, x, y, and z.
      uint64 x = detail::load64(s + len - 40);
      uint64 y = detail::load64(s + len - 16) + detail::load64(s + len - 56);
      uint64 z = detail::HashLen16(detail::load64(s + len - 48) + len, detail::load64(s + len - 24));
      std::pair<uint64, uint64> v = detail::WeakHashLen32WithSeeds(s + len - 64, len, z);
      std::pair<uint64, uint64> w = detail::WeakHashLen32WithSeeds(s + len - 32, y + detail::k1, x);
      x = x * detail::k1 + detail::load64(s);

      // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
      len = (len - 1) & ~static_cast<size_t>(63);
      do {
        x = detail::Rotate(x + y + v.first + detail::load64(s + 8), 37) * detail::k1;
        y = detail::Rotate(y + v.second + detail::load64(s + 48), 42) * detail::k1;
        x ^= w.second;
        y += v.first + detail::load64(s + 40);
        z = detail::Rotate(z + w.first, 33) * detail::k1;

        // Commented out is how the official version does it (https://github.com/google/cityhash/blob/master/src/city.cc),
        // but std::pair::operator= is not constexpr at the moment.
        //v = WeakHashLen32WithSeeds(s, v.second * detail::k1, x + w.first);
        //w = WeakHashLen32WithSeeds(s + 32, z + w.second, y + detail::load64(s + 16));
        std::pair<uint64, uint64> v2 = detail::WeakHashLen32WithSeeds(s, v.second * detail::k1, x + w.first);
        std::pair<uint64, uint64> w2 = detail::WeakHashLen32WithSeeds(s + 32, z + w.second, y + detail::load64(s + 16));
        v.first = v2.first;
        v.second = v2.second;
        w.first = w2.first;
        w.second = w2.second;

        detail::SwapValues(z, x);
        s += 64;
        len -= 64;
      } while (len != 0);

      return detail::HashLen16(detail::HashLen16(v.first, w.first) + detail::ShiftMix(y) * detail::k1 + z,
        detail::HashLen16(v.second, w.second) + x);
    }

    template<size_t N>
    constexpr uint64_t CityHash64(const char (&s) [N])
    {
      return CityHash64(s,N-1);
    }
}

#endif
