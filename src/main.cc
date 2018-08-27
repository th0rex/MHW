#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>

#include <fmt/printf.h>

#include <gcrypt.h>

#include <gsl/span>

static bool DEBUG_ENABLED = true;

template <typename... Args>
void debug(const char* format, const Args&... args) {
  if (DEBUG_ENABLED) {
    fmt::printf(format, args...);
  }
}

template <typename... Args>
void fatal(const char* format, const Args&... args) {
  debug(format, args...);
  throw std::runtime_error{"error"};
}

template <typename T>
struct owned_span {
  std::unique_ptr<T[]> data;
  gsl::span<T> view;

  owned_span(std::unique_ptr<T[]> x, std::ptrdiff_t s) : view{x.get(), s} {
    data = std::move(x);
  }
};

owned_span<std::uint8_t> read_file(const char* name) {
  auto* f = std::fopen(name, "rb");
  if (!f) {
    fatal("[-] read: fopen failed\n");
  }

  std::fseek(f, 0, SEEK_END);
  const auto size = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);

  auto buffer = std::make_unique<std::uint8_t[]>(size);
  if (!std::fread(buffer.get(), size, 1, f)) {
    fatal("[-] read: fread failed\n");
  }
  std::fclose(f);

  return {std::move(buffer), size};
}

template <typename T>
void write_file(const char* name, gsl::span<T> data) {
  auto* f = std::fopen(name, "wb");
  if (!f) {
    fatal("[-] write: fopen failed\n");
  }

  if (std::fwrite(data.data(), sizeof(T), data.size(), f) !=
      static_cast<std::size_t>(data.size())) {
    fatal("[-] write: fwrite failed\n");
  }
  std::fclose(f);
}

void bswap(gsl::span<std::uint8_t> data) {
  debug("[*] bswap: size: %d\n", data.size());

  auto* p = reinterpret_cast<std::uint32_t*>(data.data());
  for (auto i = 0; i < data.size() / 4; ++i) {
    p[i] = __builtin_bswap32(p[i]);
  }
}

template <typename F>
void do_crypt(gsl::span<std::uint8_t> key, F&& f) {
  debug("[*] do_crypt: key size: %d\n", key.size());

  gcry_cipher_hd_t handle;
  if (gcry_cipher_open(&handle, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB,
                       0)) {
    fatal("[-] do_crypt: gcry_cipher_open failed\n");
  }
  if (gcry_cipher_setkey(handle, key.data(), key.size())) {
    fatal("[-] do_crypt: gcry_cipher_setkey failed\n");
  }

  f(handle);

  gcry_cipher_close(handle);
}

void decrypt(gsl::span<std::uint8_t> data, gsl::span<std::uint8_t> key) {
  do_crypt(key, [data](gcry_cipher_hd_t handle) {
    if (gcry_cipher_decrypt(handle, data.data(), data.size(), nullptr, 0)) {
      fatal("[-] decrypt: gcry_cipher_decrypt failed\n");
    }
    debug("[+] decrypt: decrypted data\n");
  });
}

void encrypt(gsl::span<std::uint8_t> data, gsl::span<std::uint8_t> key) {
  bswap(data);

  do_crypt(key, [data](gcry_cipher_hd_t handle) {
    if (gcry_cipher_encrypt(handle, data.data(), data.size(), nullptr, 0)) {
      fatal("[-] encrypt: gcry_cipher_encrypt failed\n");
    }
    debug("[+] encrypt: encrypted data\n");
  });

  bswap(data);
}

int main(int argc, char** argv) {
  if (argc < 4) {
    fmt::printf("Usage: %s <decrypt|encrypt> input_file output_file key_file\n",
                argv[0]);
    return 1;
  }

  auto [_, data] = read_file(argv[2]);

  if (!std::strcmp(argv[1], "recover_key")) {
    const auto [_, result] = recover_key(data);
    write_file(argv[3], result);
  } else if (!std::strcmp(argv[1], "decrypt") && argc == 5) {
    const auto [_, key] = read_file(argv[4]);
    decrypt(data, key);
    write_file(argv[3], data);
  } else if (!std::strcmp(argv[1], "encrypt") && argc == 5) {
    const auto [_, key] = read_file(argv[4]);
    encrypt(data, key);
    write_file(argv[3], data);
  } else {
    fatal("[-] unknown command: %s\n", argv[1]);
  }

  return 0;
}
