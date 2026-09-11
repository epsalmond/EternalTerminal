#include "CryptoHandler.hpp"
#include "SshSetupHandler.hpp"
#include "TestHeaders.hpp"

using namespace et;

namespace {

const string kTestId = "0123456789ABCDEF";
const string kTestPasskey = "0123456789ABCDEF0123456789ABCDEF";

pair<string, string> bootstrapCredentialsFromArgs(const vector<string>& args) {
  if (args.empty()) {
    return {};
  }

  const string& command = args.back();
  const string echoPrefix = "echo '";
  const size_t credentialsStart = command.find(echoPrefix);
  if (credentialsStart == string::npos) {
    return {};
  }

  const size_t idStart = credentialsStart + echoPrefix.length();
  const size_t separator = command.find('/', idStart);
  const size_t passkeyEnd = command.find('_', separator);
  if (separator == string::npos || passkeyEnd == string::npos ||
      separator <= idStart || passkeyEnd <= separator + 1) {
    return {};
  }

  return {command.substr(idStart, separator - idStart),
          command.substr(separator + 1, passkeyEnd - separator - 1)};
}

/** Captures dispatched log messages for assertions about secret exposure. */
class SshSetupLogCapture : public el::LogDispatchCallback {
 public:
  void handle(const el::LogDispatchData* data) override {
    messages_ += data->logMessage()->message();
    messages_ += '\n';
  }

  const string& messages() const { return messages_; }

 private:
  string messages_;
};

class ScopedSshSetupLogCapture {
 public:
  ScopedSshSetupLogCapture() {
    el::Helpers::installLogDispatchCallback<SshSetupLogCapture>(callbackId());
    callback_ =
        el::Helpers::logDispatchCallback<SshSetupLogCapture>(callbackId());
  }

  ~ScopedSshSetupLogCapture() {
    el::Helpers::uninstallLogDispatchCallback<SshSetupLogCapture>(callbackId());
  }

  const string& messages() const { return callback_->messages(); }

 private:
  static const string& callbackId() {
    static const string id = "SshSetupHandlerTestLogCapture";
    return id;
  }

  SshSetupLogCapture* callback_ = nullptr;
};

class ScopedVerboseLogging {
 public:
  ScopedVerboseLogging() : previous_(el::Loggers::verboseLevel()) {
    el::Loggers::setVerboseLevel(1);
  }

  ~ScopedVerboseLogging() { el::Loggers::setVerboseLevel(previous_); }

 private:
  decltype(el::Loggers::verboseLevel()) previous_;
};

/**
 * @brief Fake subprocess handler that simulates ssh command execution
 * for testing SshSetupHandler.
 */
class FakeSshSubprocessHandler : public SubprocessUtils {
 public:
  /**
   * @brief Simulates the subprocess execution for ssh commands.
   * Verifies that the command is "ssh" and returns a simulated server response
   * similar to what etterminal would output (TerminalMain.cpp lines 117-119).
   */
  string SubprocessToStringInteractive(const string& command,
                                       const vector<string>& args) override {
    // Verify the command is "ssh"
    REQUIRE(command == "ssh");

    // Simulate the server response
    // When etterminal receives an id starting with "XXX", it generates
    // new id and passkey and outputs them in IDPASSKEY format
    string id = genRandomAlphaNum(16);
    string passkey = genRandomAlphaNum(32);
    string idpasskey = id + string("/") + passkey;

    return string("IDPASSKEY:") + idpasskey;
  }
};

/**
 * @brief Fake subprocess handler that returns empty output
 * to simulate SSH connection failure.
 */
class FakeSshSubprocessHandlerEmpty : public SubprocessUtils {
 public:
  string SubprocessToStringInteractive(const string& command,
                                       const vector<string>& args) override {
    REQUIRE(command == "ssh");
    return "";
  }
};

/**
 * @brief Fake subprocess handler that returns invalid output
 * to simulate server misconfiguration.
 */
class FakeSshSubprocessHandlerInvalid : public SubprocessUtils {
 public:
  string SubprocessToStringInteractive(const string& command,
                                       const vector<string>& args) override {
    REQUIRE(command == "ssh");
    return "Some invalid output without IDPASSKEY";
  }
};

/** Fake handler with a caller-supplied response for malformed-output tests. */
class FakeSshSubprocessHandlerWithResponse : public SubprocessUtils {
 public:
  explicit FakeSshSubprocessHandlerWithResponse(const string& response)
      : responses_{response} {}

  explicit FakeSshSubprocessHandlerWithResponse(const vector<string>& responses)
      : responses_(responses) {}

  string SubprocessToStringInteractive(const string& command,
                                       const vector<string>& args) override {
    REQUIRE(command == "ssh");
    REQUIRE(!responses_.empty());
    lastArgs_ = args;
    const size_t responseIndex = min(callCount_, responses_.size() - 1);
    ++callCount_;
    return responses_[responseIndex];
  }

  const vector<string>& lastArgs() const { return lastArgs_; }

 private:
  vector<string> responses_;
  vector<string> lastArgs_;
  size_t callCount_ = 0;
};

/** Returns the bootstrap pair, emulating an old server that reuses it. */
class FakeSshSubprocessHandlerLegacy : public SubprocessUtils {
 public:
  string SubprocessToStringInteractive(const string& command,
                                       const vector<string>& args) override {
    REQUIRE(command == "ssh");
    bootstrap_ = bootstrapCredentialsFromArgs(args);
    REQUIRE(bootstrap_.first.length() == 16);
    REQUIRE(bootstrap_.second.length() == 32);
    return "IDPASSKEY:" + bootstrap_.first + "/" + bootstrap_.second;
  }

  const pair<string, string>& bootstrap() const { return bootstrap_; }

 private:
  pair<string, string> bootstrap_;
};

class FakeSshSubprocessHandlerThrows : public SubprocessUtils {
 public:
  explicit FakeSshSubprocessHandlerThrows(const string& secret)
      : secret_(secret) {}

  string SubprocessToStringInteractive(const string& command,
                                       const vector<string>& args) override {
    REQUIRE(command == "ssh");
    throw runtime_error("ssh failed while using " + secret_);
  }

 private:
  string secret_;
};

/**
 * @brief Fake subprocess handler that simulates jumphost setup.
 */
class FakeSshSubprocessHandlerWithJumphost : public SubprocessUtils {
 public:
  string SubprocessToStringInteractive(const string& command,
                                       const vector<string>& args) override {
    REQUIRE(command == "ssh");

    // Generate id and passkey
    string id = genRandomAlphaNum(16);
    string passkey = genRandomAlphaNum(32);
    string idpasskey = id + string("/") + passkey;

    // Check if this is the jumphost call (args.size() == 2)
    // or the initial ssh call (args.size() > 2)
    if (args.size() == 2) {
      // This is the jumphost call
      // Return format similar to what the jumpclient would output
      return string("IDPASSKEY:") + idpasskey;
    } else {
      // This is the initial ssh call
      return string("IDPASSKEY:") + idpasskey;
    }
  }
};

}  // namespace

TEST_CASE("SshSetupHandler basic connection", "[SshSetupHandler]") {
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandler>();
  SshSetupHandler handler(fakeSubprocess);

  auto [id, passkey] = handler.SetupSsh("testuser",  // user
                                        "testhost",  // host
                                        "testhost",  // host_alias
                                        2022,        // port
                                        "",          // jumphost (empty)
                                        "",          // jServerFifo
                                        false,       // kill
                                        0,           // vlevel
                                        "",          // etterminal_path
                                        "",          // serverFifo
                                        std::vector<string>()  // ssh_options
  );

  SECTION("Returns id/passkey pair") {
    // Verify id and passkey have expected lengths
    REQUIRE(id.length() == 16);
    REQUIRE(passkey.length() == 32);
  }
}

TEST_CASE("SshSetupHandler with custom options", "[SshSetupHandler]") {
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandler>();
  SshSetupHandler handler(fakeSubprocess);

  std::vector<string> ssh_options = {"StrictHostKeyChecking=no",
                                     "UserKnownHostsFile=/dev/null"};

  auto [id, passkey] = handler.SetupSsh("customuser",  // user
                                        "customhost",  // host
                                        "customhost",  // host_alias
                                        2023,          // port
                                        "",            // jumphost
                                        "",            // jServerFifo
                                        true,  // kill (kill old sessions)
                                        2,     // vlevel (verbose level)
                                        "/custom/path",  // etterminal_path
                                        "/tmp/fifo",     // serverFifo
                                        ssh_options      // ssh_options
  );

  // Verify result is valid
  REQUIRE(id.length() == 16);
  REQUIRE(passkey.length() == 32);
}

TEST_CASE("SshSetupHandler with jumphost", "[SshSetupHandler]") {
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandlerWithJumphost>();
  SshSetupHandler handler(fakeSubprocess);

  auto [id, passkey] = handler.SetupSsh("testuser",  // user
                                        "testhost",  // host
                                        "testhost",  // host_alias
                                        2022,        // port
                                        "jumphost",  // jumphost (non-empty)
                                        "",          // jServerFifo
                                        false,       // kill
                                        0,           // vlevel
                                        "",          // etterminal_path
                                        "",          // serverFifo
                                        std::vector<string>()  // ssh_options
  );

  SECTION("Returns id/passkey pair with jumphost") {
    REQUIRE(id.length() == 16);
    REQUIRE(passkey.length() == 32);
  }
}

TEST_CASE("SshSetupHandler with empty SSH output", "[SshSetupHandler]") {
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandlerEmpty>();
  SshSetupHandler handler(fakeSubprocess);

  REQUIRE_THROWS_AS(handler.SetupSsh("testuser",            // user
                                     "testhost",            // host
                                     "testhost",            // host_alias
                                     2022,                  // port
                                     "",                    // jumphost
                                     "",                    // jServerFifo
                                     false,                 // kill
                                     0,                     // vlevel
                                     "",                    // etterminal_path
                                     "",                    // serverFifo
                                     std::vector<string>()  // ssh_options
                                     ),
                    std::runtime_error);
}

TEST_CASE("SshSetupHandler with invalid server output", "[SshSetupHandler]") {
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandlerInvalid>();
  SshSetupHandler handler(fakeSubprocess);

  REQUIRE_THROWS_AS(handler.SetupSsh("testuser",            // user
                                     "testhost",            // host
                                     "testhost",            // host_alias
                                     2022,                  // port
                                     "",                    // jumphost
                                     "",                    // jServerFifo
                                     false,                 // kill
                                     0,                     // vlevel
                                     "",                    // etterminal_path
                                     "",                    // serverFifo
                                     std::vector<string>()  // ssh_options
                                     ),
                    std::runtime_error);
}

TEST_CASE("SshSetupHandler accepts old and new server handshakes",
          "[SshSetupHandler]") {
  auto legacySubprocess = make_shared<FakeSshSubprocessHandlerLegacy>();
  SshSetupHandler legacyHandler(legacySubprocess);

  auto [legacyId, legacyPasskey] =
      legacyHandler.SetupSsh("testuser", "testhost", "testhost", 2022, "", "",
                             false, 0, "", "", std::vector<string>());

  REQUIRE(legacyId == legacySubprocess->bootstrap().first);
  REQUIRE(legacyPasskey == legacySubprocess->bootstrap().second);

  auto newSubprocess = make_shared<FakeSshSubprocessHandlerWithResponse>(
      "login noise\nIDPASSKEY:" + kTestId + "/" + kTestPasskey + "\n");
  SshSetupHandler newHandler(newSubprocess);

  auto [newId, newPasskey] =
      newHandler.SetupSsh("testuser", "testhost", "testhost", 2022, "", "",
                          false, 0, "", "", std::vector<string>());

  REQUIRE(newId == kTestId);
  REQUIRE(newPasskey == kTestPasskey);
}

TEST_CASE("SshSetupHandler does not log bootstrap credentials",
          "[SshSetupHandler]") {
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandlerLegacy>();
  SshSetupHandler handler(fakeSubprocess);
  ScopedSshSetupLogCapture logCapture;
  ScopedVerboseLogging verboseLogging;

  REQUIRE_NOTHROW(handler.SetupSsh("testuser", "testhost", "testhost", 2022, "",
                                   "", false, 0, "", "",
                                   std::vector<string>()));
  REQUIRE(logCapture.messages().find(fakeSubprocess->bootstrap().first) ==
          string::npos);
  REQUIRE(logCapture.messages().find(fakeSubprocess->bootstrap().second) ==
          string::npos);
}

TEST_CASE("SshSetupHandler rejects malformed direct output without leaking it",
          "[SshSetupHandler]") {
  const string malformedOutput = "IDPASSKEY:" + kTestId;
  auto fakeSubprocess =
      make_shared<FakeSshSubprocessHandlerWithResponse>(malformedOutput);
  SshSetupHandler handler(fakeSubprocess);
  ScopedSshSetupLogCapture logCapture;
  ScopedVerboseLogging verboseLogging;

  REQUIRE_THROWS_AS(
      handler.SetupSsh("testuser", "testhost", "testhost", 2022, "", "", false,
                       0, "", "", std::vector<string>()),
      std::runtime_error);
  REQUIRE(logCapture.messages().find(kTestId) == string::npos);
  REQUIRE(logCapture.messages().find(malformedOutput) == string::npos);
}

TEST_CASE("SshSetupHandler hides subprocess errors", "[SshSetupHandler]") {
  const string secret = kTestId + "/" + kTestPasskey;
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandlerThrows>(secret);
  SshSetupHandler handler(fakeSubprocess);
  ScopedSshSetupLogCapture logCapture;

  REQUIRE_THROWS_AS(
      handler.SetupSsh("testuser", "testhost", "testhost", 2022, "", "", false,
                       0, "", "", std::vector<string>()),
      std::runtime_error);
  REQUIRE(logCapture.messages().find(secret) == string::npos);
}

TEST_CASE("SshSetupHandler rejects malformed jump output without fallback",
          "[SshSetupHandler]") {
  const string malformedJumpOutput = "IDPASSKEY:" + kTestId;
  auto fakeSubprocess =
      make_shared<FakeSshSubprocessHandlerWithResponse>(vector<string>{
          "IDPASSKEY:" + kTestId + "/" + kTestPasskey, malformedJumpOutput});
  SshSetupHandler handler(fakeSubprocess);
  ScopedSshSetupLogCapture logCapture;

  REQUIRE_THROWS_AS(
      handler.SetupSsh("testuser", "testhost", "testhost", 2022, "jumphost", "",
                       false, 0, "", "", std::vector<string>()),
      std::runtime_error);
  REQUIRE(logCapture.messages().find(kTestId) == string::npos);
  REQUIRE(logCapture.messages().find(malformedJumpOutput) == string::npos);
}

TEST_CASE("SshSetupHandler with serverFifo", "[SshSetupHandler]") {
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandler>();
  SshSetupHandler handler(fakeSubprocess);

  auto [id, passkey] = handler.SetupSsh("testuser",          // user
                                        "testhost",          // host
                                        "testhost",          // host_alias
                                        2022,                // port
                                        "",                  // jumphost
                                        "",                  // jServerFifo
                                        false,               // kill
                                        1,                   // vlevel
                                        "",                  // etterminal_path
                                        "/tmp/server.fifo",  // serverFifo
                                        std::vector<string>()  // ssh_options
  );

  REQUIRE(id.length() == 16);
  REQUIRE(passkey.length() == 32);
}

TEST_CASE("SshSetupHandler with jumphost and jServerFifo",
          "[SshSetupHandler]") {
  auto fakeSubprocess = make_shared<FakeSshSubprocessHandlerWithJumphost>();
  SshSetupHandler handler(fakeSubprocess);

  auto [id, passkey] = handler.SetupSsh("testuser",        // user
                                        "testhost",        // host
                                        "testhost",        // host_alias
                                        2022,              // port
                                        "jumphost",        // jumphost
                                        "/tmp/jump.fifo",  // jServerFifo
                                        false,             // kill
                                        0,                 // vlevel
                                        "",                // etterminal_path
                                        "",                // serverFifo
                                        std::vector<string>()  // ssh_options
  );

  REQUIRE(id.length() == 16);
  REQUIRE(passkey.length() == 32);
}
