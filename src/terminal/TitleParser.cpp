#include "TitleParser.hpp"

#include <algorithm>

namespace et {
namespace {
constexpr unsigned char kEscape = 0x1b;
constexpr unsigned char kBell = 0x07;
constexpr size_t kMaxTitleBytes = 80;
constexpr size_t kMaxBufferedTitleBytes = 1024;

bool isUtf8Continuation(unsigned char byte) { return (byte & 0xc0) == 0x80; }

size_t utf8SequenceLength(unsigned char byte) {
  if ((byte & 0x80) == 0) {
    return 1;
  }
  if ((byte & 0xe0) == 0xc0) {
    return 2;
  }
  if ((byte & 0xf0) == 0xe0) {
    return 3;
  }
  if ((byte & 0xf8) == 0xf0) {
    return 4;
  }
  return 0;
}
}  // namespace

void TitleParser::beginOsc() {
  state = State::OSC_COMMAND;
  command.clear();
  title.clear();
  titleOsc = false;
}

std::string TitleParser::sanitizeTitle() const {
  std::string sanitized;
  sanitized.reserve(std::min(title.size(), kMaxTitleBytes));
  for (unsigned char byte : title) {
    if (byte >= 0x20 && byte != 0x7f) {
      sanitized.push_back(static_cast<char>(byte));
    }
  }
  if (sanitized.size() <= kMaxTitleBytes) {
    return sanitized;
  }

  sanitized.resize(kMaxTitleBytes);
  size_t lastCharacter = sanitized.size() - 1;
  while (lastCharacter > 0 && isUtf8Continuation(static_cast<unsigned char>(
                                  sanitized[lastCharacter]))) {
    --lastCharacter;
  }
  const size_t sequenceLength =
      utf8SequenceLength(static_cast<unsigned char>(sanitized[lastCharacter]));
  if (sequenceLength == 0 ||
      lastCharacter + sequenceLength > sanitized.size()) {
    sanitized.resize(lastCharacter);
  }
  return sanitized;
}

std::optional<std::string> TitleParser::parse(const std::string& bytes) {
  std::optional<std::string> latestTitle;
  for (unsigned char byte : bytes) {
    switch (state) {
      case State::TEXT:
        if (byte == kEscape) {
          state = State::ESCAPE;
        }
        break;
      case State::ESCAPE:
        if (byte == ']') {
          beginOsc();
        } else if (byte != kEscape) {
          state = State::TEXT;
        }
        break;
      case State::OSC_COMMAND:
        if (byte == ';') {
          titleOsc = command == "0" || command == "2";
          state = State::OSC_TEXT;
        } else if (byte == kBell) {
          state = State::TEXT;
        } else if (byte == kEscape) {
          state = State::OSC_COMMAND_ESCAPE;
        } else if (command.size() < 8) {
          command.push_back(static_cast<char>(byte));
        }
        break;
      case State::OSC_COMMAND_ESCAPE:
        if (byte == ']') {
          beginOsc();
        } else {
          state = State::TEXT;
        }
        break;
      case State::OSC_TEXT:
        if (byte == kBell) {
          if (titleOsc) {
            latestTitle = sanitizeTitle();
          }
          state = State::TEXT;
        } else if (byte == kEscape) {
          state = State::OSC_TEXT_ESCAPE;
        } else if (titleOsc && title.size() < kMaxBufferedTitleBytes) {
          title.push_back(static_cast<char>(byte));
        }
        break;
      case State::OSC_TEXT_ESCAPE:
        if (byte == '\\') {
          if (titleOsc) {
            latestTitle = sanitizeTitle();
          }
          state = State::TEXT;
        } else if (byte == ']') {
          // An OSC inside an unterminated OSC is malformed, but restarting
          // here lets a later valid title recover without consuming forever.
          beginOsc();
        } else {
          if (titleOsc && title.size() < kMaxBufferedTitleBytes) {
            title.push_back(static_cast<char>(byte));
          }
          state = State::OSC_TEXT;
        }
        break;
    }
  }
  return latestTitle;
}

}  // namespace et
