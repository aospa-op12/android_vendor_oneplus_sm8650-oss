/*
 * Copyright (C) 2026 The YAAP Project
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Source touch daemon.
 *
 * This daemon owns the userspace half of the OPLUS HBP touch path:
 *
 *   /dev/tcm_hbp0 -> libsynaHbpCore -> libIfp -> libthpalgo
 *
 * The stock OPLUS daemon does not parse HBP frames itself.  It opens
 * /dev/tcm_hbp0 through the Synaptics HBP core, asks the core for the raw
 * frame representation produced by the vendor IFP library, feeds that frame
 * to the vendor THP algorithm, and reports the algorithm's filtered points.
 * The same libraries are used here; no prebuilt service or daemon is needed.
 *
 * The kernel still owns the low-power gesture path.  REPORT_TOUCH reports are
 * processed by the kernel before the external-frame queue is consulted, so
 * HBP gestures keep working through the existing KEY_F4 bridge below.
 *
 * The vendor algorithm performs AFT palm/edge classification.  Its feature
 * thresholds come from sys_touch_algo_feature_config.xml, the same file the
 * stock daemon feeds to IAlgoSetConfigReadCallback().  The stock HBP type-4
 * path also runs the userspace prevention engine with the ALGO points and
 * AFT records.  Prevention is enabled by default and only bypassed when
 * persist.vendor.edge_grip_suppression is explicitly set to 0, which restores
 * fully raw touch input.
 */

#define LOG_TAG "OplusTouchDaemon"

#include <android-base/logging.h>
#include <cutils/properties.h>
#include <tinyxml2.h>

#include "TouchPrevention.h"

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <glob.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <poll.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr const char* kCoordinateNode = "/proc/touchpanel/coordinate";
constexpr const char* kFeatureConfigName = "sys_touch_function_feature_config.xml";
constexpr const char* kAlgoConfigName = "sys_touch_algo_feature_config.xml";
constexpr const char* kMainRegisterNode = "/proc/touchpanel/debug_info/main_register";
constexpr const char* kFirmwareInfoNode = "/proc/devinfo/tp";
constexpr const char* kPipelineProperty = "persist.vendor.touch.hbp_pipeline";
constexpr const char* kPreventionProperty = "persist.vendor.touch.hbp_prevention";
constexpr const char* kDebugPointsProperty = "persist.vendor.touch.hbp_debug_points";
constexpr const char* kCustomIfpProperty = "vendor.oplus.touch.customifplib.path";
constexpr const char* kScreenStateProperty = "debug.tracing.screen_state";
constexpr const char* kFingerprintActiveNode = "/proc/touchpanel/fingerprint_active";
constexpr const char* kFingerprintHalNode = "/proc/touchpanel/fingerprint_hal";
constexpr const char* kFingerprintTriggerNode = "/proc/touchpanel/fingerprint_trigger";
constexpr int kGestureStartKey = 246;

// fingerprint_hal bit 1 asks the touch driver to report screen-on fingerprint
// down/up events.  The HBP userspace path has to bridge that to the kernel's
// fingerprint_trigger proc node because REPORT_HBP_ACTIVE_FRAME bypasses the
// kernel's normal REPORT_TOUCH fingerprint reporter.
constexpr uint32_t kFingerprintHalReport = 1u << 1;
constexpr uint32_t kDcTouchHold = 0xD4;
constexpr uint32_t kFingerprintReportDown = 0x80;  // TOUCH_HOLD_DOWN
constexpr uint32_t kFingerprintReportUp = 0x81;    // TOUCH_HOLD_UP
constexpr size_t kFingerprintReportMinLength = 0x16;
constexpr size_t kFingerprintReportXOffset = 0x12;
constexpr size_t kFingerprintReportYOffset = 0x14;

// Bionic reserves signals 32..41, so SIGRTMIN is 42.  The OPLUS display
// service uses SIGRTMIN+2..+6 (44..48); SIGRTMIN+3 (45) is the display-off
// notification.  Without handlers these signals terminate the daemon and
// init restarts it on every screen-state transition.
constexpr int kTouchSignalFirst = 44;
constexpr int kTouchSignalLast = 48;
constexpr int kTouchSignalResume = 44;   // ts_resume_application
constexpr int kTouchSignalSuspend = 45;  // ts_suspend_application

// Keep the two display transitions separate.  A quick off/on pair can deliver
// both signals before the watchdog thread runs, and collapsing them into one
// "last signal" loses the mandatory HBP mode 1 step.
volatile sig_atomic_t gResumePending = 0;
volatile sig_atomic_t gSuspendPending = 0;
volatile sig_atomic_t gTerminateRequested = 0;

void touchSignalHandler(int signal) {
    if (signal == kTouchSignalResume) {
        gResumePending = 1;
    } else if (signal == kTouchSignalSuspend) {
        gSuspendPending = 1;
    } else if (signal == SIGTERM || signal == SIGINT) {
        gTerminateRequested = 1;
    }
}

void installTouchSignalHandlers() {
    struct sigaction action = {};
    action.sa_handler = touchSignalHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    for (int signal = kTouchSignalFirst; signal <= kTouchSignalLast; ++signal) {
        if (sigaction(signal, &action, nullptr) != 0) {
            LOG(WARNING) << "sigaction(" << signal << ") failed: "
                         << std::strerror(errno);
        }
    }
    if (sigaction(SIGTERM, &action, nullptr) != 0) {
        LOG(WARNING) << "sigaction(SIGTERM) failed: " << std::strerror(errno);
    }
    if (sigaction(SIGINT, &action, nullptr) != 0) {
        LOG(WARNING) << "sigaction(SIGINT) failed: " << std::strerror(errno);
    }
}

// HBP geometry used by the S3910 host-processing algorithm.  The algorithm
// itself is compiled for 23040 x 50688; the panel can override the reported
// geometry but the point package is in algorithm coordinates.
constexpr int kAlgoMaxX = 23040;
constexpr int kAlgoMaxY = 50688;

std::string trimWhitespace(const std::string& value) {
    const auto begin = std::find_if_not(value.begin(), value.end(),
                                        [](unsigned char c) { return std::isspace(c); });
    const auto end = std::find_if_not(value.rbegin(), value.rend(),
                                      [](unsigned char c) { return std::isspace(c); }).base();
    if (begin >= end) {
        return {};
    }
    return std::string(begin, end);
}

std::vector<std::string> findConfigs(const char* filename) {
    std::vector<std::string> paths;
    std::set<std::string> seen;

    const auto add = [&](const std::string& path) {
        if (seen.insert(path).second && access(path.c_str(), R_OK) == 0) {
            paths.push_back(path);
        }
    };

    add(std::string("/odm/firmware/tp/22825/") + filename);
    add(std::string("/vendor/firmware/tp/22825/") + filename);
    add(std::string("/odm/firmware/tp/") + filename);
    add(std::string("/vendor/firmware/tp/") + filename);
    // The stock daemon also accepts per-device overrides from the writable
    // touchconfig directory.  Keep the packaged ODM copy as the primary
    // source so a stale data copy cannot silently change the panel.
    add(std::string("/data/vendor/touchconfig/") + filename);

    const std::string patterns[] = {
            std::string("/odm/firmware/tp/*/") + filename,
            std::string("/vendor/firmware/tp/*/") + filename,
    };
    for (const auto& pattern : patterns) {
        glob_t matches{};
        if (glob(pattern.c_str(), GLOB_NOSORT, nullptr, &matches) == 0) {
            for (size_t i = 0; i < matches.gl_pathc; ++i) {
                add(matches.gl_pathv[i]);
            }
        }
        globfree(&matches);
    }

    return paths;
}

int32_t readFile(const char* path, std::string* result) {
    if (result == nullptr) {
        return -1;
    }
    result->clear();

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    char buffer[4096];
    ssize_t count;
    do {
        count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            result->append(buffer, static_cast<size_t>(count));
        }
    } while (count > 0 || (count < 0 && errno == EINTR));
    const int savedErrno = errno;
    close(fd);
    if (count < 0) {
        errno = savedErrno;
        return -1;
    }
    return static_cast<int32_t>(result->size());
}

std::string readFileString(const char* path) {
    std::string value;
    if (readFile(path, &value) < 0) {
        return {};
    }
    return trimWhitespace(value);
}

bool readBooleanNode(const char* path) {
    const std::string value = readFileString(path);
    if (value.empty()) {
        return false;
    }
    char* end = nullptr;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    return end != value.c_str() && parsed != 0;
}

int readIntNode(const char* path, int fallback) {
    const std::string value = readFileString(path);
    if (value.empty()) {
        return fallback;
    }
    char* end = nullptr;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    if (end == value.c_str()) {
        return fallback;
    }
    return static_cast<int>(parsed);
}

bool screenStateIsOn() {
    char value[PROP_VALUE_MAX] = {};
    property_get(kScreenStateProperty, value, "2");
    const int state = std::atoi(value);
    // Display.STATE_ON=2, STATE_VR=5, STATE_ON_SUSPEND=6.
    return state == 2 || state == 5 || state == 6;
}

std::vector<std::string> splitLines(const std::string& value) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start <= value.size()) {
        const size_t end = value.find('\n', start);
        if (end == std::string::npos) {
            lines.push_back(value.substr(start));
            break;
        }
        lines.push_back(value.substr(start, end - start));
        start = end + 1;
    }
    return lines;
}

std::string findFirstGlob(const std::string& pattern) {
    glob_t matches{};
    std::string result;
    if (glob(pattern.c_str(), GLOB_NOSORT, nullptr, &matches) == 0) {
        for (size_t i = 0; i < matches.gl_pathc; ++i) {
            if (access(matches.gl_pathv[i], R_OK) == 0) {
                result = matches.gl_pathv[i];
                break;
            }
        }
    }
    globfree(&matches);
    return result;
}

std::string resolveFirmwareFile(const std::string& directory, const std::string& name) {
    std::vector<std::string> roots;
    if (!directory.empty() && directory[0] == '/') {
        roots.push_back(directory);
    } else {
        // /proc/devinfo/tp reports the relative firmware path used by the
        // kernel request_firmware() search (for example
        // "tp/22825/FW_S3910_TIANMA_HBP.img").
        roots.push_back("/odm/firmware/" + directory);
        roots.push_back("/vendor/firmware/" + directory);
        roots.push_back("/etc/firmware/" + directory);
    }

    for (const auto& root : roots) {
        const std::string path = root + "/" + name;
        if (access(path.c_str(), R_OK) == 0) {
            return path;
        }
    }
    return roots.empty() ? std::string() : roots.front() + "/" + name;
}

enum class TouchPanelVendor {
    Unknown,
    Boe,
    Tianma,
};

std::string uppercase(std::string value) {
    for (char& character : value) {
        character = static_cast<char>(
                std::toupper(static_cast<unsigned char>(character)));
    }
    return value;
}

TouchPanelVendor panelVendorFromText(const std::string& text) {
    const std::string upper = uppercase(text);
    if (upper.find("TIANMA") != std::string::npos) {
        return TouchPanelVendor::Tianma;
    }
    if (upper.find("BOE") != std::string::npos) {
        return TouchPanelVendor::Boe;
    }
    return TouchPanelVendor::Unknown;
}

const char* panelVendorName(TouchPanelVendor vendor) {
    switch (vendor) {
        case TouchPanelVendor::Boe:
            return "BOE";
        case TouchPanelVendor::Tianma:
            return "TIANMA";
        default:
            return "";
    }
}

struct FirmwarePaths {
    std::string fw_path;
    std::string manufacture;
    std::string directory;
    std::string vendor;
    std::string hal;
    std::string algo;
    std::string ifp;
};

FirmwarePaths resolveFirmwarePaths() {
    FirmwarePaths paths;

    const std::string info = readFileString(kFirmwareInfoNode);
    for (const auto& line : splitLines(info)) {
        const std::string trimmed = trimWhitespace(line);
        if (trimmed.rfind("Device fw_path:", 0) == 0) {
            paths.fw_path = trimWhitespace(trimmed.substr(std::strlen("Device fw_path:")));
        } else if (trimmed.rfind("Device manufacture:", 0) == 0) {
            paths.manufacture =
                    trimWhitespace(trimmed.substr(std::strlen("Device manufacture:")));
        }
    }

    if (!paths.fw_path.empty()) {
        const size_t slash = paths.fw_path.find_last_of('/');
        if (slash != std::string::npos) {
            paths.directory = paths.fw_path.substr(0, slash);
        }

        const size_t start = paths.fw_path.find("FW_S3910_");
        if (start != std::string::npos) {
            const size_t vendorStart = start + std::strlen("FW_S3910_");
            size_t vendorEnd = paths.fw_path.find("_HBP", vendorStart);
            if (vendorEnd == std::string::npos) {
                vendorEnd = paths.fw_path.find(".img", vendorStart);
            }
            if (vendorEnd != std::string::npos) {
                paths.vendor = paths.fw_path.substr(vendorStart, vendorEnd - vendorStart);
            }
        }
    }

    // The HBP driver exposes the panel vendor through "Device manufacture:"
    // (for example BOE_HBP / TIANMA_HBP).  The older fw_path-only parse is
    // kept first for images that include the _HBP suffix, but manufacture is
    // authoritative when fw_path is absent or does not contain a vendor.
    if (panelVendorFromText(paths.vendor) == TouchPanelVendor::Unknown) {
        const TouchPanelVendor manufactureVendor =
                panelVendorFromText(paths.manufacture);
        if (manufactureVendor != TouchPanelVendor::Unknown) {
            paths.vendor = panelVendorName(manufactureVendor);
        }
    }

    const std::string directory = paths.directory.empty() ? "tp/22825" : paths.directory;
    if (!paths.vendor.empty()) {
        paths.hal = resolveFirmwareFile(
                directory, "LIB_S3910_" + paths.vendor + "_HBP_TS_HAL.so");
        paths.algo = resolveFirmwareFile(
                directory, "LIB_S3910_" + paths.vendor + "_HBP_TS_ALGO.so");
        paths.ifp = resolveFirmwareFile(directory, "libIfp.so");
    } else {
        // This project ships BOE and TIANMA builds.  Prefer BOE when the
        // kernel has not exposed a usable panel identifier yet.
        for (const char* vendor : {"BOE", "TIANMA"}) {
            const std::string hal = resolveFirmwareFile(
                    directory, std::string("LIB_S3910_") + vendor + "_HBP_TS_HAL.so");
            if (access(hal.c_str(), R_OK) == 0) {
                paths.vendor = vendor;
                paths.hal = hal;
                paths.algo = resolveFirmwareFile(
                        directory, std::string("LIB_S3910_") + vendor + "_HBP_TS_ALGO.so");
                paths.ifp = resolveFirmwareFile(directory, "libIfp.so");
                break;
            }
        }
    }

    if (paths.hal.empty() || access(paths.hal.c_str(), R_OK) != 0) {
        paths.hal = findFirstGlob("/odm/firmware/tp/*/LIB_S3910_*_HBP_TS_HAL.so");
        if (paths.hal.empty()) {
            paths.hal = findFirstGlob("/vendor/firmware/tp/*/LIB_S3910_*_HBP_TS_HAL.so");
        }
    }

    if (paths.algo.empty() || access(paths.algo.c_str(), R_OK) != 0) {
        if (!paths.hal.empty()) {
            const size_t slash = paths.hal.find_last_of('/');
            const std::string dir = slash == std::string::npos ? "" : paths.hal.substr(0, slash);
            const size_t libStart = paths.hal.find("LIB_S3910_");
            const size_t vendorEnd = paths.hal.find("_HBP_TS_HAL.so");
            if (!dir.empty() && libStart != std::string::npos && vendorEnd != std::string::npos) {
                paths.algo = dir + "/" + paths.hal.substr(libStart, vendorEnd - libStart) +
                             "_HBP_TS_ALGO.so";
            }
        }
        if (paths.algo.empty() || access(paths.algo.c_str(), R_OK) != 0) {
            paths.algo = findFirstGlob("/odm/firmware/tp/*/LIB_S3910_*_HBP_TS_ALGO.so");
            if (paths.algo.empty()) {
                paths.algo = findFirstGlob("/vendor/firmware/tp/*/LIB_S3910_*_HBP_TS_ALGO.so");
            }
        }
    }

    if (paths.ifp.empty() || access(paths.ifp.c_str(), R_OK) != 0) {
        paths.ifp = findFirstGlob("/odm/firmware/tp/*/libIfp.so");
        if (paths.ifp.empty()) {
            paths.ifp = findFirstGlob("/vendor/firmware/tp/*/libIfp.so");
        }
    }

    return paths;
}

struct TouchGeometry {
    int rows = 17;
    int cols = 38;
};

TouchGeometry readTouchGeometry() {
    TouchGeometry geometry;
    const std::string value = readFileString(kMainRegisterNode);
    if (value.empty()) {
        return geometry;
    }

    for (const auto& line : splitLines(value)) {
        const std::string trimmed = trimWhitespace(line);
        const auto readNumber = [&](const char* marker, int* out) {
            const size_t position = trimmed.find(marker);
            if (position == std::string::npos) {
                return;
            }
            const std::string number =
                    trimWhitespace(trimmed.substr(position + std::strlen(marker)));
            char* end = nullptr;
            const long parsed = std::strtol(number.c_str(), &end, 10);
            if (end != number.c_str() && parsed > 0 && parsed <= 64) {
                *out = static_cast<int>(parsed);
            }
        };
        readNumber("num_of_image_rows:", &geometry.rows);
        readNumber("num_of_image_cols:", &geometry.cols);
    }

    return geometry;
}

std::string eventPathFromBlock(const std::string& block) {
    const size_t handlers = block.find("Handlers=");
    if (handlers == std::string::npos) {
        return {};
    }
    const size_t lineEnd = block.find('\n', handlers);
    const std::string line = block.substr(
            handlers, lineEnd == std::string::npos ? std::string::npos : lineEnd - handlers);
    const size_t event = line.find("event");
    if (event == std::string::npos) {
        return {};
    }
    size_t numberEnd = event + std::strlen("event");
    while (numberEnd < line.size() &&
           std::isdigit(static_cast<unsigned char>(line[numberEnd]))) {
        ++numberEnd;
    }
    if (numberEnd == event + std::strlen("event")) {
        return {};
    }
    return "/dev/input/" + line.substr(event, numberEnd - event);
}

std::string findTouchInputDevice() {
    std::string devices;
    std::string fallback;
    if (readFile("/proc/bus/input/devices", &devices) > 0) {
        size_t start = 0;
        while (start < devices.size()) {
            const size_t end = devices.find("\n\n", start);
            const std::string block =
                    devices.substr(start, end == std::string::npos ? std::string::npos : end - start);

            if (block.find("s_tcm/touch_input") != std::string::npos) {
                const std::string path = eventPathFromBlock(block);
                if (!path.empty()) {
                    return path;
                }
            }
            if (fallback.empty() &&
                (block.find("synaptics") != std::string::npos ||
                 block.find("touchpanel") != std::string::npos)) {
                fallback = eventPathFromBlock(block);
            }

            if (end == std::string::npos) {
                break;
            }
            start = end + 2;
        }
    }
    if (!fallback.empty()) {
        return fallback;
    }

    for (int i = 0; i < 64; ++i) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/input/event%d", i);
        const int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            continue;
        }
        char name[128] = {};
        const bool match = ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name) >= 0 &&
                           (std::strstr(name, "synaptics") != nullptr ||
                            std::strstr(name, "touchpanel") != nullptr);
        close(fd);
        if (match) {
            return path;
        }
    }

    return {};
}

// ---------------------------------------------------------------------------
// Vendor HBP core / IFP / THP ABI
// ---------------------------------------------------------------------------

// synaBlobData_t from synaTypes.h.  The HBP core passes it by value in the
// callback, so the declaration has to match the vendor header exactly.
struct SynaBlobData {
    uint32_t length;
    uint8_t* pData;
};

// tcmActionInfo_t from tcm.h.
struct TcmActionInfo {
    uint32_t actionId;
    uint32_t actionParam;
};

using TcmHandle = void*;
using TcmEventCallback = void (*)(void*, uint32_t, SynaBlobData);

// FrameDataParse is the frame package consumed by IFrameDataParse().  The
// vendor algorithm reads the five data pointers, the five sizes, and the
// status fields at 0x3c..0x62.  The layout is fixed by the stock daemon.
struct FrameDataParse {
    uint8_t* matrix;          // 0x00
    uint8_t* col_a;           // 0x08
    uint8_t* row_a;           // 0x10
    uint8_t* col_b;           // 0x18
    uint8_t* row_b;           // 0x20
    uint32_t matrix_size;     // 0x28
    uint32_t col_a_size;      // 0x2c
    uint32_t row_a_size;      // 0x30
    uint32_t col_b_size;      // 0x34
    uint32_t row_b_size;      // 0x38
    uint16_t field3c;         // 0x3c
    uint8_t field3e;          // 0x3e
    uint8_t pad3f;            // 0x3f
    uint16_t frame_index;     // 0x40
    uint16_t charger;         // 0x42
    uint16_t game;            // 0x44
    uint16_t temperature;     // 0x46
    uint16_t field48;         // 0x48
    uint16_t field4a;         // 0x4a
    uint16_t field4c;         // 0x4c
    uint16_t field4e;         // 0x4e
    uint16_t field50;         // 0x50
    uint16_t field52;         // 0x52
    uint16_t time_since_last; // 0x54
    uint32_t field58;         // 0x58
    uint8_t field5c;          // 0x5c
    uint8_t flags;            // 0x5d
    uint16_t field5e;         // 0x5e
    uint16_t field60;         // 0x60
    uint16_t field62;         // 0x62
    uint8_t pad[0x0c];        // 0x64..0x6f
};
static_assert(sizeof(FrameDataParse) == 0x70, "FrameDataParse ABI");

// libIfp.so writes this package into the HAL report buffer.  raw points at a
// heap buffer holding (rows * cols + rows + cols) * 2 bytes.  The first two
// words are the raw size and a reserved word; the pointer is at 0x08.
struct IfpReport {
    uint32_t raw_size;        // 0x00
    uint32_t reserved;        // 0x04
    uint8_t* raw;             // 0x08
    uint64_t meta0;           // 0x10
    uint64_t meta1;           // 0x18
    uint64_t meta2;           // 0x20
    uint64_t meta3;           // 0x28
};

// IGetAlgoPoint() package.  The point records start at offset 4 and are 0x14
// bytes each.  The BOE implementation treats a size argument of 0xf9 or more
// as invalid and logs the misleading "reportData is NULL" error; callers must
// pass the 0xf8-byte payload size even though the output buffer is larger.
struct AlgoPoint {
    uint8_t status;           // 0x00
    uint8_t reserved1;        // 0x01
    uint16_t x;               // 0x02
    uint16_t y;               // 0x04
    uint16_t id;              // 0x06
    uint8_t z;                // 0x08
    uint8_t width;            // 0x09
    uint16_t touch_major;     // 0x0a
    uint32_t algo_status;     // 0x0c
    uint8_t fp_flag;          // 0x10
    uint8_t reserved2[3];     // 0x11
};
static_assert(sizeof(AlgoPoint) == 0x14, "AlgoPoint ABI");

// IGetAftInfo() returns ten 4-byte records.  sidePalmPressProc() sets both
// press values to 2 and both error bytes to 0xff for a side palm.  The BOE
// implementation treats a size argument of 0x29 or more as invalid and logs
// "size is error, aftReportData"; callers must pass the 0x28-byte payload
// size even though the output buffer is larger.
struct AlgoAftInfo {
    uint8_t tx_press;
    uint8_t rx_press;
    uint8_t tx_er;
    uint8_t rx_er;
};
static_assert(sizeof(AlgoAftInfo) == 4, "AlgoAftInfo ABI");

// BOE algorithm libraries expose the context-based IAlgoOpen/IAlgoInit pair;
// TIANMA libraries expose the older IThpAlgoInit entry point instead.
using IAlgoOpen = uint32_t (*)(void**);
using IAlgoInit = uint32_t (*)(void*, void*, uint32_t);
using IThpAlgoInit = uint32_t (*)(void**);
using IThpAlgoProcess = uint32_t (*)(void*);
using IFrameDataParse = void (*)(void*, FrameDataParse*);
using IGetAlgoPoint = uint32_t (*)(void*, void*, int);
using IGetAlgoInsertRealPoint = uint32_t (*)(void*, void*, int);
using IGetAftInfo = uint32_t (*)(void*, void*, int);
using IGetAlgoInfo = uint32_t (*)(void*, int, void*, uint32_t);
using IThpAlgoGetParam = uint32_t (*)(void*, uint32_t, uint32_t*);
using IThpAlgoSetParam = uint32_t (*)(void*, uint32_t, uint32_t);
using IThpAlgoGetMode = uint32_t (*)(void*, uint32_t*);
using IThpAlgoSetMode = uint32_t (*)(void*, uint8_t);
using IAlgoHardwareInfo = uint32_t (*)(void*, void*, uint32_t);
using IAlgoPostInit = uint32_t (*)(void*);
using IAlgoSetInfo = uint32_t (*)(void*, uint32_t, const void*, uint32_t);
using IAlgoConfigRead = int (*)(uint8_t, const char*, void*, int);
using IAlgoSetConfigReadCallback = uint32_t (*)(void*, IAlgoConfigRead);
using IThpAlgoUninit = void (*)(void*);

struct AlgoApi {
    IAlgoOpen open = nullptr;
    IAlgoInit init = nullptr;
    IThpAlgoInit thpInit = nullptr;
    IThpAlgoProcess process = nullptr;
    IFrameDataParse frameParse = nullptr;
    IGetAlgoPoint getPoint = nullptr;
    IGetAlgoInsertRealPoint getInsertRealPoint = nullptr;
    IGetAftInfo getAftInfo = nullptr;
    IGetAlgoInfo getAlgoInfo = nullptr;
    IThpAlgoGetParam getParam = nullptr;
    IThpAlgoSetParam setParam = nullptr;
    IThpAlgoGetMode getMode = nullptr;
    IThpAlgoSetMode setMode = nullptr;
    IAlgoHardwareInfo hardwareInfo = nullptr;
    IAlgoPostInit postInit = nullptr;
    IAlgoSetInfo setInfo = nullptr;
    IAlgoSetConfigReadCallback setConfigReadCallback = nullptr;
    IThpAlgoUninit uninit = nullptr;
};

// ---------------------------------------------------------------------------
// Input reporting
// ---------------------------------------------------------------------------

struct TouchPoint {
    int id;
    int x;
    int y;
    int z;
    int width;
    int touch_major;
};

class TouchReporter {
  public:
    ~TouchReporter() {
        close();
    }

    bool open() {
        std::lock_guard<std::recursive_mutex> lock(mMutex);
        close();

        const std::string path = findTouchInputDevice();
        if (path.empty()) {
            LOG(WARNING) << "touch input device not found";
            return false;
        }

        mFd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
        if (mFd < 0) {
            mFd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
        }
        if (mFd < 0) {
            LOG(WARNING) << "cannot open " << path << ": " << std::strerror(errno);
            return false;
        }

        mPath = path;
        queryAbs(ABS_MT_POSITION_X, &mAbsXMax, kAlgoMaxX);
        queryAbs(ABS_MT_POSITION_Y, &mAbsYMax, kAlgoMaxY);
        queryAbs(ABS_MT_PRESSURE, &mAbsPressureMax, 255);
        queryAbs(ABS_MT_TOUCH_MAJOR, &mAbsTouchMajorMax, 255);
        queryAbs(ABS_MT_WIDTH_MAJOR, &mAbsWidthMajorMax, 255);

        mEvents.clear();
        mEvents.reserve(128);

        for (int i = 0; i < kMaxSlots; ++i) {
            mSlotForId[i] = -1;
            mIdForSlot[i] = -1;
            mDown[i] = false;
        }
        mButtonDown = false;
        mNextTrackingId = 1;

        LOG(INFO) << "HBP touch input: " << mPath << " abs=" << mAbsXMax << "x" << mAbsYMax;
        return true;
    }

    void close() {
        std::lock_guard<std::recursive_mutex> lock(mMutex);
        if (mFd >= 0) {
            releaseAll();
            ::close(mFd);
            mFd = -1;
        }
        mPath.clear();
    }

    // The fingerprint notifier consumes display coordinates, which are the
    // same range as the touch input device.  Reuse the reporter's scaling so
    // the trigger coordinates match normal touch reporting exactly.
    int mapX(int value) const {
        std::lock_guard<std::recursive_mutex> lock(mMutex);
        return scale(value, kAlgoMaxX, mAbsXMax);
    }

    int mapY(int value) const {
        std::lock_guard<std::recursive_mutex> lock(mMutex);
        return scale(value, kAlgoMaxY, mAbsYMax);
    }

    bool valid() const {
        std::lock_guard<std::recursive_mutex> lock(mMutex);
        return mFd >= 0;
    }

    void releaseAll() {
        std::lock_guard<std::recursive_mutex> lock(mMutex);
        if (mFd < 0) {
            return;
        }

        mEvents.clear();
        for (int slot = 0; slot < kMaxSlots; ++slot) {
            if (!mDown[slot]) {
                continue;
            }
            appendEvent(&mEvents, EV_ABS, ABS_MT_SLOT, slot);
            appendEvent(&mEvents, EV_ABS, ABS_MT_TRACKING_ID, -1);
            mDown[slot] = false;
            const int id = mIdForSlot[slot];
            if (id >= 0 && id < kMaxSlots) {
                mSlotForId[id] = -1;
            }
            mIdForSlot[slot] = -1;
        }
        if (mButtonDown) {
            appendEvent(&mEvents, EV_KEY, BTN_TOUCH, 0);
            appendEvent(&mEvents, EV_KEY, BTN_TOOL_FINGER, 0);
            mButtonDown = false;
        }
        if (!mEvents.empty()) {
            appendEvent(&mEvents, EV_SYN, SYN_REPORT, 0);
            writeEvents(mEvents);
        }
    }

    void report(std::span<const TouchPoint> points) {
        std::lock_guard<std::recursive_mutex> lock(mMutex);
        if (mFd < 0) {
            return;
        }

        const TouchPoint* desiredPoint[kMaxSlots];
        for (int i = 0; i < kMaxSlots; ++i) {
            desiredPoint[i] = nullptr;
        }

        // Assign stable slots by vendor point id.  When an id disappears the
        // slot is released and can be reused by a later point.
        for (const auto& point : points) {
            const int id = (point.id >= 0 && point.id < kMaxSlots) ? point.id : -1;
            int slot = -1;
            if (id >= 0 && mSlotForId[id] >= 0 &&
                (!mDown[mSlotForId[id]] || mIdForSlot[mSlotForId[id]] == id)) {
                slot = mSlotForId[id];
            } else {
                for (int candidate = 0; candidate < kMaxSlots; ++candidate) {
                    if (!mDown[candidate] && desiredPoint[candidate] == nullptr) {
                        slot = candidate;
                        break;
                    }
                }
            }
            if (slot < 0 || desiredPoint[slot] != nullptr) {
                continue;
            }
            desiredPoint[slot] = &point;
            if (id >= 0) {
                mSlotForId[id] = slot;
            }
            mIdForSlot[slot] = id;
        }

        mEvents.clear();
        bool anyDown = false;

        for (int slot = 0; slot < kMaxSlots; ++slot) {
            if (desiredPoint[slot] != nullptr) {
                anyDown = true;
            }
        }

        if (anyDown && !mButtonDown) {
            appendEvent(&mEvents, EV_KEY, BTN_TOUCH, 1);
            appendEvent(&mEvents, EV_KEY, BTN_TOOL_FINGER, 1);
            mButtonDown = true;
        }

        for (int slot = 0; slot < kMaxSlots; ++slot) {
            const TouchPoint* point = desiredPoint[slot];
            if (point == nullptr) {
                if (mDown[slot]) {
                    appendEvent(&mEvents, EV_ABS, ABS_MT_SLOT, slot);
                    appendEvent(&mEvents, EV_ABS, ABS_MT_TRACKING_ID, -1);
                    mDown[slot] = false;
                    const int id = mIdForSlot[slot];
                    if (id >= 0 && id < kMaxSlots) {
                        mSlotForId[id] = -1;
                    }
                    mIdForSlot[slot] = -1;
                }
                continue;
            }

            appendEvent(&mEvents, EV_ABS, ABS_MT_SLOT, slot);
            if (!mDown[slot]) {
                mDownTrackingId[slot] = mNextTrackingId++;
                appendEvent(&mEvents, EV_ABS, ABS_MT_TRACKING_ID, mDownTrackingId[slot]);
                mDown[slot] = true;
            }
            appendEvent(&mEvents, EV_ABS, ABS_MT_POSITION_X, scale(point->x, kAlgoMaxX, mAbsXMax));
            appendEvent(&mEvents, EV_ABS, ABS_MT_POSITION_Y, scale(point->y, kAlgoMaxY, mAbsYMax));
            appendEvent(&mEvents, EV_ABS, ABS_MT_PRESSURE,
                        scale(point->z, 255, mAbsPressureMax));
            appendEvent(&mEvents, EV_ABS, ABS_MT_TOUCH_MAJOR,
                        scale(std::min(point->width, 255), 255, mAbsTouchMajorMax));
            appendEvent(&mEvents, EV_ABS, ABS_MT_WIDTH_MAJOR,
                        scale(std::min(point->touch_major, 255), 255, mAbsWidthMajorMax));
            appendEvent(&mEvents, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
        }

        if (!anyDown && mButtonDown) {
            appendEvent(&mEvents, EV_KEY, BTN_TOUCH, 0);
            appendEvent(&mEvents, EV_KEY, BTN_TOOL_FINGER, 0);
            mButtonDown = false;
        }

        if (!mEvents.empty()) {
            appendEvent(&mEvents, EV_SYN, SYN_REPORT, 0);
            writeEvents(mEvents);
        }
    }

  private:
    static constexpr int kMaxSlots = 10;

    static int scale(int value, int sourceMax, int targetMax) {
        if (sourceMax <= 0 || targetMax <= 0) {
            return value;
        }
        return static_cast<int>((static_cast<int64_t>(value) * targetMax) / sourceMax);
    }

    void queryAbs(int code, int* max, int fallback) {
        struct input_absinfo info = {};
        if (ioctl(mFd, EVIOCGABS(code), &info) == 0 && info.maximum > 0) {
            *max = info.maximum;
        } else {
            *max = fallback;
        }
    }

    static void appendEvent(std::vector<struct input_event>* events, uint16_t type,
                            uint16_t code, int32_t value) {
        struct input_event event = {};
        event.type = type;
        event.code = code;
        event.value = value;
        events->push_back(event);
    }

    void writeEvents(const std::vector<struct input_event>& events) {
        size_t written = 0;
        const auto* data = reinterpret_cast<const char*>(events.data());
        const size_t size = events.size() * sizeof(struct input_event);
        while (written < size) {
            const ssize_t count = write(mFd, data + written, size - written);
            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                LOG(ERROR) << "failed to write touch event: " << std::strerror(errno);
                return;
            }
            if (count == 0) {
                return;
            }
            written += static_cast<size_t>(count);
        }
    }

    int mFd = -1;
    mutable std::recursive_mutex mMutex;
    std::string mPath;
    // Reused event scratch; report()/releaseAll() are serialized by mMutex.
    std::vector<struct input_event> mEvents;
    int mAbsXMax = kAlgoMaxX;
    int mAbsYMax = kAlgoMaxY;
    int mAbsPressureMax = 255;
    int mAbsTouchMajorMax = 255;
    int mAbsWidthMajorMax = 255;
    int mSlotForId[kMaxSlots] = {};
    int mIdForSlot[kMaxSlots] = {};
    int mDownTrackingId[kMaxSlots] = {};
    bool mDown[kMaxSlots] = {};
    bool mButtonDown = false;
    int mNextTrackingId = 1;
};

// ---------------------------------------------------------------------------
// Vendor configuration helpers
// ---------------------------------------------------------------------------

std::vector<int> parseCsvInts(const std::string& value) {
    std::vector<int> result;
    size_t start = 0;
    while (start < value.size()) {
        const size_t end = value.find(',', start);
        const std::string token = trimWhitespace(
                value.substr(start, end == std::string::npos ? std::string::npos : end - start));
        char* parseEnd = nullptr;
        const long parsed = std::strtol(token.c_str(), &parseEnd, 10);
        if (parseEnd != token.c_str()) {
            result.push_back(static_cast<int>(parsed));
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return result;
}

int readEdgeGripLevel() {
    char value[PROP_VALUE_MAX] = {};
    property_get("persist.vendor.edge_grip_suppression", value, "3");

    char* end = nullptr;
    long level = std::strtol(value, &end, 10);
    if (end == value) {
        level = 3;
    }
    if (level < 0) {
        level = 0;
    } else if (level > 5) {
        level = 5;
    }
    return static_cast<int>(level);
}

bool readHbpPreventionEnabled() {
    char value[PROP_VALUE_MAX] = {};
    // Stock initializes userspace prevention whenever the panel DTS carries
    // kernel_grip_support, which this platform does.  Keep the property as a
    // diagnostic override only; unset must mean enabled.
    property_get(kPreventionProperty, value, "1");
    return std::strcmp(value, "0") != 0 && std::strcmp(value, "false") != 0;
}

bool readHbpDebugPointsEnabled() {
    char value[PROP_VALUE_MAX] = {};
    property_get(kDebugPointsProperty, value, "0");
    return std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0;
}

// ---------------------------------------------------------------------------
// Vendor THP algorithm feature configuration
// ---------------------------------------------------------------------------

struct AlgoFeaturePanel {
    int id = -1;
    std::string name;
    std::map<std::string, std::vector<int>> params;

    const std::vector<int>* find(const char* key) const {
        if (key == nullptr) {
            return nullptr;
        }
        const auto entry = params.find(key);
        return entry == params.end() ? nullptr : &entry->second;
    }
};

struct AlgoFeatureConfig {
    std::vector<AlgoFeaturePanel> panels;
    int selected_id = -1;

    const AlgoFeaturePanel* find(int id) const {
        for (const auto& panel : panels) {
            if (panel.id == id) {
                return &panel;
            }
        }
        return nullptr;
    }

    const AlgoFeaturePanel* selected() const {
        if (const AlgoFeaturePanel* panel = find(selected_id); panel != nullptr) {
            return panel;
        }
        return panels.empty() ? nullptr : &panels.front();
    }

    size_t keyCount() const {
        const AlgoFeaturePanel* panel = selected();
        return panel == nullptr ? 0 : panel->params.size();
    }
};

std::atomic<const AlgoFeatureConfig*> gActiveAlgoConfig{nullptr};

// The stock ALGO callback serves more than the AlgoParam file.  configLoad()
// also asks it for TouchConfig values such as palm_mode_support,
// hbp_algo_diff_support, panel-coords, tx-rx-num, and smooth/sensitive level.
// Merge those into the selected panel's map, keeping ALGO-specific values
// authoritative if both files define the same key.
void mergeTouchFeatureConfig(const std::string& panel_hint,
                             AlgoFeatureConfig* config) {
    if (config == nullptr) {
        return;
    }

    const auto paths = findConfigs(kFeatureConfigName);
    if (paths.empty()) {
        LOG(WARNING) << "no " << kFeatureConfigName
                     << " found; ALGO compatibility keys will use defaults";
        return;
    }

    tinyxml2::XMLDocument document;
    if (document.LoadFile(paths.front().c_str()) != tinyxml2::XML_SUCCESS) {
        LOG(WARNING) << "cannot parse " << paths.front() << ": "
                     << document.ErrorStr();
        return;
    }

    const tinyxml2::XMLElement* root = document.RootElement();
    if (root == nullptr) {
        return;
    }

    const tinyxml2::XMLElement* target_panel = nullptr;
    const tinyxml2::XMLElement* first_panel = nullptr;
    for (const tinyxml2::XMLElement* device = root->FirstChildElement("device");
         device != nullptr; device = device->NextSiblingElement("device")) {
        for (const tinyxml2::XMLElement* panel = device->FirstChildElement("panel");
             panel != nullptr; panel = panel->NextSiblingElement("panel")) {
            if (first_panel == nullptr) {
                first_panel = panel;
            }
            const char* name = panel->Attribute("name");
            if (!panel_hint.empty() && name != nullptr &&
                std::strstr(name, panel_hint.c_str()) != nullptr) {
                target_panel = panel;
            }
        }
    }
    if (target_panel == nullptr) {
        target_panel = first_panel;
    }
    if (target_panel == nullptr) {
        return;
    }

    const char* target_name = target_panel->Attribute("name");
    if (config->panels.empty()) {
        AlgoFeaturePanel panel;
        panel.id = target_panel->IntAttribute("id", 0);
        if (target_name != nullptr) {
            panel.name = target_name;
        }
        config->panels.push_back(std::move(panel));
        config->selected_id = config->panels.front().id;
    }

    AlgoFeaturePanel* destination = nullptr;
    for (auto& panel : config->panels) {
        if (target_name != nullptr && panel.name == target_name) {
            destination = &panel;
            break;
        }
    }
    if (destination == nullptr) {
        for (auto& panel : config->panels) {
            if (panel.id == config->selected_id) {
                destination = &panel;
                break;
            }
        }
    }
    if (destination == nullptr) {
        destination = &config->panels.front();
    }
    config->selected_id = destination->id;

    size_t merged = 0;
    for (const tinyxml2::XMLElement* modules =
                 target_panel->FirstChildElement("modules");
         modules != nullptr; modules = modules->NextSiblingElement("modules")) {
        for (const tinyxml2::XMLElement* param =
                     modules->FirstChildElement("param");
             param != nullptr; param = param->NextSiblingElement("param")) {
            const char* name = param->Attribute("name");
            const tinyxml2::XMLElement* value = param->FirstChildElement("value");
            if (name == nullptr || value == nullptr || value->GetText() == nullptr) {
                continue;
            }

            const std::vector<int> values = parseCsvInts(value->GetText());
            if (values.empty()) {
                continue;
            }

            const auto add = [&](const std::string& key) {
                if (destination->params.emplace(key, values).second) {
                    ++merged;
                }
            };

            add(name);
            if (std::strcmp(name, "touchpanel,smooth-level") == 0) {
                add("smooth-level");
            } else if (std::strcmp(name, "touchpanel,sensitive-level") == 0) {
                add("sensitive-level");
            } else if (std::strcmp(name, "panel-coords") == 0) {
                add("touchpanel,panel-coords");
            } else if (std::strcmp(name, "tx-rx-num") == 0) {
                add("touchpanel,tx-rx-num");
            } else if (std::strcmp(name, "grip_disable_level") == 0) {
                add("prevention,grip_disable_level");
            }
            if (std::strncmp(name, "prevention,", 11) == 0) {
                add(name + 11);
            }
        }
    }

    LOG(INFO) << "ALGO compatibility config: path=" << paths.front()
              << " panel=" << (target_name != nullptr ? target_name : "<none>")
              << " merged=" << merged
              << " total=" << destination->params.size();
}

AlgoFeatureConfig loadAlgoFeatureConfig(const std::string& panel_hint) {
    AlgoFeatureConfig config;

    const auto paths = findConfigs(kAlgoConfigName);
    if (paths.empty()) {
        LOG(WARNING) << "no " << kAlgoConfigName
                     << " found; vendor THP algorithm will use built-in defaults";
        mergeTouchFeatureConfig(panel_hint, &config);
        return config;
    }

    tinyxml2::XMLDocument document;
    if (document.LoadFile(paths.front().c_str()) != tinyxml2::XML_SUCCESS) {
        LOG(WARNING) << "cannot parse " << paths.front() << ": "
                     << document.ErrorStr();
        mergeTouchFeatureConfig(panel_hint, &config);
        return config;
    }

    const tinyxml2::XMLElement* root = document.RootElement();
    if (root == nullptr) {
        LOG(WARNING) << paths.front() << " has no root element";
        mergeTouchFeatureConfig(panel_hint, &config);
        return config;
    }

    if (const tinyxml2::XMLElement* version = root->FirstChildElement("version");
        version != nullptr && version->GetText() != nullptr) {
        LOG(INFO) << paths.front() << " version=" << version->GetText();
    }

    int panel_order = 0;
    for (const tinyxml2::XMLElement* device = root->FirstChildElement("device");
         device != nullptr; device = device->NextSiblingElement("device")) {
        for (const tinyxml2::XMLElement* panel = device->FirstChildElement("panel");
             panel != nullptr; panel = panel->NextSiblingElement("panel")) {
            AlgoFeaturePanel parsed;
            parsed.id = panel->IntAttribute("id", panel_order);
            if (const char* name = panel->Attribute("name"); name != nullptr) {
                parsed.name = name;
            }

            // The stock callback exposes every parameter from every module
            // in the selected panel.  Palm/AFT/anti-mistouch keys live in
            // separate modules (Palm, AFT, FeatureEn), not only AlgoParam.
            for (const tinyxml2::XMLElement* modules =
                         panel->FirstChildElement("modules");
                 modules != nullptr; modules = modules->NextSiblingElement("modules")) {
                for (const tinyxml2::XMLElement* param =
                             modules->FirstChildElement("param");
                     param != nullptr; param = param->NextSiblingElement("param")) {
                    const char* name = param->Attribute("name");
                    const tinyxml2::XMLElement* value =
                            param->FirstChildElement("value");
                    if (name == nullptr || value == nullptr ||
                        value->GetText() == nullptr) {
                        continue;
                    }

                    std::vector<int> values = parseCsvInts(value->GetText());
                    if (!values.empty()) {
                        parsed.params[name] = std::move(values);
                    }
                }
            }

            if (!parsed.name.empty() &&
                (!panel_hint.empty() &&
                 parsed.name.find(panel_hint) != std::string::npos)) {
                config.selected_id = parsed.id;
            } else if (panel_hint.empty() && config.selected_id < 0 &&
                       !parsed.name.empty()) {
                config.selected_id = parsed.id;
            }
            config.panels.push_back(std::move(parsed));
            ++panel_order;
        }
    }

    if (config.selected_id < 0 && !config.panels.empty()) {
        config.selected_id = config.panels.front().id;
    }

    mergeTouchFeatureConfig(panel_hint, &config);

    const AlgoFeaturePanel* selected = config.selected();
    LOG(INFO) << "ALGO feature config: path=" << paths.front()
              << " panel=" << (selected != nullptr ? selected->name : "<none>")
              << " id=" << config.selected_id
              << " keys=" << config.keyCount();

    if (selected != nullptr) {
        if (const std::vector<int>* anti =
                    selected->find("ANTI_MISTOUCH_ENABLE");
            anti != nullptr && !anti->empty()) {
            LOG(INFO) << "ALGO anti-mistouch=" << (*anti)[0];
        }
        if (const std::vector<int>* palm_pos = selected->find("palmPosThd");
            palm_pos != nullptr && !palm_pos->empty()) {
            LOG(INFO) << "ALGO palmPosThd=" << (*palm_pos)[0];
        }
        if (const std::vector<int>* palm_mode =
                    selected->find("palm_mode_support");
            palm_mode != nullptr && !palm_mode->empty()) {
            LOG(INFO) << "ALGO palm_mode_support=" << (*palm_mode)[0];
        }
        if (const std::vector<int>* algo_diff =
                    selected->find("hbp_algo_diff_support");
            algo_diff != nullptr && !algo_diff->empty()) {
            LOG(INFO) << "ALGO hbp_algo_diff_support=" << (*algo_diff)[0];
        }
    }

    return config;
}

// ---------------------------------------------------------------------------
// HBP userspace pipeline
// ---------------------------------------------------------------------------

class HbpPipeline {
  public:
    ~HbpPipeline() {
        stop();
    }

    bool start() {
        char value[PROP_VALUE_MAX] = {};
        property_get(kPipelineProperty, value, "1");
        if (std::strcmp(value, "0") == 0) {
            LOG(INFO) << "HBP userspace pipeline disabled by " << kPipelineProperty;
            return false;
        }

        mSawType4.store(false);
        mHaveLastFrame = false;
        mFrameIndex = 0;

        const FirmwarePaths paths = resolveFirmwarePaths();
        if (paths.hal.empty() || paths.algo.empty() || paths.ifp.empty()) {
            LOG(WARNING) << "HBP vendor libraries not found (hal=" << paths.hal
                         << " algo=" << paths.algo << " ifp=" << paths.ifp << ")";
            return false;
        }
        if (access("/dev/tcm_hbp0", R_OK | W_OK) != 0) {
            LOG(INFO) << "/dev/tcm_hbp0 is not available; kernel HBP path remains: "
                      << std::strerror(errno);
            return false;
        }

        LOG(INFO) << "HBP libraries: hal=" << paths.hal << " algo=" << paths.algo
                  << " ifp=" << paths.ifp;
        LOG(INFO) << "HBP device info: fw_path=" << paths.fw_path
                  << " manufacture=" << paths.manufacture
                  << " vendor=" << paths.vendor;

        // The library paths are authoritative for the ABI and point layout;
        // /proc/devinfo/tp is only the hint used to select them.
        mPanelVendor = panelVendorFromText(paths.algo);
        if (mPanelVendor == TouchPanelVendor::Unknown) {
            mPanelVendor = panelVendorFromText(paths.hal);
        }
        if (mPanelVendor == TouchPanelVendor::Unknown) {
            mPanelVendor = panelVendorFromText(paths.vendor);
        }
        if (mPanelVendor == TouchPanelVendor::Unknown) {
            mPanelVendor = panelVendorFromText(paths.manufacture);
        }
        const std::string panelHint = panelVendorName(mPanelVendor);
        LOG(INFO) << "HBP panel vendor: "
                  << (panelHint.empty() ? "<unknown>" : panelHint);

        // Stock passes sys_touch_algo_feature_config.xml to the vendor THP
        // algorithm through IAlgoSetConfigReadCallback().  These values enable
        // anti-mistouch and set the panel-specific palm/AFT thresholds; the
        // library's built-in defaults are not equivalent.
        mAlgoConfig = loadAlgoFeatureConfig(panelHint);
        mPreventionEnabled = readHbpPreventionEnabled();
        mDebugPoints = readHbpDebugPointsEnabled();

        mPalmModeSupport = false;
        if (const AlgoFeaturePanel* panel = mAlgoConfig.selected(); panel != nullptr) {
            if (const std::vector<int>* palm_mode = panel->find("palm_mode_support");
                palm_mode != nullptr && !palm_mode->empty()) {
                mPalmModeSupport = (*palm_mode)[0] != 0;
            }
        }
        char project[PROP_VALUE_MAX] = {};
        property_get("ro.boot.prjname", project, "");
        if (std::strncmp(project, "22851", 5) == 0) {
            mPalmModeSupport = true;
        }
        LOG(INFO) << "HBP palm mode support: "
                  << (mPalmModeSupport ? "enabled" : "disabled");

        // The HBP core loads this library itself when tcmInitModule() calls
        // tfpInitModule().  It must be set before the first module init.
        property_set(kCustomIfpProperty, paths.ifp.c_str());

        if (!loadHal(paths.hal) || !initHal()) {
            stop();
            return false;
        }

        mEdgeGripLevel = readEdgeGripLevel();

        // Read the panel geometry before initializing the algorithm: BOE's
        // IAlgoInit consumes numColumns/numRows from the hardware-info block,
        // and both parsers use the panel-native matrix stride.
        const TouchGeometry geometry = readTouchGeometry();
        mRows = geometry.rows;
        mCols = geometry.cols;
        mMatrixSize = mRows * mCols * 2;
        mRawFrameSize = (mRows * mCols + mRows + mCols) * 2;

        if (!loadAlgo(paths.algo) || !initAlgo()) {
            LOG(WARNING) << "vendor THP algorithm unavailable; restoring kernel HBP path";
            stop();
            return false;
        }

        const size_t algoMatrixBytes = static_cast<size_t>(kAlgoRows) * kAlgoCols * 2;
        const size_t algoColBytes = static_cast<size_t>(kAlgoCols) * 2;
        const size_t algoRowBytes = static_cast<size_t>(kAlgoRows) * 2;
        const size_t panelColBytes = static_cast<size_t>(mCols) * 2;
        const size_t panelRowBytes = static_cast<size_t>(mRows) * 2;
        mMatrix.assign(std::max(algoMatrixBytes, static_cast<size_t>(mMatrixSize)), 0);
        mColA.assign(std::max(algoColBytes, panelColBytes), 0);
        mRowA.assign(std::max(algoRowBytes, panelRowBytes), 0);
        mColB.assign(std::max(algoColBytes, panelColBytes), 0);
        mRowB.assign(std::max(algoRowBytes, panelRowBytes), 0);

        LOG(INFO) << "HBP frame geometry: " << mRows << "x" << mCols
                  << " raw=" << mRawFrameSize;

        if (!mReporter.open()) {
            LOG(WARNING) << "cannot open touch input device; restoring kernel HBP path";
            stop();
            return false;
        }

        resetActiveState();

        if (!mPreventionEnabled) {
            LOG(INFO) << "HBP userspace grip prevention disabled by "
                      << kPreventionProperty << "; reporting raw ALGO points"
                      << " (level=" << mEdgeGripLevel << ")";
        } else {
            const auto featureConfigs = findConfigs(kFeatureConfigName);
            if (!featureConfigs.empty() &&
                mTouchPrevention.start(panelHint, featureConfigs.front())) {
                mTouchPrevention.set_makeup_callbacks(
                        [this](int slot, uint16_t x, uint16_t y) {
                            onMakeupPoint(slot, x, y);
                        },
                        [this](int slot) { onMakeupRelease(slot); });
                mTouchPrevention.setStrength(mEdgeGripLevel);
                LOG(INFO) << "HBP userspace grip prevention initialized (panel="
                          << panelHint << ", level=" << mEdgeGripLevel
                          << (mEdgeGripLevel == 0 ? ", raw input" : "") << ")";
            } else {
                LOG(INFO) << "HBP userspace grip prevention unavailable; "
                             "reporting raw ALGO points (level="
                          << mEdgeGripLevel << ")";
            }
        }

        const bool initialScreenOn = screenStateIsOn();
        mScreenOn.store(initialScreenOn);
        mFingerprintHalReport.store(
                (readIntNode(kFingerprintHalNode, 0) & kFingerprintHalReport) != 0);
        mFingerprintAlgoEnabled.store(false);
        mFingerprintDcEnabled.store(false);
        mFingerprintDcPending.store(-1);
        mFingerprintTriggerDown.store(false);
        mFingerprintTriggerErrors = 0;
        // The kernel keeps is_fp_down across a userspace restart.  Clear any
        // stale screen-on fingerprint down event so a daemon crash or restart
        // cannot make the next authentication's down get ignored.
        setFingerprintTrigger(false, 0, 0, true, false);

        // Start in the same HBP core mode as the stock daemon: mode 3 when
        // the display is on, mode 1 when it is off.  Force the first
        // transition so a daemon restart during either state always puts the
        // core back into the correct state, even if the stored flags do not
        // match yet.
        mHbpScreenOn.store(!initialScreenOn);
        mHbpSuspended.store(initialScreenOn);
        {
            std::lock_guard<std::mutex> lock(mHalMutex);
            if (mHandle != nullptr) {
                if (initialScreenOn) {
                    enterScreenOnLocked(true);
                } else {
                    enterScreenOffLocked(true);
                }
            }
        }

        mFingerprintActive.store(readBooleanNode(kFingerprintActiveNode));
        mFingerprintCheckedMs.store(nowMs());
        if (!mRunning.exchange(true)) {
            mThread = std::thread([this] { serviceLoop(); });
            mWatchdog = std::thread([this] { watchdogLoop(); });
            mFingerprintThread = std::thread([this] { fingerprintLoop(); });
        }
        LOG(INFO) << "HBP userspace AFE/ALGO pipeline started";
        return true;
    }

    void stop() {
        mRunning.store(false);
        if (mThread.joinable()) {
            mThread.join();
        }
        if (mWatchdog.joinable()) {
            mWatchdog.join();
        }
        if (mFingerprintThread.joinable()) {
            mFingerprintThread.join();
        }
        mTouchPrevention.stop();
        resetActiveState();
        mReporter.close();
        closeHal();
        closeAlgo();
    }

  private:
    static constexpr int kAlgoRows = 18;
    static constexpr int kAlgoCols = 40;
    static constexpr int kMaxPoints = 10;

    using TcmInitModule = uint32_t (*)();
    using TcmUninitModule = uint32_t (*)();
    using TcmOpen = uint32_t (*)(const char*, void*, TcmHandle*);
    using TcmClose = uint32_t (*)(TcmHandle);
    using TcmGetParam = uint32_t (*)(TcmHandle, uint32_t, uint32_t*);
    using TcmSetParam = uint32_t (*)(TcmHandle, uint32_t, uint32_t);
    using TcmGetParamBlob = uint32_t (*)(TcmHandle, uint32_t, SynaBlobData*);
    using TcmSetEventCallback = uint32_t (*)(TcmHandle, TcmEventCallback, void*);
    using TcmService = uint32_t (*)(TcmHandle, uint32_t, TcmActionInfo*);
    using TcmSetMode = uint32_t (*)(TcmHandle, uint32_t);
    using TcmGetMode = uint32_t (*)(TcmHandle, uint32_t*);
    using TcmGetHbpVersion = uint32_t (*)(char*, uint32_t);

    bool loadHal(const std::string& path) {
        mHal = dlopen(path.c_str(), RTLD_LAZY);
        if (mHal == nullptr) {
            LOG(WARNING) << "cannot load " << path << ": " << dlerror();
            return false;
        }

        mTcmInitModule = reinterpret_cast<TcmInitModule>(dlsym(mHal, "tcmInitModule"));
        mTcmUninitModule = reinterpret_cast<TcmUninitModule>(dlsym(mHal, "tcmUninitModule"));
        mTcmOpen = reinterpret_cast<TcmOpen>(dlsym(mHal, "tcmOpen"));
        mTcmClose = reinterpret_cast<TcmClose>(dlsym(mHal, "tcmClose"));
        mTcmGetParam = reinterpret_cast<TcmGetParam>(dlsym(mHal, "tcmGetParam"));
        mTcmSetParam = reinterpret_cast<TcmSetParam>(dlsym(mHal, "tcmSetParam"));
        mTcmGetParamBlob = reinterpret_cast<TcmGetParamBlob>(dlsym(mHal, "tcmGetParamBlob"));
        mTcmSetEventCallback =
                reinterpret_cast<TcmSetEventCallback>(dlsym(mHal, "tcmSetEventCallback"));
        mTcmService = reinterpret_cast<TcmService>(dlsym(mHal, "tcmService"));
        mTcmSetMode = reinterpret_cast<TcmSetMode>(dlsym(mHal, "tcmSetMode"));
        mTcmGetMode = reinterpret_cast<TcmGetMode>(dlsym(mHal, "tcmGetMode"));
        mTcmGetHbpVersion =
                reinterpret_cast<TcmGetHbpVersion>(dlsym(mHal, "tcmGetHbpVersion"));

        if (mTcmInitModule == nullptr || mTcmUninitModule == nullptr || mTcmOpen == nullptr ||
            mTcmClose == nullptr || mTcmSetParam == nullptr ||
            mTcmSetEventCallback == nullptr || mTcmService == nullptr ||
            mTcmSetMode == nullptr) {
            LOG(WARNING) << "HBP core is missing a required export";
            return false;
        }
        return true;
    }

    bool initHal() {
        if (mTcmInitModule() != 0) {
            LOG(WARNING) << "tcmInitModule failed";
            return false;
        }

        const uint32_t version = mTcmGetHbpVersion != nullptr ? [this] {
            char buffer[32] = {};
            return mTcmGetHbpVersion(buffer, sizeof(buffer));
        }() : 0;
        if (version != 0) {
            LOG(WARNING) << "tcmGetHbpVersion failed: " << version;
        }

        // The stock daemon passes "/dev/tcm_hbp"; the PAL layer appends the
        // per-device index and opens /dev/tcm_hbp0.
        if (mTcmOpen("/dev/tcm_hbp", nullptr, &mHandle) != 0 || mHandle == nullptr) {
            LOG(WARNING) << "tcmOpen(/dev/tcm_hbp) failed";
            return false;
        }

        uint8_t inputParams[12] = {};
        SynaBlobData blob = {sizeof(inputParams), inputParams};
        if (mTcmGetParamBlob != nullptr && mTcmGetParamBlob(mHandle, 2, &blob) == 0) {
            uint16_t maxX = 0;
            uint16_t maxY = 0;
            uint32_t maxObjects = 0;
            std::memcpy(&maxX, inputParams + 0, sizeof(maxX));
            std::memcpy(&maxY, inputParams + 2, sizeof(maxY));
            std::memcpy(&maxObjects, inputParams + 8, sizeof(maxObjects));
            if (maxX != 0 && maxY != 0) {
                LOG(INFO) << "HBP input params: " << maxX << "x" << maxY
                          << " objects=" << maxObjects;
            }
        }

        if (mTcmSetEventCallback(mHandle, &HbpPipeline::eventCallback, this) != 0) {
            LOG(WARNING) << "tcmSetEventCallback failed";
            return false;
        }

        // Match the stock initialization order: the custom frame path is
        // configured first, then doze, recovery, and HBP mode.  Param 9
        // selects the custom frame library; param 10 selects the customer IFP
        // frame processor.  The stock daemon leaves the core in its initial
        // idle mode here and lets the screen-state transition select mode 3 or
        // mode 1.
        const uint32_t params[][2] = {
                {9, 1},   // custom frame library
                {10, 1},  // customer IFP frame processor
                {6, 1},   // doze
                {8, 1},   // recovery option
                {2, 1},   // HBP mode
        };
        for (const auto& entry : params) {
            const uint32_t result = mTcmSetParam(mHandle, entry[0], entry[1]);
            if (result != 0) {
                LOG(WARNING) << "tcmSetParam(" << entry[0] << ") failed: " << result;
                if (entry[0] == 2 || entry[0] == 9 || entry[0] == 10) {
                    return false;
                }
            }
        }

        LOG(INFO) << "HBP core opened and initialized";
        return true;
    }

    // The kernel sysfs path cannot reliably program the grip DCs while this
    // process owns /dev/tcm_hbp0.  Apply the same sequence through the HBP
    // handle so the firmware level follows the userspace prevention level.
    bool applyFirmwareGripLevel(int level) {
        if (mHandle == nullptr || mTcmSetParam == nullptr) {
            return false;
        }

        if (level < 0) {
            level = 0;
        } else if (level > 5) {
            level = 5;
        }

        bool ok = true;
        const auto setDc = [this, &ok](uint32_t id, uint32_t value) {
            const uint32_t result =
                    mTcmSetParam(mHandle, 7, (id << 16) | (value & 0xFFFF));
            if (result != 0) {
                ok = false;
                LOG(WARNING) << "HBP grip DC set failed: id=0x" << id
                             << " value=0x" << value << " ret=" << result;
            }
        };

        if (level == 0) {
            setDc(0x0B, 0);  // DC_GRIP_SUPPRESSION_ENABLED
            setDc(0xDE, 0);  // DC_GRIP_ENABLED
            setDc(0xDD, 0);  // DC_DARK_ZONE_ENABLE
        } else {
            const uint32_t darkX = 0x0A + 2 * (level - 1);
            setDc(0x0B, 1);      // DC_GRIP_SUPPRESSION_ENABLED
            setDc(0xDE, 1);      // DC_GRIP_ENABLED
            setDc(0xDC, 0);      // DC_GRIP_ROATE_TO_HORIZONTAL_LEVEL
            setDc(0xE5, 0x03);   // DC_GRIP_ABS_DARK_SEL
            setDc(0xE1, darkX);  // DC_GRIP_ABS_DARK_X
            setDc(0xDD, 0x05);   // DC_DARK_ZONE_ENABLE
            setDc(0xDF, 0x24);   // DC_GRIP_DARK_ZONE_X
            setDc(0xE0, 0xF5);   // DC_GRIP_DARK_ZONE_Y
        }

        if (ok) {
            LOG(INFO) << "HBP firmware grip level " << level << " applied";
        }
        return ok;
    }

    bool loadAlgo(const std::string& path) {
        mAlgoLib = dlopen(path.c_str(), RTLD_LAZY);
        if (mAlgoLib == nullptr) {
            LOG(WARNING) << "cannot load " << path << ": " << dlerror();
            return false;
        }

        mAlgo.open = reinterpret_cast<IAlgoOpen>(dlsym(mAlgoLib, "IAlgoOpen"));
        mAlgo.init = reinterpret_cast<IAlgoInit>(dlsym(mAlgoLib, "IAlgoInit"));
        mAlgo.thpInit = reinterpret_cast<IThpAlgoInit>(dlsym(mAlgoLib, "IThpAlgoInit"));
        mAlgo.process = reinterpret_cast<IThpAlgoProcess>(dlsym(mAlgoLib, "IThpAlgoProcess"));
        mAlgo.frameParse =
                reinterpret_cast<IFrameDataParse>(dlsym(mAlgoLib, "IFrameDataParse"));
        mAlgo.getPoint = reinterpret_cast<IGetAlgoPoint>(dlsym(mAlgoLib, "IGetAlgoPoint"));
        mAlgo.getInsertRealPoint = reinterpret_cast<IGetAlgoInsertRealPoint>(
                dlsym(mAlgoLib, "IGetAlgoInsertRealPoint"));
        mAlgo.getAftInfo = reinterpret_cast<IGetAftInfo>(dlsym(mAlgoLib, "IGetAftInfo"));
        mAlgo.getAlgoInfo = reinterpret_cast<IGetAlgoInfo>(dlsym(mAlgoLib, "IGetAlgoInfo"));
        mAlgo.getParam = reinterpret_cast<IThpAlgoGetParam>(dlsym(mAlgoLib, "IThpAlgoGetParam"));
        mAlgo.setParam = reinterpret_cast<IThpAlgoSetParam>(dlsym(mAlgoLib, "IThpAlgoSetParam"));
        mAlgo.getMode = reinterpret_cast<IThpAlgoGetMode>(dlsym(mAlgoLib, "IThpAlgoGetMode"));
        mAlgo.setMode = reinterpret_cast<IThpAlgoSetMode>(dlsym(mAlgoLib, "IThpAlgoSetMode"));
        mAlgo.hardwareInfo =
                reinterpret_cast<IAlgoHardwareInfo>(dlsym(mAlgoLib, "IAlgoHardwareInfo"));
        mAlgo.postInit = reinterpret_cast<IAlgoPostInit>(dlsym(mAlgoLib, "IAlgoPostInit"));
        mAlgo.setInfo = reinterpret_cast<IAlgoSetInfo>(dlsym(mAlgoLib, "IAlgoSetInfo"));
        mAlgo.setConfigReadCallback = reinterpret_cast<IAlgoSetConfigReadCallback>(
                dlsym(mAlgoLib, "IAlgoSetConfigReadCallback"));
        mAlgo.uninit = reinterpret_cast<IThpAlgoUninit>(dlsym(mAlgoLib, "IThpAlgoUninit"));

        // BOE releases provide IAlgoOpen + IAlgoInit, while TIANMA releases
        // provide IThpAlgoInit.  Accept either complete interface.
        const bool boePath = mAlgo.open != nullptr && mAlgo.init != nullptr;
        const bool tianmaPath = mAlgo.thpInit != nullptr;
        if ((!boePath && !tianmaPath) || mAlgo.process == nullptr ||
            mAlgo.frameParse == nullptr || mAlgo.getPoint == nullptr ||
            mAlgo.getAftInfo == nullptr) {
            LOG(WARNING) << "THP algorithm is missing a required export";
            return false;
        }
        return true;
    }

    // The vendor ALGO asks for its per-panel feature thresholds through this
    // callback while handling PARAM_ID_ALGO_CONFIG_MODE (0x11) and during
    // later frame processing.  Serve the values from
    // sys_touch_algo_feature_config.xml, exactly like the stock daemon.
    static int algoConfigRead(uint8_t panelIndex, const char* key, void* out, int count) {
        if (out == nullptr || key == nullptr || count <= 0) {
            return -EINVAL;
        }

        (void)panelIndex;
        int* values = static_cast<int*>(out);
        const AlgoFeatureConfig* config =
                gActiveAlgoConfig.load(std::memory_order_acquire);
        // The daemon loads exactly one panel library, so the panel selected
        // from the resolved firmware path is authoritative.  The ALGO's
        // requested index is only a hint.
        const AlgoFeaturePanel* panel =
                config != nullptr ? config->selected() : nullptr;

        const std::vector<int>* configured = panel != nullptr ? panel->find(key) : nullptr;
        if (configured == nullptr) {
            // Keep ALGO initialization working if both XML files are absent.
            // The real XML supplies prjId=22825 and the panel thresholds; a
            // missing file can only fall back to the library defaults.
            static const char* const kZeroDefaultKeys[] = {
                    "paramLogLevel",
                    "prjId",
                    "is_curved_screen_v4_3",
                    "gloveEnableSupport",
                    "waterproofSupport",
                    "touchZToPressureSupport",
                    "smartTpSupport",
                    "frame_insert_skip_frames",
                    "edge_pull_out_support",
                    "report_rate_white_list_support",
                    "game_mode_divided_report_rate_support",
                    "extreme_game_report_rate",
                    "aiFilmSupport",
            };
            for (const char* default_key : kZeroDefaultKeys) {
                if (std::strcmp(key, default_key) == 0) {
                    // These are scalar defaults.  Never zero-fill the whole
                    // caller buffer: the vendor passes large capacity hints
                    // for array keys and expects the callback to stop at the
                    // number of values actually present.
                    values[0] = 0;
                    return 0;
                }
            }
            return -EINVAL;
        }

        // Match the stock callback: write only the values present in the XML
        // and never exceed the caller-provided capacity.  Zero-filling to
        // `count` corrupts the vendor stack because several array keys pass
        // large byte-size/capacity hints (for example getGainParam() passes
        // 0x334 for the 20-element rowGain array).
        const int value_count =
                std::min<int>(static_cast<int>(configured->size()), count);
        for (int i = 0; i < value_count; ++i) {
            values[i] = (*configured)[i];
        }
        return 0;
    }

    bool initAlgo() {
        std::lock_guard<std::mutex> lock(mAlgoMutex);
        const bool boePath = mAlgo.open != nullptr && mAlgo.init != nullptr;

        // The algorithm reads numColumns from offset 0 and numRows from offset
        // 2.  On this panel that is 38 and 17 respectively; the TIANMA panel
        // uses 40 and 18.
        uint8_t hardware[0x31c] = {};
        const uint16_t numColumns = static_cast<uint16_t>(mCols);
        const uint16_t numRows = static_cast<uint16_t>(mRows);
        std::memcpy(hardware + 0x00, &numColumns, sizeof(numColumns));
        std::memcpy(hardware + 0x02, &numRows, sizeof(numRows));

        uint32_t result = 0;
        if (boePath) {
            result = mAlgo.open(&mAlgoContext);
            if (static_cast<int32_t>(result) < 0 || mAlgoContext == nullptr) {
                LOG(WARNING) << "IAlgoOpen failed: " << result;
                mAlgoContext = nullptr;
                return false;
            }

            result = mAlgo.init(mAlgoContext, hardware, sizeof(hardware));
            if (static_cast<int32_t>(result) < 0) {
                LOG(WARNING) << "IAlgoInit failed: " << result;
                if (mAlgo.uninit != nullptr) {
                    mAlgo.uninit(mAlgoContext);
                }
                mAlgoContext = nullptr;
                return false;
            }
            LOG(INFO) << "HBP algorithm interface: BOE (IAlgoOpen/IAlgoInit)";
        } else {
            if (mAlgo.hardwareInfo != nullptr) {
                mAlgo.hardwareInfo(mAlgoContext, hardware, sizeof(hardware));
            }

            result = mAlgo.thpInit(&mAlgoContext);
            if (static_cast<int32_t>(result) < 0) {
                LOG(WARNING) << "IThpAlgoInit failed: " << result;
                mAlgoContext = nullptr;
                return false;
            }
            LOG(INFO) << "HBP algorithm interface: TIANMA (IThpAlgoInit)";
        }

        if (mAlgo.getAlgoInfo != nullptr) {
            char version[0x40] = {};
            if (mAlgo.getAlgoInfo(mAlgoContext, 0, version, sizeof(version) - 1) == 0) {
                version[sizeof(version) - 1] = '\0';
                LOG(INFO) << "THP algorithm version: " << version;
            }
        }

        bool configCallbackReady = false;
        if (mAlgo.setConfigReadCallback != nullptr) {
            gActiveAlgoConfig.store(&mAlgoConfig, std::memory_order_release);
            result = mAlgo.setConfigReadCallback(mAlgoContext, &HbpPipeline::algoConfigRead);
            if (result != 0) {
                LOG(WARNING) << "IAlgoSetConfigReadCallback failed: " << result;
                gActiveAlgoConfig.store(nullptr, std::memory_order_release);
            } else {
                configCallbackReady = true;
            }
        }

        // PARAM_ID_ALGO_CONFIG_MODE selects the XML panel index.  On BOE this
        // call invokes algoConfigRead(), so only issue it after registration.
        if (mAlgo.setParam != nullptr && (!boePath || configCallbackReady)) {
            uint32_t panelIndex = boePath ? 0u : 1u;
            if (mAlgoConfig.selected_id >= 0) {
                panelIndex = static_cast<uint32_t>(mAlgoConfig.selected_id);
            }
            result = mAlgo.setParam(mAlgoContext, 0x11, panelIndex);
            if (static_cast<int32_t>(result) < 0) {
                LOG(WARNING) << "IThpAlgoSetParam(0x11) failed: " << result;
            } else {
                LOG(INFO) << "IThpAlgoSetParam(0x11) panel index " << panelIndex;
            }
        }

        if (mAlgo.postInit != nullptr) {
            mAlgo.postInit(mAlgoContext);
        }
        if (mAlgo.setMode != nullptr) {
            // The stock daemon sets MODE_SCREEN_ON (1) after tcmSetMode(3).
            mAlgo.setMode(mAlgoContext, 1);
        }

        if (mAlgo.getParam != nullptr) {
            uint32_t value = 0;
            if (mAlgo.getParam(mAlgoContext, 0, &value) == 0) {
                LOG(INFO) << "THP algorithm report mode: " << value;
            }
        }

        LOG(INFO) << "THP algorithm initialized (rows=" << mRows << ", cols=" << mCols
                  << ")";
        return true;
    }

    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                .count();
    }

    void closeHal() {
        std::lock_guard<std::mutex> lock(mHalMutex);
        mFingerprintDcPending.store(-1);
        mFingerprintDcEnabled.store(false);
        mFingerprintAlgoEnabled.store(false);
        forceFingerprintTriggerUp();
        if (mHandle != nullptr && mTcmSetMode != nullptr) {
            // The stock state machine leaves through ts_switch_mode(0) on
            // termination.  Let the HBP core process that transition before
            // releasing the character device; cdev release then disables HBP
            // in the kernel and restores the LBP path.
            const uint32_t modeResult = mTcmSetMode(mHandle, 0);
            if (modeResult == 0 && mTcmService != nullptr) {
                TcmActionInfo action = {};
                mTcmService(mHandle, 100, &action);
            }
        }
        if (mHandle != nullptr && mTcmClose != nullptr) {
            mTcmClose(mHandle);
            mHandle = nullptr;
        }
        if (mTcmUninitModule != nullptr) {
            mTcmUninitModule();
            mTcmUninitModule = nullptr;
        }
        if (mHal != nullptr) {
            dlclose(mHal);
            mHal = nullptr;
        }
    }

    void closeAlgo() {
        std::lock_guard<std::mutex> lock(mAlgoMutex);
        if (mAlgo.uninit != nullptr) {
            mAlgo.uninit(mAlgoContext);
        }
        gActiveAlgoConfig.store(nullptr, std::memory_order_release);
        mAlgoConfig.panels.clear();
        mAlgoConfig.selected_id = -1;
        mAlgoContext = nullptr;
        mAlgo = {};
        if (mAlgoLib != nullptr) {
            dlclose(mAlgoLib);
            mAlgoLib = nullptr;
        }
    }

    static void eventCallback(void* user, uint32_t type, SynaBlobData blob) {
        auto* self = static_cast<HbpPipeline*>(user);
        if (self != nullptr) {
            self->handleEvent(type, blob);
        }
    }

    void handleEvent(uint32_t type, const SynaBlobData& blob) {
        if (blob.pData == nullptr || blob.length == 0) {
            return;
        }

        if (!mScreenOn.load()) {
            // Screen-off gestures and UDFPS are owned by the kernel and the
            // fingerprint HAL.  Do not run the screen-on frame/prevention
            // pipeline against them.
            clearActivePoints();
            return;
        }

        if (type == 1) {
            // The stock daemon consumes type-1 touch reports here.  HBP mode
            // normally does not deliver them: the HAL accepts only active
            // frame and power-state reports while HBP owns the panel.  Keep
            // this as the secondary stock path; the primary screen-on bridge
            // is driven from the type-4 algorithm points below.
            handleFingerprintReport(blob);
            return;
        }

        if (type == 4) {
            // The custom IFP frame processor returns a report package with a
            // pointer to the raw HBP frame.  The package starts with the raw
            // size and has the data pointer at offset 8.
            if (blob.length < sizeof(IfpReport)) {
                return;
            }
            const auto* report = reinterpret_cast<const IfpReport*>(blob.pData);
            if (report->raw == nullptr || report->raw_size == 0) {
                return;
            }
            mSawType4.store(true);
            processFrame(report->raw, report->raw_size);
            return;
        }

        if (type == 0x23) {
            // Raw HBP frame callback.  The stock daemon only uses this for
            // diagnostics; type 4 is the ALGO frame path.  Keep it as a
            // fallback for panels where the IFP package is not emitted.
            if (!mSawType4.load() && blob.length >= static_cast<uint32_t>(mRawFrameSize)) {
                processFrame(blob.pData, blob.length);
            }
            return;
        }

        if (type == 3) {
            // Normal status reports arrive continuously while a finger is
            // down; only surface an unexpected package size.
            if (blob.length != 20) {
                LOG(DEBUG) << "HBP status report, length " << blob.length;
            }
        }
    }

    void processFrame(const uint8_t* raw, uint32_t size) {
        // libIfp may append the per-object custom-data block to the raw frame
        // (maxObjects * 4 bytes).  The matrix and row/column arrays are always
        // at the front, so accept any buffer large enough for the base frame.
        if (raw == nullptr || size < static_cast<uint32_t>(mRawFrameSize)) {
            logFrameError(size);
            return;
        }

        std::memset(mMatrix.data(), 0, mMatrix.size());
        std::memset(mColA.data(), 0xff, mColA.size());
        std::memset(mRowA.data(), 0xff, mRowA.size());
        std::memset(mColB.data(), 0xff, mColB.size());
        std::memset(mRowB.data(), 0xff, mRowB.size());

        // BOE's parser uses the native panel dimensions from the hardware-info
        // block (17 rows x 38 columns) and expects the packed HAL matrix with
        // mCols as the row stride.  TIANMA's parser uses its fixed 18 x 40
        // layout, which equals that panel's native dimensions.  Copy the
        // packed matrix directly; mCols is the correct stride in both cases.
        std::memcpy(mMatrix.data(), raw, static_cast<size_t>(mMatrixSize));
        std::memcpy(mColA.data(), raw + mMatrixSize, static_cast<size_t>(mCols * 2));
        std::memcpy(mColB.data(), raw + mMatrixSize, static_cast<size_t>(mCols * 2));
        std::memcpy(mRowA.data(), raw + mMatrixSize + mCols * 2,
                    static_cast<size_t>(mRows * 2));
        std::memcpy(mRowB.data(), raw + mMatrixSize + mCols * 2,
                    static_cast<size_t>(mRows * 2));

        const auto now = std::chrono::steady_clock::now();
        uint32_t elapsedMs = 0;
        if (mHaveLastFrame) {
            elapsedMs = static_cast<uint32_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - mLastFrame)
                            .count());
            if (elapsedMs > 0xffff) {
                elapsedMs = 0xffff;
            }
        }
        mLastFrame = now;
        mHaveLastFrame = true;

        std::memset(&mFrame, 0, sizeof(mFrame));
        mFrame.matrix = mMatrix.data();
        mFrame.col_a = mColA.data();
        mFrame.row_a = mRowA.data();
        mFrame.col_b = mColB.data();
        mFrame.row_b = mRowB.data();
        mFrame.matrix_size = static_cast<uint32_t>(mMatrixSize);
        mFrame.col_a_size = static_cast<uint32_t>(mCols * 2);
        mFrame.row_a_size = static_cast<uint32_t>(mRows * 2);
        mFrame.col_b_size = static_cast<uint32_t>(mCols * 2);
        mFrame.row_b_size = static_cast<uint32_t>(mRows * 2);
        mFrame.frame_index = static_cast<uint16_t>(mFrameIndex++);
        mFrame.temperature = 25;
        mFrame.time_since_last = static_cast<uint16_t>(elapsedMs);

        // The BOE getters reject the full buffer sizes.  They copy only when
        // the requested size is below the payload limit: IGetAlgoPoint()
        // accepts < 0xf9 and IGetAftInfo() accepts < 0x29.  Pass the payload
        // sizes (0xf8 / 0x28) and keep the larger stack buffers so the
        // library cannot overrun them.  The error strings for the rejected
        // sizes are misleading: "reportData is NULL" and "size is error,
        // aftReportData" both mean the size argument was too large.
        uint8_t pointPackage[0x100] = {};
        uint8_t insertPackage[0x100] = {};
        uint8_t aftPackage[0x30] = {};
        uint32_t processResult = 0;
        bool pointOk = false;
        bool insertOk = false;
        {
            std::lock_guard<std::mutex> algoLock(mAlgoMutex);
            if (mAlgo.frameParse == nullptr || mAlgo.process == nullptr) {
                return;
            }
            mAlgo.frameParse(mAlgoContext, &mFrame);
            processResult = mAlgo.process(mAlgoContext);
            if (processResult == 0) {
                pointOk = mAlgo.getPoint(mAlgoContext, pointPackage, 0xf8) == 0;
                if (mAlgo.getInsertRealPoint != nullptr) {
                    insertOk = mAlgo.getInsertRealPoint(
                                       mAlgoContext, insertPackage, 0xf8) == 0;
                }
            }
            if ((pointOk || insertOk) &&
                mAlgo.getAftInfo(mAlgoContext, aftPackage, 0x28) != 0) {
                std::memset(aftPackage, 0, sizeof(aftPackage));
            }
        }
        if (processResult != 0) {
            logProcessError(processResult);
            mTouchPrevention.reset();
            clearActivePoints();
            return;
        }
        if (!pointOk && !insertOk) {
            logPointError();
            mTouchPrevention.reset();
            clearActivePoints();
            return;
        }

        buildAndReport(pointOk ? pointPackage : nullptr,
                       insertOk ? insertPackage : nullptr, aftPackage);
    }

    struct Candidate {
        int slot;
        TouchPoint point;
        AlgoAftInfo aft;
    };

    void publishActivePointsLocked() {
        std::array<TouchPoint, kMaxPoints> desired{};
        size_t desiredCount = 0;
        for (int i = 0; i < kMaxPoints; ++i) {
            if (mActiveMask & (1u << i)) {
                desired[desiredCount++] = mActivePoints[i];
            }
        }
        const std::span<const TouchPoint> points(desired.data(), desiredCount);
        mReporter.report(points);
        updateFingerprintTriggerFromPointsLocked(points);
    }

    // HBP core mode 3 delivers type-4 IFP frames only.  The HBP HAL accepts
    // just active-frame and power-state reports in that mode, so the firmware
    // TOUCH_HOLD_DOWN/UP reports that stock bridged from type 1 never reach
    // the daemon here.  Drive the same kernel notifier from the algorithm
    // points that already drive normal touch reporting.
    void updateFingerprintTriggerFromPointsLocked(
            std::span<const TouchPoint> points) {
        if (!mScreenOn.load() || !mFingerprintHalReport.load()) {
            return;
        }
        if (points.empty()) {
            forceFingerprintTriggerUp();
            return;
        }
        if (mFingerprintTriggerDown.load()) {
            return;
        }

        const TouchPoint& point = points.front();
        const int x = mReporter.mapX(point.x);
        const int y = mReporter.mapY(point.y);
        if (x < 0 || y < 0) {
            return;
        }
        setFingerprintTrigger(true,
                               static_cast<uint16_t>(std::min(x, 0xffff)),
                               static_cast<uint16_t>(std::min(y, 0xffff)));
    }

    void clearActivePoints() {
        std::lock_guard<std::mutex> lock(mActiveMutex);
        mActiveMask = 0;
        mReporter.releaseAll();
    }

    void resetActiveState() {
        std::lock_guard<std::mutex> lock(mActiveMutex);
        mActiveMask = 0;
        for (int i = 0; i < kMaxPoints; ++i) {
            mLastTouchPoints[i] = TouchPoint{};
            mLastTouchPoints[i].id = -1;
            mLastPreventionPoints[i] = TouchPreventionPoint{};
            mActivePoints[i] = TouchPoint{};
            mActivePoints[i].id = -1;
        }
        mReporter.releaseAll();
    }

    void onMakeupPoint(int slot, uint16_t x, uint16_t y) {
        if (slot < 0 || slot >= kMaxPoints) {
            return;
        }

        std::lock_guard<std::mutex> lock(mActiveMutex);
        TouchPoint point = mLastTouchPoints[slot];
        if (point.id < 0) {
            point.id = slot;
        }
        point.x = x;
        point.y = y;
        mActivePoints[slot] = point;
        mActiveMask |= (1u << slot);
        publishActivePointsLocked();
    }

    void onMakeupRelease(int slot) {
        if (slot < 0 || slot >= kMaxPoints) {
            return;
        }

        std::lock_guard<std::mutex> lock(mActiveMutex);
        mActiveMask &= ~(1u << slot);
        publishActivePointsLocked();
    }

    // While UDFPS is active the fingerprint HAL owns the sensor area.  Stock
    // keeps the grip engine running and does not reset it on fingerprint
    // transitions; only a small contact inside fpSpot is exempted from the
    // prevention result.  Read the vendor nodes with a short cache so the
    // event path does not open two proc files for every frame.
    bool fingerprintSessionActive() {
        const int64_t now = nowMs();
        if (now - mFingerprintCheckedMs.load() < 50) {
            return mFingerprintHalReport.load() || mFingerprintActive.load();
        }

        mFingerprintCheckedMs.store(now);
        const bool active = mFingerprintHalReport.load() ||
                            readBooleanNode(kFingerprintActiveNode);
        const bool wasActive = mFingerprintActive.exchange(active);
        if (active != wasActive) {
            LOG(DEBUG) << "HBP fingerprint " << (active ? "active" : "inactive")
                       << ": prevention continues (UDFPS point exemption only)";
        }
        return active;
    }

    bool isFingerprintPoint(const TouchPoint& point) const {
        const AlgoFeaturePanel* panel = mAlgoConfig.selected();
        if (panel == nullptr) {
            return false;
        }

        const auto value = [panel](const char* key, int fallback) {
            const std::vector<int>* entry = panel->find(key);
            return entry != nullptr && !entry->empty() ? (*entry)[0] : fallback;
        };

        const int centerX = value("fpSpotCenterX", -1);
        const int centerY = value("fpSpotCenterY", -1);
        const int radius = value("fpSpotRadius", 0);
        if (centerX < 0 || centerY < 0 || radius <= 0) {
            return false;
        }

        // A palm covering the UDFPS is large; only the actual fingerprint
        // contact should be exempted from prevention.
        if (point.width > 10 || point.touch_major > 10) {
            return false;
        }

        const int64_t dx = static_cast<int64_t>(point.x) - centerX;
        const int64_t dy = static_cast<int64_t>(point.y) - centerY;
        return dx * dx + dy * dy <=
               static_cast<int64_t>(radius) * radius;
    }

    AlgoPoint decodeAlgoPoint(const uint8_t* pointPackage, int index) const {
        AlgoPoint point = {};
        const uint8_t* raw =
                pointPackage + 4 + index * static_cast<int>(sizeof(AlgoPoint));
        std::memcpy(&point, raw, sizeof(point));

        // BOE's IGetAlgoPoint() packet is a 20-byte record whose first four
        // bytes are a header/status word.  The TIANMA packet places the
        // status at +0 and starts the point payload four bytes later.  x/y/id
        // and algo_status happen to align for both, but the pressure and
        // contact-size fields do not.
        if (mPanelVendor == TouchPanelVendor::Boe) {
            point.z = raw[0];
            point.width = raw[8];
            point.touch_major = raw[9];
        }
        return point;
    }

    void buildAndReport(const uint8_t* pointPackage, const uint8_t* insertPackage,
                        const uint8_t* aftPackage) {
        const bool screenOn = mScreenOn.load();
        if (!screenOn) {
            clearActivePoints();
            return;
        }
        mScreenOn.store(true);

        const bool fingerprintActive = fingerprintSessionActive();
        const bool fpSession = mFingerprintHalReport.load();

        // Stock rebuilds both arrays from the current frame.  Starting from
        // the previous frame keeps a disappeared palm point alive with
        // status=1 and lets it block every later finger.
        std::array<TouchPreventionPoint, kMaxPoints> prevention{};
        std::array<TouchPoint, kMaxPoints> current{};
        for (auto& point : current) {
            point.id = -1;
        }
        uint32_t activeMask = 0;
        uint32_t mainMask = 0;
        uint32_t insertMask = 0;
        std::array<Candidate, kMaxPoints> candidates{};
        std::array<bool, kMaxPoints> seen{};
        int candidateCount = 0;
        int insertAdded = 0;

        const auto addPoint = [&](const uint8_t* package, int slot,
                                  uint32_t& groupMask) {
            if (package == nullptr) {
                return;
            }

            const AlgoPoint point = decodeAlgoPoint(package, slot);
            const int id = static_cast<int>(point.id);
            if (id < 0 || id >= kMaxPoints || seen[id]) {
                return;
            }

            // Stock treats every algo status except 0 (no point) and 3 (up)
            // as an active point; statuses 1/2 are the normal down states.
            const bool active = point.algo_status != 0 && point.algo_status != 3 &&
                                point.x < kAlgoMaxX && point.y < kAlgoMaxY;
            if (!active) {
                return;
            }

            seen[id] = true;
            activeMask |= (1u << id);
            groupMask |= (1u << id);

            // Stock normalizes the two contact axes before prevention and
            // reporting.  The vendor package can place the larger axis in
            // either field, so use min/max rather than positional names.
            // width is one byte and touch_major is two bytes in AlgoPoint;
            // normalize both to the byte range used by stock's report.
            const uint16_t widthValue = point.width;
            const uint16_t touchValue =
                    std::min<uint16_t>(point.touch_major, 0xff);
            const uint8_t widthMajor = static_cast<uint8_t>(
                    std::min(widthValue, touchValue));
            const uint8_t touchMajor = static_cast<uint8_t>(
                    std::max(widthValue, touchValue));

            Candidate candidate{};
            candidate.slot = id;
            candidate.point.id = id;
            candidate.point.x = point.x;
            candidate.point.y = point.y;
            candidate.point.z = point.z;
            candidate.point.width = widthMajor;
            candidate.point.touch_major = touchMajor;

            // Stock indexes the AFT records by package slot, including the
            // insert-point worker.  Only the prevention/report arrays are
            // indexed by point ID.
            const int aftIndex = slot;
            if (aftPackage != nullptr && aftIndex >= 0 &&
                aftIndex < kMaxPoints) {
                std::memcpy(&candidate.aft,
                            aftPackage + aftIndex * sizeof(AlgoAftInfo),
                            sizeof(candidate.aft));
            }

            current[id] = candidate.point;
            candidates[candidateCount++] = candidate;

            prevention[id].x = point.x;
            prevention[id].y = point.y;
            prevention[id].z = point.z;
            prevention[id].width_major = widthMajor;
            prevention[id].touch_major = touchMajor;
            prevention[id].status = 1;
            prevention[id].tx_press = candidate.aft.tx_press;
            prevention[id].rx_press = candidate.aft.rx_press;
            prevention[id].tx_er = candidate.aft.tx_er;
            prevention[id].rx_er = candidate.aft.rx_er;
        };

        // The stock daemon indexes the prevention array and mask by the ALGO
        // point ID, not by the package slot.  The AFT records stay indexed by
        // the package slot because that is how IGetAftInfo orders them.
        for (int i = 0; i < kMaxPoints; ++i) {
            addPoint(pointPackage, i, mainMask);
        }

        // Stock's insert-point worker recovers points that the palm/edge
        // algorithm removed from the normal package.  Its
        // IGetAlgoInsertRealPoint package uses the same 20-byte report layout.
        // Merge new IDs before prevention so a resting palm is rejected while
        // the new finger is still reported.
        if (insertPackage != nullptr) {
            const int before = candidateCount;
            for (int i = 0; i < kMaxPoints; ++i) {
                addPoint(insertPackage, i, insertMask);
            }
            insertAdded = candidateCount - before;
        }

        if (mDebugPoints) {
            LOG(INFO) << "HBP raw mask=" << static_cast<int>(activeMask)
                      << " points=" << candidateCount
                      << " insert=" << insertAdded
                      << " fp=" << (fingerprintActive ? 1 : 0);
            for (int ci = 0; ci < candidateCount; ++ci) {
                const Candidate& candidate = candidates[ci];
                LOG(INFO) << "HBP point id=" << candidate.point.id
                          << " x=" << candidate.point.x
                          << " y=" << candidate.point.y
                          << " z=" << candidate.point.z
                          << " w=" << candidate.point.width
                          << " tm=" << candidate.point.touch_major
                          << " aft=" << static_cast<int>(candidate.aft.tx_press)
                          << "," << static_cast<int>(candidate.aft.rx_press)
                          << "," << static_cast<int>(candidate.aft.tx_er)
                          << "," << static_cast<int>(candidate.aft.rx_er);
            }
        }

        if (fpSession) {
            mFpSessionFrames.fetch_add(1, std::memory_order_relaxed);
            if (activeMask != 0) {
                mFpSessionPointFrames.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (!mPreventionEnabled) {
            // Diagnostic override only.  Stock runs prevention on the HBP
            // type-4 path; this branch bypasses it only when the property is
            // explicitly set to 0.
            std::lock_guard<std::mutex> lock(mActiveMutex);
            mLastTouchPoints = current;
            mActiveMask = 0;
            for (int ci = 0; ci < candidateCount; ++ci) {
                const Candidate& candidate = candidates[ci];
                mActivePoints[candidate.slot] = candidate.point;
                mActiveMask |= (1u << candidate.slot);
            }
            publishActivePointsLocked();
            return;
        }

        // Level 0 is an explicit request for fully raw input.  It bypasses
        // userspace prevention even when prevention itself is enabled.
        // Fingerprint activity must not bypass prevention: stock keeps the
        // grip engine running and only exempts the UDFPS point itself.
        if (mEdgeGripLevel == 0) {
            std::lock_guard<std::mutex> lock(mActiveMutex);
            mLastPreventionPoints = prevention;
            mLastTouchPoints = current;
            mActiveMask = 0;
            for (int ci = 0; ci < candidateCount; ++ci) {
                const Candidate& candidate = candidates[ci];
                mActivePoints[candidate.slot] = candidate.point;
                mActiveMask |= (1u << candidate.slot);
            }
            publishActivePointsLocked();
            return;
        }

        if (mTouchPrevention.valid()) {
            // The stock type-4 prevention call sees the normal package.  The
            // insert-point worker runs prevention separately with only the
            // insert package, so the palm that was rejected in the main
            // package cannot cover the recovered finger.  Reproduce that by
            // processing the two groups separately and merging the results.
            std::array<TouchPreventionPoint, kMaxPoints> preventionMain =
                    prevention;
            std::array<TouchPreventionPoint, kMaxPoints> preventionInsert =
                    prevention;
            for (int i = 0; i < kMaxPoints; ++i) {
                if ((mainMask & (1u << i)) == 0) {
                    preventionMain[i] = TouchPreventionPoint{};
                }
                if ((insertMask & (1u << i)) == 0) {
                    preventionInsert[i] = TouchPreventionPoint{};
                }
            }

            std::array<TouchPreventionPoint, kMaxPoints> filteredMain =
                    preventionMain;
            std::array<TouchPreventionPoint, kMaxPoints> filteredInsert =
                    preventionInsert;

            const auto runPrevention = [&](const std::array<TouchPreventionPoint,
                                                             kMaxPoints>& input,
                                           uint32_t mask,
                                           std::array<TouchPreventionPoint,
                                                      kMaxPoints>& output,
                                           uint32_t groupMask) {
                uint32_t result = mask;
                if (mask != 0) {
                    result = mTouchPrevention.process(input, mask, &output);
                }

                // Stock keeps prevention active while UDFPS is active and
                // exempts only the small fingerprint contact.
                if (fingerprintActive) {
                    for (int ci = 0; ci < candidateCount; ++ci) {
                        const Candidate& candidate = candidates[ci];
                        if ((groupMask & (1u << candidate.slot)) != 0 &&
                            isFingerprintPoint(candidate.point)) {
                            result |= (1u << candidate.slot);
                        }
                    }
                }
                return result;
            };

            const uint32_t mainOut =
                    runPrevention(preventionMain, mainMask, filteredMain,
                                  mainMask);
            const uint32_t insertOut =
                    runPrevention(preventionInsert, insertMask, filteredInsert,
                                  insertMask);
            const uint32_t effectiveMask = mainOut | insertOut;

            if (mDebugPoints) {
                LOG(INFO) << "HBP prevention main_in="
                          << static_cast<int>(mainMask)
                          << " main_out=" << static_cast<int>(mainOut)
                          << " insert_in=" << static_cast<int>(insertMask)
                          << " insert_out=" << static_cast<int>(insertOut)
                          << " final=" << static_cast<int>(effectiveMask);
            }

            std::lock_guard<std::mutex> lock(mActiveMutex);
            mLastPreventionPoints = prevention;
            mLastTouchPoints = current;
            mActiveMask = 0;
            for (int i = 0; i < kMaxPoints; ++i) {
                if ((effectiveMask & (1u << i)) == 0 || current[i].id < 0) {
                    continue;
                }
                TouchPoint point = current[i];
                const TouchPreventionPoint& filtered =
                        (mainOut & (1u << i)) != 0 ? filteredMain[i]
                                                   : filteredInsert[i];
                point.x = filtered.x;
                point.y = filtered.y;
                mActivePoints[i] = point;
                mActiveMask |= (1u << i);
            }
            publishActivePointsLocked();
            return;
        }

        // Prevention was requested but its configuration could not be
        // loaded.  Do not substitute a different heuristic: the previous
        // AFT/geometry fallback rejected normal bottom-edge touches.  Report
        // raw ALGO points until the stock prevention engine is available.
        if ((mRejectedFrames++ % 600) == 0) {
            LOG(WARNING) << "HBP prevention unavailable; reporting raw points";
        }
        std::lock_guard<std::mutex> lock(mActiveMutex);
        mLastPreventionPoints = prevention;
        mLastTouchPoints = current;
        mActiveMask = 0;
        for (int ci = 0; ci < candidateCount; ++ci) {
            const Candidate& candidate = candidates[ci];
            mActivePoints[candidate.slot] = candidate.point;
            mActiveMask |= (1u << candidate.slot);
        }
        publishActivePointsLocked();
    }

    // The HBP core is a two-stage state machine: tcmSetMode() selects the next
    // mode and tcmService() runs the transition.  Stock's ts_switch_mode()
    // performs this set/service/get sequence, then verifies the current mode.
    bool switchHbpModeLocked(uint32_t mode, uint32_t* outResult) {
        if (outResult != nullptr) {
            *outResult = 0;
        }
        if (mHandle == nullptr || mTcmSetMode == nullptr || mTcmService == nullptr) {
            if (outResult != nullptr) {
                *outResult = 0x65;
            }
            return false;
        }

        uint32_t result = mTcmSetMode(mHandle, mode);
        if (result != 0) {
            if (outResult != nullptr) {
                *outResult = result;
            }
            return false;
        }

        uint32_t lastResult = 0;
        for (int attempt = 0; attempt < 4; ++attempt) {
            TcmActionInfo action = {};
            result = mTcmService(mHandle, 100, &action);
            lastResult = result;

            if (result == 0x78) {
                if (outResult != nullptr) {
                    *outResult = result;
                }
                return false;
            }
            if (result != 0 && result != 0x75 && result != 0x67) {
                if (outResult != nullptr) {
                    *outResult = result;
                }
                return false;
            }

            uint32_t current = 0;
            if (mTcmGetMode != nullptr) {
                const uint32_t getResult = mTcmGetMode(mHandle, &current);
                if (getResult == 0 && current == mode) {
                    if (outResult != nullptr) {
                        *outResult = 0;
                    }
                    return true;
                }
            } else if (result == 0 || result == 0x75) {
                if (outResult != nullptr) {
                    *outResult = 0;
                }
                return true;
            }

            if (result == 0x67 && mode == 3) {
                // The driver still reports the panel as suspended.  Do not
                // force an active-report transition while it is off.
                if (outResult != nullptr) {
                    *outResult = result;
                }
                return false;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        if (outResult != nullptr) {
            *outResult = lastResult;
        }
        return false;
    }

    bool driverReportsSuspendedLocked() {
        if (mHandle == nullptr || mTcmGetParamBlob == nullptr) {
            return !screenStateIsOn();
        }
        // Stock ts_isSyncSuspend() reads tcmGetParamBlob(4), which maps to
        // TSM driver-status information: pwr_state, reqMode, lpwg, irq.
        uint8_t params[8] = {};
        SynaBlobData blob = {sizeof(params), params};
        if (mTcmGetParamBlob(mHandle, 4, &blob) != 0) {
            return !screenStateIsOn();
        }
        uint16_t powerState = 0;
        std::memcpy(&powerState, params, sizeof(powerState));
        // kernel enum power_state: PWR_OFF=0, PWR_ON=1, LOW_PWR=2.
        return powerState == 0 || powerState == 2;
    }

    bool writeFingerprintTrigger(bool down, uint16_t x, uint16_t y,
                                 bool log = true) {
        const int fd = open(kFingerprintTriggerNode, O_WRONLY | O_CLOEXEC);
        if (fd < 0) {
            if ((mFingerprintTriggerErrors++ % 50) == 0) {
                LOG(WARNING) << "cannot open " << kFingerprintTriggerNode << ": "
                             << std::strerror(errno);
            }
            return false;
        }

        char buffer[64] = {};
        const int length = snprintf(buffer, sizeof(buffer), "%d,%u,%u\n",
                                    down ? 1 : 0, x, y);
        bool ok = false;
        if (length > 0 && static_cast<size_t>(length) + 1 <= sizeof(buffer)) {
            // Stock writes the terminating NUL as well.
            const ssize_t written =
                    write(fd, buffer, static_cast<size_t>(length) + 1);
            ok = written == static_cast<ssize_t>(length) + 1;
        }
        close(fd);
        if (!ok) {
            if ((mFingerprintTriggerErrors++ % 50) == 0) {
                LOG(WARNING) << "cannot write fingerprint trigger";
            }
            return false;
        }
        if (log && mDebugPoints) {
            LOG(INFO) << "HBP fingerprint trigger " << (down ? "down" : "up")
                      << " x=" << x << " y=" << y;
        }
        return true;
    }

    // Serialize trigger transitions.  The inotify thread, the secondary type-1
    // HAL callback, and the type-4 frame pipeline can all start or end a
    // screen-on fingerprint session, while the kernel tracks is_fp_down
    // globally.
    void setFingerprintTrigger(bool down, uint16_t x, uint16_t y,
                               bool force = false, bool log = true) {
        std::lock_guard<std::mutex> lock(mFingerprintTriggerMutex);
        if (!force && down == mFingerprintTriggerDown.load()) {
            return;
        }
        if (writeFingerprintTrigger(down, x, y, log)) {
            mFingerprintTriggerDown.store(down);
            mFpSessionTriggers.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void forceFingerprintTriggerUp() {
        if (!mFingerprintTriggerDown.load()) {
            return;
        }
        setFingerprintTrigger(false, 0, 0);
    }

    // Program the vendor ALGO fingerprint parameter.  This does not touch the
    // HBP handle, so the inotify thread can run it immediately without
    // contending on mHalMutex.
    bool setFingerprintAlgoMode(bool enable, bool force = false) {
        if (mAlgo.setParam == nullptr || mAlgoContext == nullptr) {
            return false;
        }
        if (!force && mFingerprintAlgoEnabled.load() == enable) {
            return true;
        }

        uint32_t result = 0;
        {
            std::lock_guard<std::mutex> algoLock(mAlgoMutex);
            result = mAlgo.setParam(mAlgoContext, 1, enable ? 1u : 0u);
        }
        if (result != 0) {
            LOG(WARNING) << "HBP fingerprint algo set failed: " << result;
            mFingerprintAlgoEnabled.store(false);
            return false;
        }
        mFingerprintAlgoEnabled.store(enable);
        LOG(DEBUG) << "HBP fingerprint algo mode " << (enable ? "on" : "off");
        return true;
    }

    // Program the firmware touch-and-hold DC through the HBP handle.  Caller
    // must hold mHalMutex.  force is used across suspend/resume because the
    // kernel may have changed DC_TOUCH_HOLD while the daemon was paused.
    bool setFingerprintDcModeLocked(bool enable, bool force = false) {
        if (mHandle == nullptr || mTcmSetParam == nullptr) {
            return false;
        }
        if (!force && mFingerprintDcEnabled.load() == enable) {
            return true;
        }

        const uint32_t result = mTcmSetParam(
                mHandle, 7, (kDcTouchHold << 16) | (enable ? 3u : 0u));
        if (result != 0) {
            LOG(WARNING) << "HBP fingerprint touch-hold set failed: " << result;
            return false;
        }
        mFingerprintDcEnabled.store(enable);
        LOG(DEBUG) << "HBP fingerprint touch-hold " << (enable ? "on" : "off");
        return true;
    }

    // Try to apply the HBP-handle DC immediately without blocking the
    // inotify thread.  If the service loop owns mHalMutex, leave a pending
    // request that the service loop consumes on its next iteration.
    void queueFingerprintDcMode(bool enable) {
        if (!mScreenOn.load() || mHbpSuspended.load() || gSuspendPending) {
            return;
        }
        if (mHalMutex.try_lock()) {
            bool applied = false;
            if (mHandle != nullptr && mScreenOn.load() &&
                !mHbpSuspended.load() && !gSuspendPending) {
                applied = setFingerprintDcModeLocked(enable, true);
            }
            mHalMutex.unlock();
            if (applied) {
                return;
            }
        }
        mFingerprintDcPending.store(enable ? 1 : 0);
    }

    void handleFingerprintReport(const SynaBlobData& blob) {
        if (blob.pData == nullptr ||
            blob.length < kFingerprintReportMinLength) {
            return;
        }
        uint32_t reportId = 0;
        std::memcpy(&reportId, blob.pData, sizeof(reportId));
        if (reportId != kFingerprintReportDown &&
            reportId != kFingerprintReportUp) {
            return;
        }
        if (!mFingerprintHalReport.load() && !mFingerprintActive.load()) {
            return;
        }

        uint16_t x = 0;
        uint16_t y = 0;
        std::memcpy(&x, blob.pData + kFingerprintReportXOffset, sizeof(x));
        std::memcpy(&y, blob.pData + kFingerprintReportYOffset, sizeof(y));
        const bool down = reportId == kFingerprintReportDown;
        setFingerprintTrigger(down, x, y);
    }

    // Mirror ts_suspend_application() and the stock STATE_SCREEN_OFF branch:
    // stop the vendor algorithm first, switch the HBP core to idle mode 1,
    // then pause servicing until the resume signal arrives.
    bool enterScreenOffLocked(bool force = false) {
        if (!force && !mHbpScreenOn.load() && mHbpSuspended.load()) {
            mScreenOn.store(false);
            return true;
        }
        if (mHandle == nullptr) {
            return false;
        }

        mScreenOn.store(false);
        {
            std::lock_guard<std::mutex> algoLock(mAlgoMutex);
            if (mAlgo.setParam != nullptr) {
                mAlgo.setParam(mAlgoContext, 0x15, 0);
            }
            if (mAlgo.setMode != nullptr) {
                mAlgo.setMode(mAlgoContext, 0);
            }
        }
        mFingerprintDcPending.store(-1);
        mFingerprintDcEnabled.store(false);
        forceFingerprintTriggerUp();
        if (mFingerprintAlgoEnabled.load()) {
            setFingerprintAlgoMode(false);
        }

        uint32_t result = 0;
        if (!switchHbpModeLocked(1, &result)) {
            LOG(WARNING) << "HBP screen off: tcmSetMode(1) transition failed: "
                         << result;
            const bool screenOn = screenStateIsOn();
            mScreenOn.store(screenOn);
            // A failed suspend leaves the retry flag set until the display
            // settles.  Do not let a lagging screen_state hide the retry.
            mHbpScreenOn.store(true);
            mHbpSuspended.store(false);
            mTouchPrevention.reset();
            clearActivePoints();
            if (screenOn) {
                {
                    std::lock_guard<std::mutex> algoLock(mAlgoMutex);
                    if (mAlgo.setMode != nullptr) {
                        mAlgo.setMode(mAlgoContext, 1);
                    }
                }
                if (mFingerprintHalReport.load()) {
                    setFingerprintAlgoMode(true, true);
                    setFingerprintDcModeLocked(true, true);
                }
            }
            return false;
        }

        mTouchPrevention.reset();
        resetActiveState();
        mHbpSuspended.store(true);
        mHbpScreenOn.store(false);
        LOG(INFO) << "HBP screen off: core mode 1, algorithm mode off";
        return true;
    }

    // Stock ts_get_palm_mode() is consulted on the screen-on path.  When the
    // panel enables palm_mode_support, syna_hbp_main resets the vendor
    // algorithm state (PARAM_ID 0xe) and re-applies the panel config mode.
    // PARAM_ID 0xe is the ALGO's full data re-init path: it clears palm,
    // report, coordinate-filter, water, and temperature state.
    void resetAlgoForScreenOnLocked() {
        if (mAlgo.setParam == nullptr || mAlgoContext == nullptr) {
            return;
        }

        std::lock_guard<std::mutex> algoLock(mAlgoMutex);
        uint32_t result = 0;

        if (mPalmModeSupport) {
            result = mAlgo.setParam(mAlgoContext, 0xe, 1);
            if (result != 0) {
                LOG(WARNING) << "HBP palm-mode ALGO reset failed: " << result;
            } else {
                uint32_t panelIndex = 0;
                if (mAlgoConfig.selected_id >= 0) {
                    panelIndex =
                            static_cast<uint32_t>(mAlgoConfig.selected_id);
                }
                result = mAlgo.setParam(mAlgoContext, 0x11, panelIndex);
                if (result != 0) {
                    LOG(WARNING) << "HBP ALGO panel reapply failed: " << result;
                } else {
                    LOG(INFO) << "HBP palm-mode ALGO reset, panel index "
                              << panelIndex;
                }
            }
        }

        // Stock enables the insert-point mode through ts_update_custom_cfg()
        // (PARAM_ID 0).  It lets IGetAlgoInsertRealPoint return the points the
        // palm/edge algorithm removed from the normal package.
        result = mAlgo.setParam(mAlgoContext, 0x0, 1);
        if (result != 0) {
            LOG(DEBUG) << "HBP insert mode unavailable: " << result;
        } else {
            LOG(INFO) << "HBP insert-point mode enabled";
        }
    }

    // Mirror the stock STATE_SCREEN_ON branch: switch the core back to mode 3
    // (enable report), then put the vendor algorithm into MODE_SCREEN_ON.
    bool enterScreenOnLocked(bool force = false) {
        if (!force && mHbpScreenOn.load() && !mHbpSuspended.load()) {
            mScreenOn.store(true);
            return true;
        }
        if (mHandle == nullptr) {
            return false;
        }

        // Let reports produced while the core transitions reach the IFP path.
        mScreenOn.store(true);
        uint32_t result = 0;
        if (!switchHbpModeLocked(3, &result)) {
            LOG(WARNING) << "HBP screen on: tcmSetMode(3) transition failed: "
                         << result;
            const bool screenOn = screenStateIsOn();
            mScreenOn.store(screenOn);
            // Keep retrying the screen-on transition while the display says
            // it is on; if the display is actually off, the service loop and
            // the suspend path will take over.
            mHbpScreenOn.store(false);
            mHbpSuspended.store(false);
            mTouchPrevention.reset();
            clearActivePoints();
            return false;
        }

        {
            std::lock_guard<std::mutex> algoLock(mAlgoMutex);
            if (mAlgo.setMode != nullptr) {
                mAlgo.setMode(mAlgoContext, 1);
            }
        }
        resetAlgoForScreenOnLocked();
        mTouchPrevention.reset();
        resetActiveState();
        mHbpSuspended.store(false);
        mHbpScreenOn.store(true);
        mFingerprintDcPending.store(-1);
        if (mFingerprintHalReport.load()) {
            setFingerprintAlgoMode(true, true);
            setFingerprintDcModeLocked(true, true);
        } else {
            setFingerprintAlgoMode(false, true);
            if (mFingerprintDcEnabled.load()) {
                setFingerprintDcModeLocked(false, true);
            }
        }
        mFingerprintDcPending.store(-1);
        applyFirmwareGripLevel(mEdgeGripLevel);
        LOG(INFO) << "HBP screen on: core mode 3";
        return true;
    }

    bool enterScreenOff(bool force = false) {
        std::lock_guard<std::mutex> lock(mHalMutex);
        if (!mRunning.load() || mHandle == nullptr) {
            return false;
        }
        return enterScreenOffLocked(force);
    }

    bool enterScreenOn(bool force = false) {
        std::lock_guard<std::mutex> lock(mHalMutex);
        if (!mRunning.load() || mHandle == nullptr) {
            return false;
        }
        return enterScreenOnLocked(force);
    }

    void serviceLoop() {
        int consecutiveErrors = 0;
        int stateRequests = 0;
        while (mRunning.load()) {
            if (mHbpSuspended.load()) {
                // Stock waits on its resume condition after switching the
                // core to mode 1.  The kernel owns LBP gestures/UDFPS here.
                consecutiveErrors = 0;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            TcmActionInfo action = {};
            uint32_t result = 0;
            const int fingerprintDc = mFingerprintDcPending.exchange(-1);
            {
                std::lock_guard<std::mutex> lock(mHalMutex);
                if (mHandle == nullptr) {
                    break;
                }
                if (mHbpSuspended.load()) {
                    continue;
                }
                if (fingerprintDc >= 0 && !gSuspendPending &&
                    mScreenOn.load()) {
                    // The inotify thread applies the ALGO parameter directly;
                    // the HBP handle write is applied here so it cannot be
                    // starved by the continuous tcmService() loop.
                    setFingerprintDcModeLocked(fingerprintDc != 0, true);
                }
                result = mTcmService(mHandle, 100, &action);
            }

            if (result == 0x75) {
                consecutiveErrors = 0;
                continue;  // timeout, no report
            }
            if (result == 0) {
                consecutiveErrors = 0;
                continue;
            }
            if (result == 0x67) {
                // 0x67 is not a transport error.  It is the HBP core asking
                // the daemon to switch state, exactly what stock handles in
                // ts_isSyncSuspend().  If the driver is suspended, run the
                // full screen-off transition; otherwise wait for the next
                // event instead of retrying the same call in a tight loop.
                consecutiveErrors = 0;
                ++stateRequests;
                bool suspended = false;
                {
                    std::lock_guard<std::mutex> lock(mHalMutex);
                    if (mHandle == nullptr) {
                        break;
                    }
                    suspended = driverReportsSuspendedLocked();
                }
                if (suspended || !screenStateIsOn()) {
                    if (action.actionId == 4) {
                        LOG(INFO) << "HBP core requested screen-off transition";
                    }
                    enterScreenOff(false);
                } else {
                    if ((stateRequests % 20) == 1) {
                        LOG(DEBUG) << "HBP core state request while driver is on"
                                   << " action=" << action.actionId;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
                continue;
            }
            if (result == 0x78) {
                LOG(WARNING) << "HBP core requested termination (0x78)";
                break;
            }

            ++consecutiveErrors;
            if ((consecutiveErrors % 50) == 1) {
                LOG(WARNING) << "tcmService failed: " << result;
            }
            // Do not tear the pipeline down after a short burst.  The HBP
            // core has its own recovery state and the next mode transition
            // must still be able to run.
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        mRunning.store(false);
        clearActivePoints();
        closeHal();
        LOG(INFO) << "HBP userspace pipeline stopped";
    }

    void watchdogLoop() {
        int64_t lastSignalMs = 0;
        while (mRunning.load()) {
            // Wait up to 500 ms, but respond immediately to a vendor display
            // transition.  The signal handler records resume and suspend
            // separately so a quick off/on pair is not collapsed.
            for (int i = 0; i < 50 && mRunning.load() &&
                            !gResumePending && !gSuspendPending; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            if (!mRunning.load()) {
                break;
            }

            const bool suspendSignal = gSuspendPending != 0;
            const bool resumeSignal = gResumePending != 0;
            gSuspendPending = 0;
            gResumePending = 0;
            const int64_t now = nowMs();
            if (suspendSignal || resumeSignal) {
                lastSignalMs = now;
            }

            const int edgeGripLevel = readEdgeGripLevel();
            if (edgeGripLevel != mEdgeGripLevel) {
                std::lock_guard<std::mutex> lock(mHalMutex);
                if (!mRunning.load()) {
                    break;
                }
                mEdgeGripLevel = edgeGripLevel;
                if (mPreventionEnabled) {
                    mTouchPrevention.setStrength(edgeGripLevel);
                }
                if (mHandle != nullptr && mHbpScreenOn.load() &&
                    !mHbpSuspended.load()) {
                    applyFirmwareGripLevel(edgeGripLevel);
                }
                clearActivePoints();
                LOG(INFO) << "HBP edge grip level changed to " << edgeGripLevel;
            }

            // Signals 44/45 are authoritative.  Process the actual off/on
            // pair in order; the resume transition is forced so a lost
            // suspend notification still re-enables report mode.
            if (suspendSignal) {
                enterScreenOff(false);
            }
            if (resumeSignal) {
                enterScreenOn(true);
            }

            // Use debug.tracing.screen_state only as a fallback, and only
            // after the state has had time to settle.  It can lag the kernel
            // resume by several frames.
            if (!suspendSignal && !resumeSignal && now - lastSignalMs > 1000) {
                const bool screenOn = screenStateIsOn();
                if (screenOn != mHbpScreenOn.load()) {
                    if (screenOn) {
                        enterScreenOn(false);
                    } else {
                        enterScreenOff(false);
                    }
                }
            }
        }
    }

    // Event-driven fingerprint_hal monitor.  The fingerprint HAL writes bit 1
    // when authentication/enrollment starts; inotify wakes this thread
    // immediately, so there is no polling delay on the fingerprint path.
    void fingerprintLoop() {
        int inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        int watch = -1;
        if (inotifyFd >= 0) {
            watch = inotify_add_watch(inotifyFd, kFingerprintHalNode,
                                      IN_MODIFY);
            if (watch < 0) {
                LOG(WARNING) << "cannot watch " << kFingerprintHalNode << ": "
                             << std::strerror(errno);
            }
        } else {
            LOG(WARNING) << "inotify_init1 failed: " << std::strerror(errno);
        }

        int lastMode = -1;
        bool lastReport = false;
        const auto refresh = [&]() {
            const int mode = readIntNode(kFingerprintHalNode, -1);
            if (mode < 0) {
                return;
            }
            const bool report = (mode & kFingerprintHalReport) != 0;
            const bool reportChanged = report != lastReport;
            lastReport = report;
            if (mode != lastMode) {
                lastMode = mode;
                LOG(DEBUG) << "HBP fingerprint_hal mode " << mode
                           << ", screen-on report "
                           << (report ? "on" : "off");
            }
            mFingerprintHalReport.store(report);

            if (reportChanged) {
                if (report) {
                    mFpSessionFrames.store(0, std::memory_order_relaxed);
                    mFpSessionPointFrames.store(0, std::memory_order_relaxed);
                    mFpSessionTriggers.store(0, std::memory_order_relaxed);
                } else {
                    forceFingerprintTriggerUp();
                    LOG(DEBUG) << "HBP fingerprint session: frames="
                               << mFpSessionFrames.load(std::memory_order_relaxed)
                               << " point_frames="
                               << mFpSessionPointFrames.load(std::memory_order_relaxed)
                               << " triggers="
                               << mFpSessionTriggers.load(std::memory_order_relaxed);
                }
            }

            if (!mRunning.load()) {
                return;
            }

            // The ALGO parameter does not need the HBP handle.  Apply it
            // immediately so the fingerprint path is never blocked by the
            // tcmService() hot loop or a screen transition.
            if (report != mFingerprintAlgoEnabled.load()) {
                setFingerprintAlgoMode(report);
            }

            const bool screenOn = mScreenOn.load() && !mHbpSuspended.load();
            if (!screenOn) {
                return;
            }
            if (report && (!mFingerprintDcEnabled.load() || reportChanged)) {
                queueFingerprintDcMode(true);
            } else if (!report &&
                       (reportChanged || mFingerprintDcEnabled.load())) {
                queueFingerprintDcMode(false);
            }
        };

        refresh();
        while (mRunning.load()) {
            if (inotifyFd >= 0 && watch < 0) {
                watch = inotify_add_watch(inotifyFd, kFingerprintHalNode,
                                          IN_MODIFY);
                if (watch < 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    refresh();
                    continue;
                }
            }

            if (inotifyFd < 0) {
                // Only used if inotify is unavailable on this kernel.  The
                // normal HBP path is event-driven.
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                refresh();
                continue;
            }

            struct pollfd descriptor = {inotifyFd, POLLIN, 0};
            const int pollResult = poll(&descriptor, 1, 200);
            if (pollResult > 0 && (descriptor.revents & POLLIN)) {
                char buffer[sizeof(struct inotify_event) + NAME_MAX + 1] = {};
                bool ignored = false;
                ssize_t length = 0;
                while ((length = read(inotifyFd, buffer, sizeof(buffer))) > 0) {
                    size_t offset = 0;
                    while (offset + sizeof(struct inotify_event) <=
                           static_cast<size_t>(length)) {
                        const auto* event =
                                reinterpret_cast<const struct inotify_event*>(
                                        buffer + offset);
                        if ((event->mask & IN_IGNORED) != 0) {
                            ignored = true;
                        }
                        offset += sizeof(struct inotify_event) + event->len;
                    }
                }
                if (ignored) {
                    watch = -1;
                }
                refresh();
            } else if (pollResult == 0) {
                // Retry an incomplete mode application; normal changes still
                // wake immediately through inotify above.
                refresh();
            } else if (pollResult < 0 && errno != EINTR) {
                LOG(WARNING) << "fingerprint_hal poll failed: "
                             << std::strerror(errno);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        if (inotifyFd >= 0 && watch >= 0) {
            inotify_rm_watch(inotifyFd, watch);
        }
        if (inotifyFd >= 0) {
            close(inotifyFd);
        }
    }

    void logFrameError(uint32_t size) {
        if ((mFrameErrors++ % 120) == 0) {
            LOG(WARNING) << "unexpected HBP frame size " << size << ", expected "
                         << mRawFrameSize;
        }
    }

    void logProcessError(uint32_t result) {
        if ((mProcessErrors++ % 120) == 0) {
            LOG(WARNING) << "IThpAlgoProcess failed: " << result;
        }
    }

    void logPointError() {
        if ((mPointErrors++ % 120) == 0) {
            LOG(WARNING) << "IGetAlgoPoint failed";
        }
    }

    void* mHal = nullptr;
    void* mAlgoLib = nullptr;
    TcmHandle mHandle = nullptr;

    TcmInitModule mTcmInitModule = nullptr;
    TcmUninitModule mTcmUninitModule = nullptr;
    TcmOpen mTcmOpen = nullptr;
    TcmClose mTcmClose = nullptr;
    TcmGetParam mTcmGetParam = nullptr;
    TcmSetParam mTcmSetParam = nullptr;
    TcmGetParamBlob mTcmGetParamBlob = nullptr;
    TcmSetEventCallback mTcmSetEventCallback = nullptr;
    TcmService mTcmService = nullptr;
    TcmSetMode mTcmSetMode = nullptr;
    TcmGetMode mTcmGetMode = nullptr;
    TcmGetHbpVersion mTcmGetHbpVersion = nullptr;

    AlgoApi mAlgo;
    AlgoFeatureConfig mAlgoConfig;
    TouchPanelVendor mPanelVendor = TouchPanelVendor::Unknown;
    bool mPalmModeSupport = false;
    bool mDebugPoints = false;
    void* mAlgoContext = nullptr;

    std::atomic<bool> mRunning{false};
    std::atomic<bool> mSawType4{false};
    std::atomic<bool> mScreenOn{true};
    std::atomic<bool> mHbpScreenOn{false};
    std::atomic<bool> mHbpSuspended{false};
    std::atomic<bool> mFingerprintActive{false};
    std::atomic<bool> mFingerprintHalReport{false};
    std::atomic<bool> mFingerprintAlgoEnabled{false};
    std::atomic<bool> mFingerprintDcEnabled{false};
    std::atomic<int> mFingerprintDcPending{-1};
    std::atomic<bool> mFingerprintTriggerDown{false};
    std::atomic<uint32_t> mFpSessionFrames{0};
    std::atomic<uint32_t> mFpSessionPointFrames{0};
    std::atomic<uint32_t> mFpSessionTriggers{0};
    std::atomic<int64_t> mFingerprintCheckedMs{0};
    uint32_t mFingerprintTriggerErrors = 0;
    std::mutex mFingerprintTriggerMutex;
    std::thread mThread;
    std::thread mWatchdog;
    std::thread mFingerprintThread;
    std::mutex mHalMutex;
    std::mutex mAlgoMutex;
    TouchReporter mReporter;
    bool mPreventionEnabled = false;
    int mEdgeGripLevel = 3;

    std::array<TouchPreventionPoint, 10> mLastPreventionPoints = {};
    std::array<TouchPoint, 10> mLastTouchPoints = {};
    std::array<TouchPoint, 10> mActivePoints = {};
    uint32_t mActiveMask = 0;
    std::mutex mActiveMutex;
    // Declared after the state its worker touches so it is destroyed first.
    TouchPrevention mTouchPrevention;

    int mRows = 17;
    int mCols = 38;
    int mMatrixSize = 0;
    int mRawFrameSize = 0;

    std::vector<uint8_t> mMatrix;
    std::vector<uint8_t> mColA;
    std::vector<uint8_t> mRowA;
    std::vector<uint8_t> mColB;
    std::vector<uint8_t> mRowB;
    FrameDataParse mFrame = {};

    uint32_t mFrameIndex = 0;
    bool mHaveLastFrame = false;
    std::chrono::steady_clock::time_point mLastFrame;

    uint32_t mFrameErrors = 0;
    uint32_t mProcessErrors = 0;
    uint32_t mPointErrors = 0;
    uint32_t mRejectedFrames = 0;
};

// ---------------------------------------------------------------------------
// HBP gesture bridge
// ---------------------------------------------------------------------------

int gestureTypeToKeycode(uint32_t type) {
    // These are the HBP / legacy gesture ids used by the touchpanel proc
    // interface.  The Lineage HAL uses KEY_GESTURE_START + id.
    switch (type) {
        case 2:  return kGestureStartKey + 2;   // UpVee / V
        case 3:  return kGestureStartKey + 3;   // DownVee
        case 4:  return kGestureStartKey + 4;   // LeftVee
        case 5:  return kGestureStartKey + 5;   // RightVee
        case 6:  return kGestureStartKey + 6;   // Circle / O
        case 7:  return kGestureStartKey + 7;   // Double swipe
        case 8:  return kGestureStartKey + 8;   // Left to right
        case 9:  return kGestureStartKey + 9;   // Right to left
        case 10: return kGestureStartKey + 10;  // Up to down
        case 11: return kGestureStartKey + 11;  // Down to up
        case 12: return kGestureStartKey + 12;  // M
        case 13: return kGestureStartKey + 13;  // W
        case 16: return kGestureStartKey + 16;  // Single tap
        case 18: return kGestureStartKey + 18;  // S
        default: return -1;
    }
}

class InputInjector {
  public:
    ~InputInjector() {
        close();
    }

    bool open() {
        mFd = ::open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (mFd < 0) {
            LOG(WARNING) << "cannot open /dev/uinput: " << std::strerror(errno);
            return false;
        }

        if (ioctl(mFd, UI_SET_EVBIT, EV_KEY) < 0) {
            LOG(WARNING) << "UI_SET_EVBIT failed: " << std::strerror(errno);
            close();
            return false;
        }

        for (int key = kGestureStartKey; key <= kGestureStartKey + 31; ++key) {
            if (ioctl(mFd, UI_SET_KEYBIT, key) < 0) {
                LOG(WARNING) << "UI_SET_KEYBIT " << key << " failed: "
                             << std::strerror(errno);
                close();
                return false;
            }
        }

        struct uinput_setup setup = {};
        setup.id.bustype = BUS_VIRTUAL;
        setup.id.vendor = 0x1d1d;
        setup.id.product = 0x0001;
        setup.id.version = 1;
        snprintf(setup.name, sizeof(setup.name), "oplus-touch-gesture");
        if (ioctl(mFd, UI_DEV_SETUP, &setup) < 0) {
            LOG(WARNING) << "UI_DEV_SETUP failed: " << std::strerror(errno);
            close();
            return false;
        }

        if (ioctl(mFd, UI_DEV_CREATE) < 0) {
            LOG(WARNING) << "UI_DEV_CREATE failed: " << std::strerror(errno);
            close();
            return false;
        }

        LOG(INFO) << "virtual gesture input device created";
        return true;
    }

    void sendKey(int keycode) {
        if (mFd < 0 || keycode < 0) {
            return;
        }

        struct input_event events[4] = {};
        events[0].type = EV_KEY;
        events[0].code = static_cast<uint16_t>(keycode);
        events[0].value = 1;
        events[1].type = EV_SYN;
        events[1].code = SYN_REPORT;
        events[1].value = 0;
        events[2].type = EV_KEY;
        events[2].code = static_cast<uint16_t>(keycode);
        events[2].value = 0;
        events[3].type = EV_SYN;
        events[3].code = SYN_REPORT;
        events[3].value = 0;

        writeEvents(events, sizeof(events));
    }

    bool valid() const {
        return mFd >= 0;
    }

    void close() {
        if (mFd >= 0) {
            ioctl(mFd, UI_DEV_DESTROY);
            ::close(mFd);
            mFd = -1;
        }
    }

  private:
    int mFd = -1;

    void writeEvents(const struct input_event* events, size_t size) {
        size_t written = 0;
        const auto* data = reinterpret_cast<const char*>(events);
        while (written < size) {
            const ssize_t count = write(mFd, data + written, size - written);
            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                LOG(ERROR) << "failed to write virtual gesture event: "
                           << std::strerror(errno);
                return;
            }
            if (count == 0) {
                return;
            }
            written += static_cast<size_t>(count);
        }
    }
};

class GestureBridge {
  public:
    ~GestureBridge() {
        stop();
    }

    bool start() {
        mRunning.store(true);
        mThread = std::thread([this] { run(); });
        return true;
    }

    void stop() {
        if (!mRunning.exchange(false)) {
            return;
        }
        if (mThread.joinable()) {
            mThread.join();
        }
    }

  private:
    std::atomic<bool> mRunning{false};
    std::thread mThread;
    int mEventFd = -1;
    bool mEventWritable = false;
    InputInjector mInjector;

    int findTouchEvent() {
        for (int i = 0; i < 64; ++i) {
            char path[64];
            snprintf(path, sizeof(path), "/dev/input/event%d", i);
            int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
            bool writable = fd >= 0;
            if (fd < 0) {
                fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            }
            if (fd < 0) {
                continue;
            }

            char name[128] = {};
            if (ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name) < 0) {
                close(fd);
                continue;
            }

            if (strstr(name, "touchpanel") != nullptr ||
                strstr(name, "synaptics") != nullptr) {
                mEventWritable = writable;
                LOG(INFO) << "using " << path << " (" << name << ", "
                          << (writable ? "read-write" : "read-only") << ")";
                return fd;
            }

            close(fd);
        }
        return -1;
    }

    void injectKey(int keycode) {
        if (keycode < 0) {
            return;
        }

        if (mInjector.valid()) {
            mInjector.sendKey(keycode);
            LOG(INFO) << "injected gesture key " << keycode;
            return;
        }

        if (mEventFd < 0 || !mEventWritable) {
            return;
        }

        struct input_event events[4] = {};
        events[0].type = EV_KEY;
        events[0].code = static_cast<uint16_t>(keycode);
        events[0].value = 1;
        events[1].type = EV_SYN;
        events[1].code = SYN_REPORT;
        events[1].value = 0;
        events[2].type = EV_KEY;
        events[2].code = static_cast<uint16_t>(keycode);
        events[2].value = 0;
        events[3].type = EV_SYN;
        events[3].code = SYN_REPORT;
        events[3].value = 0;

        size_t written = 0;
        const auto* data = reinterpret_cast<const char*>(events);
        while (written < sizeof(events)) {
            const ssize_t count = write(mEventFd, data + written, sizeof(events) - written);
            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                LOG(ERROR) << "failed to inject gesture key " << keycode << ": "
                           << std::strerror(errno);
                return;
            }
            if (count == 0) {
                LOG(ERROR) << "short write while injecting gesture key";
                return;
            }
            written += static_cast<size_t>(count);
        }
        LOG(INFO) << "injected gesture key " << keycode;
    }

    void handleGesture() {
        std::string value;
        if (readFile(kCoordinateNode, &value) < 0) {
            LOG(DEBUG) << "cannot read " << kCoordinateNode << ": " << std::strerror(errno);
            return;
        }

        const std::string trimmed = trimWhitespace(value);
        if (trimmed.empty()) {
            return;
        }

        char* end = nullptr;
        errno = 0;
        const unsigned long type = strtoul(trimmed.c_str(), &end, 10);
        if (errno != 0 || end == trimmed.c_str()) {
            LOG(DEBUG) << "cannot parse gesture coordinate: " << trimmed;
            return;
        }

        const int keycode = gestureTypeToKeycode(static_cast<uint32_t>(type));
        if (keycode < 0) {
            LOG(DEBUG) << "ignoring unsupported HBP gesture type " << type;
            return;
        }
        injectKey(keycode);
    }

    void run() {
        if (!mInjector.open()) {
            LOG(WARNING) << "falling back to evdev injection on the touch device";
        }

        while (mRunning.load()) {
            if (mEventFd < 0) {
                mEventFd = findTouchEvent();
                if (mEventFd < 0) {
                    LOG(WARNING) << "touch input device not found; retrying";
                    sleep(1);
                    continue;
                }
            }

            struct pollfd pfd = {};
            pfd.fd = mEventFd;
            pfd.events = POLLIN;
            const int pollResult = poll(&pfd, 1, 1000);
            if (pollResult < 0) {
                if (errno == EINTR) {
                    continue;
                }
                LOG(ERROR) << "poll on touch input failed: " << std::strerror(errno);
                close(mEventFd);
                mEventFd = -1;
                continue;
            }
            if (pollResult == 0) {
                continue;
            }
            if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                LOG(WARNING) << "touch input device disappeared";
                close(mEventFd);
                mEventFd = -1;
                continue;
            }

            struct input_event events[32];
            const ssize_t count = read(mEventFd, events, sizeof(events));
            if (count < 0) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                }
                LOG(ERROR) << "read from touch input failed: " << std::strerror(errno);
                close(mEventFd);
                mEventFd = -1;
                continue;
            }

            const size_t eventCount = static_cast<size_t>(count) / sizeof(events[0]);
            for (size_t i = 0; i < eventCount; ++i) {
                const struct input_event& event = events[i];
                if (event.type == EV_KEY && event.code == KEY_F4 && event.value == 1) {
                    handleGesture();
                }
            }
        }

        if (mEventFd >= 0) {
            close(mEventFd);
            mEventFd = -1;
        }
    }
};

void logFeatureConfig(const std::string& path) {
    tinyxml2::XMLDocument document;
    if (document.LoadFile(path.c_str()) != tinyxml2::XML_SUCCESS) {
        LOG(WARNING) << "cannot parse " << path << ": " << document.ErrorStr();
        return;
    }

    const tinyxml2::XMLElement* root = document.RootElement();
    if (root == nullptr) {
        LOG(WARNING) << path << " has no root element";
        return;
    }

    if (const tinyxml2::XMLElement* version = root->FirstChildElement("version");
        version != nullptr && version->GetText() != nullptr) {
        LOG(INFO) << path << " version=" << version->GetText();
    }

    for (const tinyxml2::XMLElement* device = root->FirstChildElement("device");
         device != nullptr; device = device->NextSiblingElement("device")) {
        const int deviceId = device->IntAttribute("id", 0);
        for (const tinyxml2::XMLElement* panel = device->FirstChildElement("panel");
             panel != nullptr; panel = panel->NextSiblingElement("panel")) {
            const char* name = panel->Attribute("name");
            LOG(INFO) << "touch feature device=" << deviceId
                      << " panel=" << (name != nullptr ? name : "<unnamed>");
        }
    }
}

void logConfiguration() {
    const auto featureConfigs = findConfigs(kFeatureConfigName);
    if (featureConfigs.empty()) {
        LOG(WARNING) << "no " << kFeatureConfigName << " found";
        return;
    }

    logFeatureConfig(featureConfigs.front());
}

}  // namespace

int main() {
    android::base::InitLogging(nullptr, android::base::LogdLogger());
    installTouchSignalHandlers();
    LOG(INFO) << "source touchDaemon starting";

    GestureBridge gestureBridge;
    gestureBridge.start();

    logConfiguration();

    char pipelineProperty[PROP_VALUE_MAX] = {};
    property_get(kPipelineProperty, pipelineProperty, "1");
    HbpPipeline pipeline;
    if (std::strcmp(pipelineProperty, "0") != 0) {
        bool started = false;
        for (int attempt = 0; attempt < 15 && !started; ++attempt) {
            started = pipeline.start();
            if (!started) {
                sleep(1);
            }
        }
        if (!started) {
            LOG(INFO) << "HBP userspace pipeline is not active; kernel touch reporting remains";
        }
    } else {
        LOG(INFO) << "HBP userspace pipeline disabled; kernel touch reporting remains";
    }

    while (!gTerminateRequested) {
        pause();
    }

    pipeline.stop();
    gestureBridge.stop();
    return 0;
}
