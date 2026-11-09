# OPLUS touch reverse-engineering notes

## Inputs

- `vendor/oneplus/sm8650-common/proprietary/odm/bin/hw/vendor-oplus-hardware-touch-V2-service`
  - SHA-256 `219d1b5aed650dfb7f1fd99c3869f26aad1aa3ef4920a500ef8cca975cd82e3f`
  - 1328 Ghidra procedures, 2035 defined strings.
- `vendor/oneplus/sm8650-common/proprietary/odm/bin/touchDaemon`
  - SHA-256 `f84be749e8ad8a15e5667b3e3dc367edfdb95b335c04d267e1be93de8790943b`
  - 1070 Ghidra procedures, 2538 defined strings.
- `vendor/oneplus/waffle/proprietary/odm/firmware/tp/22825/`
  - S3910 HAL and ALGO libraries and scene XML.

## Service behavior

The stock service has two personalities selected in its constructor:

- `/proc/touchpanel/framework_mode` exists: `BINDER_MODE`.
- otherwise: direct proc mode.
- The legacy no-`/proc/touchpanel` entry point is `HBPService`.

In `BINDER_MODE` the service forwards node operations to the daemon's native
Binder service named `touchDeamonBinder` with a raw Parcel payload:

```text
int32 deviceId
int32 nodeFlag
int32 operation   # 0 write, 1 read, 2 support, 4 BT info
[optional String16 BT/pen payload for operation 4]
```

The daemon's `MyBinderService::onTransact` performs the operation and returns a
String16 result.

The source service does not use this transport. It owns the nodes directly.
`/proc/touchpanel/framework_mode` is deliberately ignored.

## Recovered node table

The table is at `0x15c5f8` in the stock service, 96 entries of `0x5c` bytes:

```c
struct entry {
    int32_t flag;
    int32_t devicePosition;
    char directory[0x28];
    char name[0x28];
    int32_t readSize;
};
```

- `devicePosition == 1` produces `directory + deviceId + "/" + name`.
- `devicePosition == 2` produces `directory + "/" + name + deviceId`.
- `deviceId == 0` uses `directory + "/" + name`.
- `flag == 0xa8` is the special "list all nodes" operation.

The stock table is preserved in `TouchNodeMap.cpp`, with the legacy
kernel-grip, edge-limit, dead-zone, and TCM character-device entries omitted
because HBP owns those paths.

Important flags:

- `1` `double_tap_enable`
- `21` `double_tap_enable_indep`
- `26` `game_switch_enable`
- `31` `fp_enable`
- `192` `glove_mode_enable`

`TouchscreenGesture.cpp` uses `(0, 21)` for the gesture mask and `(0, 1)` to
keep gestures enabled.

## AIDL contract

The shipped V2 contract contains:

- `initialize()`
- `isTouchNodeSupport()`
- `touchReadNodeFile()`
- `touchWriteNodeFile()`
- `touchWriteBtInfo()`
- one-way `touchWriteNodeFileOneWay()`
- `touchNotifyClient()`
- `registerEventCallback()`
- `unregisterEventCallback()`

`OplusTouchStatus` is an `@Backing(type="int")` enum.
`IOplusTouchEventCallback` has `touchSendCommand()` and one-way
`touchSendCommandOneWay()`.

The stock `touchNotifyClient` dispatch rule:

- `clientFlag < 0x10000`: one-way callback.
- `clientFlag >= 0x10000`: synchronous callback.

The source service implements the same rule. Its unregister path removes only
the matching callback; the stock implementation had a list-walk bug that could
remove unrelated entries.

`touchWriteBtInfo` was forwarded to the daemon as the BT pen message type. There
is no in-tree BT pen consumer, so the source implementation logs the request and
returns `-1` rather than writing a pressure string to a proc node.

## Daemon behavior and source boundary

The stock daemon:

- opens `/dev/tp_misc`, `/dev/tp_misc1`, and `/dev/tcm_hbp0`;
- loads `LIB_<panel>_TS_HAL.so` and `LIB_<panel>_TS_ALGO.so` via `dlopen`;
- processes HBP frames in the ALGO library;
- registers `touchDeamonBinder`;
- parses touch scene/edge XML;
- sends `touchNotifyClient` notifications to the AIDL service.

The source daemon keeps the userspace gesture hand-off and also owns the HBP
AFE/ALGO frame pipeline. The gesture bridge watches the HBP input device for
`KEY_F4`, reads the decoded gesture from `/proc/touchpanel/coordinate`, maps the
legacy gesture id to `KEY_GESTURE_START + id`, and creates a uinput keyboard for
those scan codes. The source service exposes a software gesture mask for the
legacy AIDL node 21 because HBP does not create `double_tap_enable_indep`.

The HBP AFE/ALGO pipeline:

- It derives the panel library from `/proc/devinfo/tp` `Device fw_path`.
- It sets `vendor.oplus.touch.customifplib.path` to the stock `libIfp.so`.
- It calls `tcmInitModule`, `tcmOpen("/dev/tcm_hbp", ...)`, and registers the
  event callback.
- It enables the custom frame path (IDs 9 and 10), doze (ID 6), recovery
  (ID 8), and HBP mode (ID 2).  The stock daemon leaves the core in its
  initial idle mode at this point; the screen transition selects mode 3 or
  mode 1.
- The HBP core is a two-stage state machine: `tcmSetMode()` selects the next
  mode and `tcmService()` runs the transition.  Mode 3 is screen-on/enable
  report; mode 1 is screen-off/idle.  The daemon mirrors stock
  `ts_switch_mode()` by calling `tcmSetMode`, servicing once or twice, then
  verifying the current mode with `tcmGetMode`.
- It feeds the `FrameDataParse` package from the HAL/IFP path to
  `IFrameDataParse`, `IThpAlgoProcess`, `IGetAlgoPoint`, and `IGetAftInfo`.
  The matrix is copied with the panel-native row stride: BOE uses 17x38 and
  TIANMA uses 18x40. BOE's parser reads `numColumns` from hardware-info offset
  0 and `numRows` from offset 2, so those fields are filled before init.
- It selects the ALGO entry points by panel: BOE uses `IAlgoOpen` followed by
  `IAlgoInit(ctx, hardware, 0x31c)`; TIANMA uses `IThpAlgoInit`. The resulting
  context is passed to every subsequent ALGO call. It also registers
  `IAlgoSetConfigReadCallback` before setting
  `PARAM_ID_ALGO_CONFIG_MODE (0x11)` to the XML panel index, because the BOE
  library invokes that callback while handling 0x11.
- It serves every parameter from `sys_touch_algo_feature_config.xml` to the
  ALGO callback. The keys are spread across `AlgoParam`, `FeatureEn`, `AFT`,
  `Palm`, and the other modules in that panel, not just `AlgoParam`. It also
  merges the `TouchConfig` and `PreventionConfig` keys from
  `sys_touch_function_feature_config.xml` (`palm_mode_support`,
  `hbp_algo_diff_support`, `smooth-level`, `sensitive-level`, panel geometry,
  grip level, and the monitor/feature switches), because stock's `configLoad`
  asks the same callback for those keys.
- The stock HBP type-4 path builds a 20-byte-per-point `touch_point_report`
  and a 32-byte-per-point `point_info` array, then calls
  `oplus_prevention_handle()` at `0x457cc`. That wrapper calls
  `get_touch_points()` and `notify_prevention_handle()`; it is not a direct
  `notify_prevention_handle()` call, which is why the earlier xref-only
  analysis missed it. The source daemon runs the same prevention engine by
  default. It indexes prevention by ALGO point ID and AFT by package slot,
  matching stock.
- BOE's public getters have an inverted size check: they copy only when the
  requested size is below the payload boundary (`IGetAlgoPoint()` accepts
  `< 0xf9`, `IGetAftInfo()` accepts `< 0x29`) and reject the full payload
  size. The rejection messages are misleading (`reportData is NULL` and
  `size is error, aftReportData`). The daemon reserves `0x100` and `0x30`
  byte buffers but passes `0xf8` and `0x28`.
- Stock also resets the vendor ALGO state on the screen-on transition when
  `palm_mode_support=1`: `ts_get_palm_mode()` is true for this panel, and
  `IThpAlgoSetParam(ctx, 0xe, 1)` reinitializes palm, report, coordinate
  filter, water, and temperature state. The daemon now performs the same
  reset, re-applies the panel config mode (`0x11`), and enables the insert
  mode (`PARAM_ID 0`).
- Stock type-4 signals `process_insertpt_timer` (`0x44b4c`) while the panel
  is in the high-frame-rate reporting path. The worker calls
  `IGetAlgoInsertRealPoint()` through ALGO table offset `+0x48`, decodes the
  same 20-byte report layout, runs prevention, and reports the insert points.
  The source daemon performs the equivalent merge synchronously after
  `IThpAlgoProcess()`: every active insert ID not present in the normal
  package is added to the current frame, and the insert group runs prevention
  separately so the rejected palm cannot cover the recovered finger. AFT
  records remain indexed by package slot, matching stock.
- Fingerprint activity does not bypass prevention in stock. The previous
  source-daemon behavior reset prevention and exempted the entire frame while
  UDFPS was active, which let a resting palm through raw. Prevention now stays
  active; only a small contact inside the parsed `fpSpotCenterX/Y/Radius` is
  re-added to the output mask.
- It reapplies the firmware grip DCs through the HBP handle when the shared
  edge-grip level changes. While the daemon owns `/dev/tcm_hbp0`, the kernel
  sysfs write can update only the stored level and cannot reliably program the
  panel through the daemon-owned response path.  A level change while the
  panel is suspended is deferred to the next screen-on transition.
- It mirrors the stock screen-state transitions.  On suspend it calls
  `ts_suspend_application`'s ALGO parameter `0x15, 0`, sets the vendor ALGO to
  `MODE_SCREEN_OFF`, switches the HBP core to mode 1, then pauses servicing
  until resume.  On resume it switches the core back to mode 3, sets ALGO
  `MODE_SCREEN_ON`, and applies the current firmware grip level.  HBP
  custom-frame parameters, HBP mode, and `DC_CONTROL_LBP_HBP` are not rewritten
  on resume; the kernel resume path has already restored them.
- `tcmService()` returning `0x67` (103) is a state-change request, not an
  error.  The daemon handles it like stock `ts_isSyncSuspend()`: it reads the
  driver power state and, if the panel is suspended, runs the screen-off
  transition.  Repeated transient service errors no longer tear down the
  pipeline.
- The daemon installs handlers for vendor signals `SIGRTMIN+2..+6`. Signals
  44/45 are `ts_resume_application`/`ts_suspend_application` and drive the HBP
  mode transitions; a quick off/on pair is kept as two separate pending
  transitions.  Signals 46/47/48 are fingerprint-down, under-water, and
  fingerprint-up notifications and are caught but do not drive HBP transitions.
  This prevents screen-state changes from terminating the daemon and forcing
  init to restart it.
- While `/proc/touchpanel/fingerprint_active` is set, prevention stays active.
  Only a small contact inside the parsed `fpSpotCenterX/Y/Radius` is exempted
  from the prevention result so a UDFPS press is not classified as a
  grip/palm touch. Fingerprint state is polled with a short cache to avoid
  opening the proc node every frame.
- Screen-on fingerprint reporting is bridged explicitly.  `REPORT_HBP_ACTIVE_FRAME`
  bypasses the kernel's normal `REPORT_TOUCH` path, so
  `syna_dev_report_fp_screen_on()` never runs while HBP owns the panel.  The
  fingerprint HAL arms `/proc/touchpanel/fingerprint_hal` bit 1; the daemon
  watches that node with inotify (event-driven, no polling on the fingerprint
  path), applies `IThpAlgoSetParam(ctx, 1, 1)` immediately without waiting for
  the HBP handle mutex, and queues
  `tcmSetParam(handle, 7, DC_TOUCH_HOLD=0xD4, 3)` for the HBP service loop so
  the authentication path cannot be starved.  The UDFPS area is marked
  prevention-exempt.
- In HBP mode the HAL accepts only `0x23` active-frame and power-state
  reports, so the firmware `TOUCH_HOLD_DOWN/UP` (`0x80`/`0x81`) type-1 reports
  that stock writes to `/proc/touchpanel/fingerprint_trigger` are not
  delivered.  The daemon drives the same trigger from the type-4 algorithm
  points instead: while `fingerprint_hal` bit 1 is set it writes `1,x,y` from
  the first reported point (scaled from algorithm to touch-input coordinates)
  and `0,0,0` when the points are released.  The type-1 `0x80`/`0x81` handler
  remains as a secondary path.  Trigger transitions are serialized and an
  explicit up is written when bit 1 clears, because the kernel's `is_fp_down`
  persists across suspend and a stale down would suppress the next
  authentication.  Fingerprint state transitions are logged at DEBUG; the
  trigger down/up lines remain at INFO, and a DEBUG session summary reports
  `frames`, `point_frames`, and `triggers` when the bit clears.
- On screen-off the algorithm parameter and trigger state are cleared without
  touching the firmware touch-hold DC; the kernel/fingerprint HAL own the
  low-power path, and the full fingerprint mode is reapplied on resume.
- Normal 20-byte HBP status reports are not logged; only an unexpected status
  package size produces a debug line.
- The init rc makes `/dev/uinput` accessible to the daemon's `input` group so
  gesture keys use the virtual input device instead of injecting key events
  into the kernel touch device.
- On service termination it sends the HBP core mode 0 and closes the
  character device; cdev release then restores kernel LBP reporting.

The HBP kernel still forces the Synaptics firmware grip-suppression policy
during application-firmware setup and resume. That firmware layer is retained
as a second line of defense; the stock userspace ALGO/AFT plus prevention
engine is the primary mistouch/palm mechanism.

## Prior blob fixes

The old extraction script inserted this into the stock daemon rc:

```text
task_profiles ProcessCapacityHigh MaxPerformance
```

It is preserved in the source daemon rc.

The old extraction script replaced `libtinyxml2.so` with
`libtinyxml2_stock.so` for the prebuilt service and daemon. The source daemon
uses the platform `libtinyxml2` directly; the source service has no XML
dependency at all. No touch entry needs the `_stock` workaround.

## Prevention port

`sys_touch_function_feature_config.xml` is parsed for panel/version diagnostics
and for the stock `PreventionConfig` block. `sys_touch_algo_feature_config.xml`
is parsed for the vendor ALGO feature thresholds used by the normal HBP path.
Both parsers select the panel matching the resolved HBP library (`TIANMA` or
`BOE`). The kernel DTS continues to own the firmware equivalents; HBP firmware
grip is applied from the kernel at the selected level, and the source daemon
does not apply the legacy `sys_edge_touch_config.xml` values verbatim.

The prevention implementation is a userspace port of the stock daemon's
`oplus_prevention_*`, `kernel_grip_init`, `curved_large_handle_V2`, and helper
code. The stock binary calls the same engine from the HBP type-4 path through
`oplus_prevention_handle()`. The daemon clears the prevention and report
arrays every frame, because keeping a disappeared palm point with `status=1`
blocks every later finger. It also bypasses the custom AFT/geometry fallback
when the prevention configuration is missing; that fallback rejected normal
bottom-edge touches, so raw ALGO points are safer until the stock engine is
available. The reference binary is `proprietary/odm/bin/touchDaemon` from
vendor commit `0b4dda3` in the `sm8650-common` repository.

`persist.vendor.edge_grip_suppression` controls the firmware level and the
userspace prevention engine. Level `0` means fully raw input: both firmware
grip and userspace prevention are bypassed. Levels `1-5` scale the ten
edge/corner region dimensions used by `large_judge_pos()`; level `3` restores
the stock XML geometry exactly. The scale matches the firmware DARK X ratio
`(0x0A + 2 * (level - 1)) / 0x0E`. The daemon polls the persistent property
from its existing watchdog.

`persist.vendor.touch.hbp_prevention` is a diagnostic override, not a stock
property. It defaults to enabled (`1`, or unset). Set it to `0` only to bypass
userspace prevention while keeping firmware grip. `edge_grip_suppression=0`
also bypasses prevention regardless of this property.

`persist.vendor.touch.hbp_debug_points=1` enables per-frame point logging:
normal/insert counts, IDs, coordinates, pressure, contact axes, AFT bytes, and
the prevention input/output masks. It is off by default and only affects
logging.

The source HBP node map still does not forward the legacy direction and
reclining-mode nodes, so the prevention engine starts in the stock portrait
(`VERTICAL_SCREEN`) orientation. Landscape/reclining parameter switching is a
separate follow-up.

The userspace pipeline is controlled by
`persist.vendor.touch.hbp_pipeline` (default `1`). Setting it to `0` keeps the
daemon in gesture-only mode and leaves `/dev/tcm_hbp0` to the kernel path.
