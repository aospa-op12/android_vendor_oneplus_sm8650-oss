# Source OPLUS touch service

This module replaces the prebuilt OPLUS touch AIDL service and the stock
`touchDaemon` with source code.

## What is implemented

- `vendor.oplus.hardware.touch.IOplusTouch/default` V2.
- The stock node table, with the obsolete HBP grip, edge, and TCM entries
  omitted so userspace cannot reprogram the kernel-owned touch policy.
- Direct access to the `/proc` nodes used by the table.
- `initialize`, `isTouchNodeSupport`, node read/write, one-way write,
  callback registration, callback removal, and `touchNotifyClient`.
- A software gesture-mask compatibility node for the HBP driver, which does not
  expose the legacy `double_tap_enable_indep` proc node. The Lineage touch HAL
  can therefore read and update its gesture mask without crashing.
- A source `touchDaemon` that translates the HBP `KEY_F4` gesture notification
  and `/proc/touchpanel/coordinate` payload into the legacy
  `KEY_GESTURE_START + id` scan codes. The daemon creates a small uinput
  keyboard for those scan codes and falls back to evdev injection on the touch
  device when uinput is unavailable.
- A source HBP userspace pipeline that opens `/dev/tcm_hbp0` through the stock
  `libsynaHbpCore.so`, sets `vendor.oplus.touch.customifplib.path` to the stock
  `libIfp.so`, runs the stock `LIB_S3910_*_TS_ALGO.so` per-frame algorithm, and
  reports the algorithm's filtered points on the touch input device.
- `sys_touch_algo_feature_config.xml` is parsed per panel and served to the
  vendor ALGO through `IAlgoSetConfigReadCallback()`. The TouchConfig keys
  from `sys_touch_function_feature_config.xml` (`palm_mode_support`,
  `hbp_algo_diff_support`, `smooth-level`, `sensitive-level`, panel geometry,
  and the monitor/feature switches) are merged into the same map. This
  supplies the stock anti-mistouch, palm, AFT, edge-grip, gain, and mapping
  thresholds. Without it the vendor ALGO silently uses its built-in defaults,
  which are not the stock touch tuning.
- The stock HBP type-4 path reports the vendor ALGO points through the
  userspace prevention engine. The source daemon enables that engine by
  default, builds the prevention point array from the ALGO points and
  `IGetAftInfo()` records, and reports the filtered points. It also merges
  the stock `IGetAlgoInsertRealPoint()` package so fingers removed by the
  palm/edge algorithm can still be reported. The kernel continues to force
  the Synaptics firmware grip-suppression policy as a second layer. Set
  `persist.vendor.edge_grip_suppression=0` for fully raw input, which bypasses
  userspace prevention as well as firmware grip.
- The stock `task_profiles ProcessCapacityHigh MaxPerformance` setting remains
  on the source daemon.
- XML parsing uses the platform `libtinyxml2`. The stock
  `libtinyxml2_stock.so` dependency is intentionally not used.

## HBP boundary

The source daemon owns the userspace AFE/ALGO pipeline. It loads exactly the
vendor libraries selected by the kernel's `/proc/devinfo/tp` firmware path:

```text
/odm/firmware/tp/22825/LIB_S3910_<panel>_HBP_TS_HAL.so   (libsynaHbpCore.so)
/odm/firmware/tp/22825/libIfp.so                         (raw HBP frame package)
/odm/firmware/tp/22825/LIB_S3910_<panel>_HBP_TS_ALGO.so  (libthpalgo.so)
```

The HBP core is opened with `/dev/tcm_hbp`, which selects `/dev/tcm_hbp0` and
enables the kernel external-frame queue. The core's custom-IFP path invokes
`customFrameProcessor_detectObjects` from `libIfp.so`; the daemon then feeds the
resulting `FrameDataParse` package to `IFrameDataParse()` and
`IThpAlgoProcess()`. The point package from `IGetAlgoPoint()`, the insert
package from `IGetAlgoInsertRealPoint()`, and the AFT records from
`IGetAftInfo()` are fed to the userspace prevention engine before the
filtered points are reported through the touch input device. The insert
package uses the same 20-byte report layout; new point IDs are merged before
prevention. The BOE getters reject the full buffer lengths.
`IGetAlgoPoint()` accepts sizes below `0xf9` and `IGetAftInfo()` accepts sizes
below `0x29`, so the daemon passes the `0xf8` / `0x28` payload sizes while
reserving larger stack buffers. The library's rejection messages for larger
sizes are misleading (`reportData is NULL` and `size is error,
aftReportData`).

`REPORT_TOUCH` reports are still processed by the kernel before the external
frame queue check, so the existing `KEY_F4` low-power gesture bridge is
unchanged. If the vendor pipeline cannot start or the service loop fails, the
daemon releases `/dev/tcm_hbp0` and returns the panel to LBP so the kernel touch
path remains usable.

## Feature diagnostics

`sys_touch_function_feature_config.xml` is parsed at startup for panel/version
diagnostics and for the stock userspace `PreventionConfig` block.
`sys_touch_algo_feature_config.xml` is parsed for the vendor ALGO feature
thresholds used by the normal HBP path. Both parsers select the panel matching
the resolved HBP library (`TIANMA` or `BOE`). The kernel driver continues to
own the equivalent firmware/DTS values.

## Runtime control

The HBP userspace pipeline is enabled by default. Set
`persist.vendor.touch.hbp_pipeline=0` to leave the daemon in gesture-only mode
and keep the kernel HBP path.

`persist.vendor.edge_grip_suppression` controls the firmware grip and the
userspace prevention engine. `0` means fully raw input: firmware grip and
userspace prevention are both bypassed. `3` is the stock baseline, and `1-5`
scale the edge/corner width using the same ratios as the firmware
negative-DARK-X levels. The source daemon reads the persistent property at
startup and polls it from the watchdog.

`persist.vendor.touch.hbp_prevention` is a diagnostic override, not a stock
property. It defaults to enabled (`1`, or unset). Set it to `0` only to bypass
userspace prevention while keeping firmware grip for comparison. Prevention
is also bypassed whenever `persist.vendor.edge_grip_suppression=0`.

`persist.vendor.touch.hbp_debug_points=1` logs per-frame normal and insert
point IDs, coordinates, pressure, contact axes, AFT bytes, and prevention
input/output masks. It is off by default and only affects logging.

## Files

- `OplusTouch.cpp/.h` — Binder service and callback registry.
- `TouchNodeMap.cpp/.h` — recovered node flag table and path resolution.
- `main.cpp` — service registration.
- `touchDaemon/TouchConfigDaemon.cpp` — source touch daemon, HBP
  AFE/ALGO pipeline, and gesture bridge.
- `etc/` — init rc files and VINTF manifest.
- `docs/RE-NOTES.md` — reverse-engineering notes and source boundaries.
