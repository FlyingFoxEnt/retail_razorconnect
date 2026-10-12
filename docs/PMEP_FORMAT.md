# DECI4 PMEP (0x4000, power monitor) wire format (psp2tm.exe)

Reverse-engineered from decompiled `psp2tm.exe` (Ghidra project TMRE) plus the COM type library
`Interop.PSP2TMAPILib.dll`. Verified end to end with `tools/mock_pmep.py` against the live psp2tm,
`psp2ctrl battery` and the Battery Monitor GUI (2026-09-15). This is what
`PSP2BatteryMonitor.exe` needs.

## Key functions

| Function | Role |
|---|---|
| `FUN_1400d5950` | PMEP frame accessor: `proto@frame+8 == 0x4000`, 12-byte payload header at `frame+0x10` |
| `FUN_1400cedb0` | response validator: `payload[0] == expected RES code`, logs "Decoding PMEP response Code:0x.." |
| `FUN_140091310` | send + wait for `(seq, RES code)`, deadline `now + 5,000,000` ticks = **0.5 s** |
| `FUN_140132320` | async/unsolicited PMEP dispatcher: codes 0x01, 0x03, 0x13 |
| `FUN_1400ddaf0` / `FUN_14007d0b0` / `FUN_14010d8c0` | GET_PROPERTIES 0x00 (TMAPI `ChannelProperties`) |
| `FUN_1400ddb80` / `FUN_14007d1a0` / `FUN_14010d710` | GET_STATUS 0x02 (`QueryChannelValues`, request id 0x38206dfb) |
| `FUN_1400dd990` / `FUN_140089520` / `FUN_140108540` | GET_BATTERY_VALUES 0x04 (`GetBatteryValues`, 0x06b863d0) |
| `FUN_1400ddcb0` / `FUN_140089700` / `FUN_14013c640` | SET_BATTERY_VALUES 0x06 (`SetBatteryValues`, 0x19362a5c) |
| `FUN_1400ddc10` / `FUN_140089600` / `FUN_14013c490` | SET_AC_STATUS 0x08 (`put_ACStatus`, 0x75426a79) |
| `FUN_1400dd900` / `FUN_140089410` / `FUN_140107150` | GET_AC_STATUS 0x0C (`get_ACStatus`, 0x34e9eb6d) |
| `FUN_1400dda60` / `FUN_14007cfc0` / `FUN_14010d4f0` | GET_POWER_STATUS 0x12 (`QueryVoltages`, 0x354d2828) |
| `FUN_1400d5830` (1), `FUN_1400d58c0` (3), `FUN_1400d5710` (5), `FUN_1400d5a10` (7), `FUN_1400d59c0` (9), `FUN_1400d56c0` (0xd), `FUN_1400d57a0` (0x13) | per-code body bounds checks |
| `FUN_1400cdeb0` | self-sized record walker (each record's first u32 is its own size) |
| `FUN_1400ce200` | fixed 8-byte record walker |
| `FUN_1400f5350` / `FUN_140109090` | property record -> {UTF-8 name (CP 0xfde9, NUL-terminated), units, scale} |
| `FUN_1400e4e20` | voltage record {u16, u16, u32} -> 12-byte element |
| `FUN_14017c750`, `FUN_140175a40` | request dispatchers (switch on the request ids above) |

Request-id dispatch sites: `FUN_14017c750` at `14017cea9` (GetBatteryValues -> `FUN_140108540`),
`14017ee06` (SetBatteryValues -> `FUN_14013c640`), `1401808f5` (GetACStatus -> `FUN_140107150`),
`1401862de` (SetACStatus -> `FUN_14013c490`); `FUN_140175a40` at `140176d21` (GetPmepPowerStatus ->
`FUN_14010d4f0`) and `1401775e6` (GetPmepStatus -> `FUN_14010d710`).

## 1. Framing

```
frame +0x00  u24 total_len | u8 0x40 | u16 flags | u16 node | u32 proto = 0x4000 | u32 0
payload +0x00  u8  code          even = CMD (host), odd = RES (target) = CMD + 1
        +0x01  u8[3] 0
        +0x04  u32 arg           host puts target+0x2e0 here (observed 0x160afb = HWID low word); echo it
        +0x08  u32 seq           echo it; responses are matched on (seq, code)
        +0x0c  ...  body
```

The builders write `code` as a u32 (so bytes 1..3 are 0). A reply's body starts at payload+0x0c.
Any body `result` word other than 0 is mapped by `FUN_140074990` and reaches TMAPI as
`TMAPI_COMMS_ERR_UNKNOWN`; a body that is too short fails the bounds check -> internal 0x100007 ->
`TMAPI_COMMS_ERR_DECODE`.

## 2. Commands and responses (all little-endian)

| CMD | CMD body | RES | RES body | Path |
|---|---|---|---|---|
| 0x00 GET_PROPERTIES | none | 0x01 | `u32 result, u32 0 (unused), u32 count, count x PROPERTY` | async, matched by seq (`FUN_140068fc0`) |
| 0x02 GET_STATUS | none | 0x03 | `u32 result, u32 count, u16 value[count]` (pad to 4) | notification: `CPowerInfoNotification` + `CPowerDataNotification(seq, error)` |
| 0x04 GET_BATTERY_VALUES | `u32 count, u32 id[count]` | 0x05 | `u32 result, u32 count, count x {u32 id, u32 value}` | sync |
| 0x06 SET_BATTERY_VALUES | `u32 count, count x {u32 id, u32 value}` | 0x07 | `u32 result` | sync |
| 0x08 SET_AC_STATUS | `u32 plugged (0/1)` | 0x09 | `u32 result` | sync |
| 0x0C GET_AC_STATUS | none | 0x0D | `u32 result, u32 plugged (0/1)` | sync |
| 0x12 GET_POWER_STATUS | none | 0x13 | `u32 result, u32 count, count x {u16 channel, u16 flags, u32 voltage}` | notification: `CVoltageDataNotification` |

PROPERTY record (self-sized, walked by `FUN_1400cdeb0`):

```
+0x00  u32 record_len        = 16 + align4(name_len), includes itself; must be non-zero
+0x04  u32 name_len          bytes incl. NUL
+0x08  char name[align4(name_len)]   UTF-8, NUL-terminated
+0x08+align4(name_len)  u32 units    eUnits: 0 NotUsed, 1 MilliAmps, 2 Celcius
+0x0c+align4(name_len)  u32 scale    IChannelInfo.ScaleFactor (Single); 1.0f = 0x3F800000 verified
```

Channel values in RES 0x03 are indexed in property order. Values are u16. MilliAmps channels plot on
the Power graph and show in the legend (the legend labels the number "mW"); Celcius channels belong
to the Temperature tab.

Battery value ids (`eBatteryValue`) and units, as `psp2ctrl battery` prints them (a bq27xxx gauge):

| id | name | unit |
|---|---|---|
| 0 | BATTERY_TEMP | 0.1 K |
| 1 | BATTERY_VOLT | mV |
| 2 | BATTERY_RM | mAh remaining |
| 3 | BATTERY_FCC | mAh full-charge capacity |
| 4 | BATTERY_AI | mA average current (signed; psp2ctrl prints it as u32) |
| 5 | BATTERY_TTE | minutes to empty (GUI "Time remaining") |
| 6 | BATTERY_INTTEMP | 0.1 K |
| 7 | BATTERY_SOH | % |
| 8 | BATTERY_SOC | % (GUI battery meter) |

The GUI always asks for all nine ids in order (CMD 0x04 payload 0x34 = 12 + 4 + 9 x 4).

GET_POWER_STATUS is only sent when `target+0x784 > 0x1000300` (`FUN_14010d4f0`, else 0x800402f9).
That field is not set from the CPUP GET_INFO version words (mock set all of them to 1.0.4.0 and the
command still never appeared), and the GUI never requested it in any run. The voltage u32 encoding
(float bits vs mV) is therefore unverified; reply `result 0, count 0` if it ever comes.

## 3. What the GUI does (mock logs, `mock_pmep.py`)

* On open: 0x04 and 0x0C. With valid replies the left panel shows SOC % and "Time remaining" (TTE);
  with a failing 0x04 it shows "Target powered off" (the error the retail plugin produced).
* Start monitor: 0x00 once, then 0x02, 0x04 and 0x0C every sample interval (500 ms).
* Virtual AC: 0x08 with body `01000000`, then 0x0D must report 1 and the meter shows a plug.
* "Peak power/current" and the right-hand watt meter stayed 0 in every run (probably fed by the
  voltage notification that is never requested).
* One run logged `Target not ready (no protocol)` (0x8004029a) 0.35 s after launch while the mock
  session was blocked in FSD (proto 0x12000) requests. That error comes from psp2tm's DCMP NOPROTO
  handling for 0x12000 (`FUN_14012c0c0`), not from PMEP. It did not recur.

Why the retail plugin failed: it answered 0x0C with a 4-byte body (RES 0x0D needs 8) ->
`GetACStatus TMAPI_COMMS_ERR_DECODE`; it answered 0x04 with `{volt, temp, remain}`, so the result
word was the voltage -> `GetBatteryValues TMAPI_COMMS_ERR_UNKNOWN`; and 0x00 got the same 12 bytes
(result = voltage), so no channels could be set up.

## 4. Retail Vita sources (SceShell user plugin, `psp2/power.h`, `libScePower_stub`)

| Wire value | Retail API | Conversion |
|---|---|---|
| TEMP, INTTEMP (0.1 K) | `scePowerGetBatteryTemp()` (header: degC x 100) | `t / 10 + 2732`; no separate internal temperature, reuse |
| VOLT | `scePowerGetBatteryVolt()` | mV as-is |
| RM | `scePowerGetBatteryRemainCapacity()` | mAh |
| FCC | `scePowerGetBatteryFullCapacity()` | mAh |
| AI | `scePowerGetBatteryElec()` (in the stub, not in the header; declare it) | signed mA as-is |
| TTE | `scePowerGetBatteryLifeTime()` | minutes, clamp < 0 to 0 |
| SOH | `scePowerGetBatterySOH()` | % |
| SOC | `scePowerGetBatteryLifePercent()` | % |
| AC plugged (0x0D) | `scePowerIsPowerOnline()` OR the Virtual AC flag from 0x08 | 0/1 |
| channel "Battery" (mA) | `abs(scePowerGetBatteryElec())` | clamp to 0xffff |
| channel "Temperature" (degC) | `scePowerGetBatteryTemp() / 100` | clamp >= 0 |
| SET_BATTERY_VALUES | no retail source (a DevKit battery emulator) | reply non-zero result |
| voltage (0x13) | `scePowerGetBatteryVolt()` if ever requested | reply count 0 until verified |

Device-side units of `scePowerGetBatteryTemp` and the sign of `scePowerGetBatteryElec` are from the
VitaSDK header/NID database, not yet checked on the console.
