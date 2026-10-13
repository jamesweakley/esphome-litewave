#!/usr/bin/env python3
"""
Broad BLE scan - show ALL nearby BLE devices with names and manufacturer data.
Helps identify the Sense+ switch BLE advertisement.
"""

import asyncio
import objc
from Foundation import NSObject
import CoreBluetooth as CB


class ScanDelegate(NSObject):
    def init(self):
        self = objc.super(ScanDelegate, self).init()
        self.seen = {}
        return self

    def centralManagerDidUpdateState_(self, central):
        if central.state() == 5:
            # Scan with duplicates to see RSSI updates
            central.scanForPeripheralsWithServices_options_(
                None, {CB.CBCentralManagerScanOptionAllowDuplicatesKey: False}
            )

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
        self, central, peripheral, adv, rssi
    ):
        uuid = str(peripheral.identifier())
        if uuid in self.seen:
            return
        self.seen[uuid] = True

        name = str(peripheral.name()) if peripheral.name() else "(unnamed)"
        rssi_val = int(rssi) if rssi else "?"

        mfg_data = adv.get("kCBAdvDataManufacturerData") if adv else None
        mfg_hex = bytes(mfg_data).hex() if mfg_data else ""

        svc_uuids = adv.get("kCBAdvDataServiceUUIDs") if adv else None
        svc_list = []
        if svc_uuids:
            for s in svc_uuids:
                svc_list.append(str(s))

        connectable = adv.get("kCBAdvDataIsConnectable") if adv else None

        parts = [f"{name:30s} RSSI={rssi_val:4d}"]
        if mfg_hex:
            parts.append(f"mfg={mfg_hex}")
        if svc_list:
            parts.append(f"svcs={','.join(svc_list)}")
        if connectable is not None:
            parts.append(f"conn={'Y' if connectable else 'N'}")

        print("  ".join(parts))


async def main():
    delegate = ScanDelegate.alloc().init()
    central = CB.CBCentralManager.alloc().initWithDelegate_queue_(delegate, None)

    print("Scanning ALL BLE devices for 15 seconds...")
    print("(Press Sense+ button to trigger advertisement if needed)\n")
    await asyncio.sleep(15)
    central.stopScan()
    print(f"\nTotal: {len(delegate.seen)} devices found")


asyncio.run(main())
