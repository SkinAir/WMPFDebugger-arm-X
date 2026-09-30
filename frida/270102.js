/**
 * WMPFDebugger Frida Hook Script
 * WeChatAppEx Framework version: 4.1.15 (build 270102)
 * Architecture: arm64
 *
 * Key changes from 269629 (4.1.13):
 *   - StructOffset changed 1488 -> 1520 (+32). The scene pointer chain is still
 *     INLINED in OnLoadStart1 (no separate helper to NativeFunction):
 *       result+8 -> v4 -> v4+1520 -> q1 -> q1+16 -> q2 -> q2+456 == 1101
 *   - SceneOffset unchanged at 456.
 *   - NEW ANCHOR: the old `ws://localhost:9421` literal is GONE in 4.1.15
 *     (0 occurrences — the port is now assembled at runtime, and the
 *     `ws://127.0.0.1:` at 0xa27b32b belongs to XwebUseManager, not devtools).
 *     Use the RTTI signature string instead:
 *       "virtual void applet::AppletIndexContainer::OnLoadStart(bool, ...)"
 *     at 0xa2b56df — single xref straight into OnLoadStart2 (0x5775250).
 *   - OnLoadStart1 (scene)        -> 0x9356CC8
 *   - OnLoadStart2 (debug X1=1)   -> 0x5775170
 *   - CDPFilter                   -> 0x93534C4
 *   - ResourceCachePolicy         -> 0x5787A54
 *
 * Caller/callee: 0x5775170 (OnLoadStart2) BL 0x9356CC8 (OnLoadStart1) at
 * 0x5775428, matching the 4.1.13 OnLoadStart1-unique-caller relationship.
 */

const getMainModule = () => {
    return Process.findModuleByName("WeChatAppEx Framework");
}

const moduleBase = getMainModule().base;

console.log("[hook] WeChatAppEx Framework base:", moduleBase);
console.log("[hook] Version: 4.1.15 (build 270102)");

// Hook 1: SendToClientFilter — CDP message filter bypass
// sub_93534C4: LDR W8,[X0,#8] / CMP W8,#6 / B.EQ loc_9353668
Interceptor.attach(moduleBase.add(0x93534C4), {
    onEnter(args) {},
    onLeave(retval) {
        if (retval && !retval.isNull()) {
            const v8_2_address = retval.add(8);
            try {
                if (v8_2_address.readU32() == 6) {
                    v8_2_address.writeU32(0x0);
                }
            } catch (e) {
                // Ignore read errors
            }
        }
    }
});

// Hook 2: OnLoadStart1 — Modify scene value to 1101
// sub_9356CC8, inlined chain: [X0+8] -> +0x5F0(1520) -> +0x10 -> +0x1C8(456)
const allowedValues = [1005, 1007, 1008, 1012, 1027, 1035, 1053, 1074, 1145, 1168, 1178, 1256, 1260, 1302, 1308];

Interceptor.attach(moduleBase.add(0x9356CC8), {
    onEnter(args) {
        try {
            const a1 = args[0];
            const v4 = a1.add(8).readPointer();

            if (v4 && !v4.isNull()) {
                const q1 = v4.add(1520).readPointer();

                if (q1 && !q1.isNull()) {
                    const base16 = q1.add(16).readPointer();

                    if (base16 && !base16.isNull()) {
                        const scenePtr = base16.add(456);
                        const currentValue = scenePtr.readInt();

                        if (allowedValues.includes(currentValue)) {
                            scenePtr.writeInt(1101);
                            // 4.1.15 NEW GATE: head also requires *(base16+0x2d4)==1
                            // (relocated debug-enable flag; 4.1.13 read *(a1+0x29) instead).
                            base16.add(0x2d4).writeInt(1);
                        }
                    }
                }
            }
        } catch (error) {
            // Silently ignore errors
        }
    },
    onLeave(retval) {}
});

// Hook 3: OnLoadStart2 — Force enable debugging (X1=1) + rewrite scene
// sub_5775170 tail (0x57753E0..0x5775428) gates the call to OnLoadStart1:
//   if (!a2) return;
//   x8 = *(this+0x38); x9 = *(*(x8+1520)+16);   // base is this+0x38, NOT +8
//   if (x9 && *(x9+0x2D4)==1 && *(x9+456)==1101 && appid nonempty)
//       OnLoadStart1(*(x8+0x630), ...);
// The 1101 check happens HERE, so Hook 2 alone is never reached —
// the scene must be rewritten at OnLoadStart2 entry.
Interceptor.attach(moduleBase.add(0x5775170), {
    onEnter(args) {
        this.context.x1 = ptr(1);
        try {
            const x8 = args[0].add(0x38).readPointer();
            if (x8 && !x8.isNull()) {
                const q1 = x8.add(1520).readPointer();
                if (q1 && !q1.isNull()) {
                    const base16 = q1.add(16).readPointer();
                    if (base16 && !base16.isNull()) {
                        const scenePtr = base16.add(456);
                        const currentValue = scenePtr.readInt();
                        if (allowedValues.includes(currentValue)) {
                            scenePtr.writeInt(1101);
                            // 4.1.15: tail gate at 0x5775428 requires *(base16+0x2d4)==1
                            // before it BLs OnLoadStart1. probe4 showed this is always 0,
                            // which is why OnLoadStart1 was never reached. Open the gate.
                            base16.add(0x2d4).writeInt(1);
                        }
                    }
                }
            }
        } catch (error) {
            // Silently ignore errors
        }
    },
    onLeave(retval) {}
});

// Hook 4: WAPCAdapterAppIndex — Resource cache policy bypass
Interceptor.attach(moduleBase.add(0x5787A54), {
    onEnter(args) {},
    onLeave(retval) {
        retval.replace(0x0);
    }
});

console.log("[hook] All 4 hooks installed successfully!");
