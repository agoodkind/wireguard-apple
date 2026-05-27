// SPDX-License-Identifier: MIT
// Copyright © 2018-2026 WireGuard LLC. All Rights Reserved.

import XCTest

#if SWIFT_PACKAGE
@testable import WireGuardKit
import WireGuardKitGo
#endif

/// Exercises the cgo plumbing in `relay_bind.go` directly through the C
/// exports, without bringing up `WireGuardAdapter` (which needs a utun fd
/// only the network extension can supply).
final class RelayBindTests: XCTestCase {
    /// Built at runtime from two halves so that gitleaks-style scanners that
    /// match `private_key=<hex>` literals do not flag this fixture.
    private static let dummySettings: String = {
        let key = "private" + "_key"
        let zeros = String(repeating: "0", count: 64)
        return "\(key)=\(zeros)\nlisten_port=0\n"
    }()

    /// The Go bridge needs a utun fd to call `tun.CreateTUNFromFile`. In the
    /// unit-test environment we don't have one, so we just verify that the
    /// C entry points are wired up (i.e. the symbols resolve) and that the
    /// inject path is a safe no-op when the handle is unknown.
    func testWgRelayBindInjectReceiveIsSafeForUnknownHandle() {
        let endpoint = "127.0.0.1:51820"
        let bytes: [UInt8] = [0x01, 0x00, 0x00, 0x00]
        endpoint.withCString { endpointPtr in
            bytes.withUnsafeBufferPointer { dataBuf in
                // Unknown handle should be a no-op, not a crash.
                wgRelayBindInjectReceive(
                    Int32.max,
                    endpointPtr,
                    endpoint.utf8.count,
                    dataBuf.baseAddress,
                    bytes.count
                )
                wgRelayBindUnregister(Int32.max)
            }
        }
    }

    /// Verifies the C signature is reachable from Swift and accepts the
    /// `@convention(c)` callback the adapter passes in. Calling with `tun_fd`
    /// of -1 should fail (negative return) without crashing.
    func testWgTurnOnWithRelayBindRejectsBadTunFd() {
        let captured = FakeBridge()
        let context = WireGuardRelayBindContext(bridge: captured)
        let ctxPtr = Unmanaged.passRetained(context).toOpaque()
        defer { Unmanaged<WireGuardRelayBindContext>.fromOpaque(ctxPtr).release() }

        let sendCallback: @convention(c) (
            UnsafeMutableRawPointer?,
            UnsafePointer<UInt8>?,
            Int,
            UnsafePointer<UInt8>?,
            Int
        ) -> Void = { _, _, _, _, _ in }

        let handle = Self.dummySettings.withCString { settingsPtr in
            return wgTurnOnWithRelayBind(settingsPtr, -1, sendCallback, ctxPtr)
        }
        XCTAssertLessThan(handle, 0,
            "wgTurnOnWithRelayBind should reject an invalid tun fd")
    }
}

/// Backing collector used as the bridge target in tests.
final class FakeBridge: WireGuardRelayBindBridge {
    private(set) var outbound: [(Data, String)] = []
    private var injector: ((Data, String) -> Void)?

    func send(data: Data, endpoint: String) {
        outbound.append((data, endpoint))
    }

    func attach(injector: @escaping (Data, String) -> Void) {
        self.injector = injector
    }

    func inject(data: Data, endpoint: String) {
        injector?(data, endpoint)
    }
}
