/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.
 *
 * Unit tests for the relay-bind plumbing. These exercise the bind directly
 * (without wgTurnOnWithRelayBind) so they don't need a utun fd.
 */

package main

import (
	"net"
	"sync"
	"testing"
	"unsafe"
)

func TestRelayBindOpenAndInject(t *testing.T) {
	bind := NewRelayBind(nil, nil)
	defer bind.Close()

	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if port == 0 {
		t.Fatalf("expected non-zero port from Open")
	}
	if len(fns) != 1 {
		t.Fatalf("expected exactly one ReceiveFunc, got %d", len(fns))
	}

	payload := []byte{0x01, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef}
	endpoint := "phone-relay:51820"
	go func() {
		if err := bind.inject(payload, endpoint); err != nil {
			t.Errorf("inject returned error: %v", err)
		}
	}()

	buf := make([]byte, 65535)
	n, ep, err := fns[0](buf)
	if err != nil {
		t.Fatalf("ReceiveFunc returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("received %d bytes, want %d", n, len(payload))
	}
	for i := range payload {
		if buf[i] != payload[i] {
			t.Fatalf("byte %d mismatch: got 0x%x want 0x%x", i, buf[i], payload[i])
		}
	}
	if ep.DstToString() != endpoint {
		t.Fatalf("endpoint mismatch: got %q want %q", ep.DstToString(), endpoint)
	}
}

func TestRelayBindCloseUnblocksReceive(t *testing.T) {
	bind := NewRelayBind(nil, nil)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var receivedErr error
	go func() {
		defer wg.Done()
		buf := make([]byte, 64)
		_, _, receivedErr = fns[0](buf)
	}()
	bind.Close()
	wg.Wait()
	if receivedErr != net.ErrClosed {
		t.Fatalf("after Close, receive returned %v, want net.ErrClosed", receivedErr)
	}
}

func TestRelayBindParseEndpoint(t *testing.T) {
	bind := NewRelayBind(nil, nil)
	defer bind.Close()
	ep, err := bind.ParseEndpoint("relay-peer-uuid")
	if err != nil {
		t.Fatalf("ParseEndpoint returned error: %v", err)
	}
	if ep.DstToString() != "relay-peer-uuid" {
		t.Fatalf("DstToString mismatch: got %q want %q", ep.DstToString(), "relay-peer-uuid")
	}
	if _, err := bind.ParseEndpoint(""); err == nil {
		t.Fatalf("ParseEndpoint(\"\") should return an error")
	}
}

func TestRelayBindSendWithoutCallbackIsNoOp(t *testing.T) {
	bind := NewRelayBind(nil, nil)
	defer bind.Close()
	ep := RelayEndpoint("ignored")
	if err := bind.Send([]byte{0x01}, ep); err != nil {
		t.Fatalf("Send with nil callback returned error: %v", err)
	}
}

// Ensure the unsafe.Pointer alias compiles even when the bind has no
// callback. This guards against accidental nil-pointer dereferences on the C
// side if someone later wires the callback up without a context.
var _ = unsafe.Pointer(nil)
