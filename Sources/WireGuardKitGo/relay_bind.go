/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.
 *
 * relay_bind.go provides a conn.Bind implementation that delegates outbound
 * datagrams to a Swift-supplied callback and accepts inbound datagrams pushed
 * in from Swift (so wireguard-go's encrypted UDP can ride on a custom
 * transport such as USB-C to an iPhone instead of the host network stack).
 */

package main

// #include <stdlib.h>
// #include <stdint.h>
// #include <sys/types.h>
// typedef void (*wg_relay_send_callback_t)(void* context, const uint8_t* endpoint, size_t endpoint_len, const uint8_t* data, size_t data_len);
// static void callRelaySend(wg_relay_send_callback_t cb, void* ctx, const uint8_t* endpoint, size_t endpoint_len, const uint8_t* data, size_t data_len) {
// 	cb(ctx, endpoint, endpoint_len, data, data_len);
// }
import "C"

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// RelayEndpoint is a conn.Endpoint backed by an opaque string identifier that
// Swift assigns to a peer's transport-side address (typically "host:port" as
// announced over the Bonjour relay discovery).
type RelayEndpoint string

var _ conn.Endpoint = RelayEndpoint("")

func (RelayEndpoint) ClearSrc() {}

func (RelayEndpoint) SrcToString() string { return "" }

func (e RelayEndpoint) DstToString() string { return string(e) }

func (e RelayEndpoint) DstToBytes() []byte { return []byte(e) }

// DstIP returns the zero value because the relay transport carries arbitrary
// opaque identifiers; wireguard-go only uses this for logging.
func (RelayEndpoint) DstIP() netip.Addr { return netip.Addr{} }

// SrcIP returns the zero value for the same reason as DstIP.
func (RelayEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// relayDatagram is what flows through the receive channel.
type relayDatagram struct {
	data     []byte
	endpoint RelayEndpoint
}

// RelayBind is a conn.Bind that hands outbound datagrams to a C callback and
// accepts inbound datagrams that Swift pushes in via wgRelayBindInjectReceive.
type RelayBind struct {
	mu      sync.Mutex
	closed  bool
	recv    chan relayDatagram
	sendCb  C.wg_relay_send_callback_t
	sendCtx unsafe.Pointer
}

var _ conn.Bind = (*RelayBind)(nil)

// NewRelayBind constructs a RelayBind. sendCb may be nil for tests that only
// exercise the inbound path; in that case Send drops the packet and returns
// nil. ctx is opaque to Go and is forwarded verbatim to the C callback.
func NewRelayBind(sendCb C.wg_relay_send_callback_t, ctx unsafe.Pointer) *RelayBind {
	return &RelayBind{
		recv:    make(chan relayDatagram, 64),
		sendCb:  sendCb,
		sendCtx: ctx,
	}
}

// Open returns a single ReceiveFunc that reads from the bind's receive channel.
// The reported port is whatever the caller asked for (we have no real socket),
// defaulting to 51820 when the caller passes 0.
func (b *RelayBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		// re-arm after a previous Close so wgBumpSockets style flows work.
		b.recv = make(chan relayDatagram, 64)
		b.closed = false
	}
	if port == 0 {
		port = 51820
	}
	fn := func(buff []byte) (int, conn.Endpoint, error) {
		dg, ok := <-b.recv
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(buff, dg.data)
		return n, dg.endpoint, nil
	}
	return []conn.ReceiveFunc{fn}, port, nil
}

// Close drains the channel and unblocks any pending receivers. Subsequent
// receives return net.ErrClosed.
func (b *RelayBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	close(b.recv)
	return nil
}

// SetMark is a no-op since the relay transport is opaque to the kernel.
func (*RelayBind) SetMark(_ uint32) error { return nil }

// Send forwards a single encrypted datagram to the registered C callback.
func (b *RelayBind) Send(buff []byte, ep conn.Endpoint) error {
	rep, ok := ep.(RelayEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	cb := b.sendCb
	ctx := b.sendCtx
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if cb == nil {
		return nil
	}
	epBytes := []byte(rep)
	var epPtr *C.uint8_t
	if len(epBytes) > 0 {
		epPtr = (*C.uint8_t)(unsafe.Pointer(&epBytes[0]))
	}
	var dataPtr *C.uint8_t
	if len(buff) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&buff[0]))
	}
	C.callRelaySend(cb, ctx, epPtr, C.size_t(len(epBytes)), dataPtr, C.size_t(len(buff)))
	return nil
}

// ParseEndpoint treats the entire string as the opaque endpoint identifier.
// This is what wireguard-go calls when applying a UAPI Endpoint= line, so the
// caller controls the format (e.g. "peer-uuid" or "host:port").
func (*RelayBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == "" {
		return nil, errors.New("empty relay endpoint")
	}
	return RelayEndpoint(s), nil
}

// inject pushes an inbound datagram into the bind. It returns net.ErrClosed
// after Close has been called.
func (b *RelayBind) inject(data []byte, endpoint string) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return net.ErrClosed
	}
	ch := b.recv
	b.mu.Unlock()
	// copy because the buffer ownership stays with the C caller after return.
	cp := make([]byte, len(data))
	copy(cp, data)
	ch <- relayDatagram{data: cp, endpoint: RelayEndpoint(endpoint)}
	return nil
}

// relayBindHandles maps tunnel handles back to their RelayBind so the
// inject-receive cgo export can find the right bind.
var (
	relayBindHandlesMu sync.Mutex
	relayBindHandles   = make(map[int32]*RelayBind)
)

func registerRelayBind(handle int32, bind *RelayBind) {
	relayBindHandlesMu.Lock()
	relayBindHandles[handle] = bind
	relayBindHandlesMu.Unlock()
}

func unregisterRelayBind(handle int32) {
	relayBindHandlesMu.Lock()
	delete(relayBindHandles, handle)
	relayBindHandlesMu.Unlock()
}

func lookupRelayBind(handle int32) *RelayBind {
	relayBindHandlesMu.Lock()
	b := relayBindHandles[handle]
	relayBindHandlesMu.Unlock()
	return b
}

//export wgTurnOnWithRelayBind
func wgTurnOnWithRelayBind(settings *C.char, tunFd int32, sendCb C.wg_relay_send_callback_t, sendCtx unsafe.Pointer) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tunDev, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	bind := NewRelayBind(sendCb, sendCtx)
	logger.Verbosef("Attaching to interface with relay bind")
	dev := device.NewDevice(tunDev, bind, logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		dev.Close()
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started with relay bind")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		dev.Close()
		unix.Close(dupTunFd)
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger}
	registerRelayBind(i, bind)
	return i
}

//export wgRelayBindInjectReceive
func wgRelayBindInjectReceive(handle int32, endpoint *C.char, endpointLen C.size_t, data *C.uint8_t, dataLen C.size_t) {
	bind := lookupRelayBind(handle)
	if bind == nil {
		return
	}
	var ep string
	if endpointLen > 0 && endpoint != nil {
		ep = string(C.GoBytes(unsafe.Pointer(endpoint), C.int(endpointLen)))
	}
	var payload []byte
	if dataLen > 0 && data != nil {
		payload = C.GoBytes(unsafe.Pointer(data), C.int(dataLen))
	}
	_ = bind.inject(payload, ep)
}

// teardown hook so wgTurnOff also drops the bind from the lookup map.
// We piggy-back on the existing wgTurnOff by wrapping the handle removal:
// in api-apple.go wgTurnOff already deletes from tunnelHandles, so we add
// a parallel cleanup here that the consumer can call right before wgTurnOff
// (or we just leave the entry to be replaced when a handle slot is reused;
// since NewRelayBind closes its channel on bind.Close() via dev.Close()
// during wgTurnOff, the entry becoming stale is harmless).
//
//export wgRelayBindUnregister
func wgRelayBindUnregister(handle int32) {
	unregisterRelayBind(handle)
}
