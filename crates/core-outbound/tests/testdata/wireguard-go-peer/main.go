package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type channelTUN struct {
	incoming chan []byte
	outgoing chan []byte
	events   chan tun.Event
	closed   chan struct{}
	once     sync.Once
}

func newChannelTUN() *channelTUN {
	t := &channelTUN{
		incoming: make(chan []byte, 8),
		outgoing: make(chan []byte, 8),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

func (t *channelTUN) File() *os.File           { return nil }
func (t *channelTUN) MTU() (int, error)        { return 1420, nil }
func (t *channelTUN) Name() (string, error)    { return "rp-kernel-channel-tun", nil }
func (t *channelTUN) Events() <-chan tun.Event { return t.events }
func (t *channelTUN) BatchSize() int           { return 1 }

func (t *channelTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case packet := <-t.incoming:
		if len(bufs) == 0 || len(sizes) == 0 || offset+len(packet) > len(bufs[0]) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}

func (t *channelTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buffer := range bufs {
		if offset > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		packet := append([]byte(nil), buffer[offset:]...)
		select {
		case <-t.closed:
			return 0, os.ErrClosed
		case t.outgoing <- packet:
		}
	}
	return len(bufs), nil
}

func (t *channelTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

func makePacket(source, destination [4]byte, marker byte) []byte {
	packet := make([]byte, 21)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = byte(len(packet))
	packet[8] = 64
	packet[9] = 253
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	packet[20] = marker
	return packet
}

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: peer endpoint private-key-hex server-public-key-hex marker")
		os.Exit(2)
	}
	privateKey, err := hex.DecodeString(os.Args[2])
	if err != nil || len(privateKey) != 32 {
		fmt.Fprintln(os.Stderr, "invalid private key")
		os.Exit(2)
	}
	serverPublic, err := hex.DecodeString(os.Args[3])
	if err != nil || len(serverPublic) != 32 {
		fmt.Fprintln(os.Stderr, "invalid server public key")
		os.Exit(2)
	}
	marker, err := hex.DecodeString(os.Args[4])
	if err != nil || len(marker) != 1 {
		fmt.Fprintln(os.Stderr, "invalid marker")
		os.Exit(2)
	}

	tunDevice := newChannelTUN()
	logger := device.NewLogger(device.LogLevelError, "wireguard-go-interop: ")
	wg := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	defer wg.Close()
	config := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\npublic_key=%s\nendpoint=%s\nallowed_ip=10.88.0.1/32\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(privateKey), hex.EncodeToString(serverPublic), os.Args[1],
	)
	if err := wg.IpcSet(config); err != nil {
		fmt.Fprintln(os.Stderr, "IpcSet:", err)
		os.Exit(1)
	}
	request := makePacket([4]byte{10, 88, 0, 2}, [4]byte{10, 88, 0, 1}, marker[0])
	select {
	case tunDevice.incoming <- request:
	case <-time.After(3 * time.Second):
		fmt.Fprintln(os.Stderr, "inject timeout")
		os.Exit(1)
	}
	expected := makePacket([4]byte{10, 88, 0, 1}, [4]byte{10, 88, 0, 2}, marker[0])
	select {
	case response := <-tunDevice.outgoing:
		if !bytes.Equal(response, expected) {
			fmt.Fprintf(os.Stderr, "unexpected response: %x\n", response)
			os.Exit(1)
		}
		fmt.Println("wireguard-go interop ok")
	case <-time.After(8 * time.Second):
		fmt.Fprintln(os.Stderr, errors.New("decrypted response timeout"))
		os.Exit(1)
	}
}
