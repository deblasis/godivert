package main

import (
	"context"
	"net"
	"time"

	"github.com/deblasis/godivert"
)

var cloudflareDNS = net.ParseIP("1.1.1.1")

func checkPacket(wd *godivert.WinDivertHandle, packetChan <-chan *godivert.Packet) {
	for packet := range packetChan {
		if !packet.DstIP().Equal(cloudflareDNS) {
			packet.Send(wd)
		}
	}
}

func main() {
	winDivert, err := godivert.NewWinDivertHandle("icmp")
	if err != nil {
		panic(err)
	}
	defer winDivert.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	packetChan, err := winDivert.Packets(ctx)
	if err != nil {
		panic(err)
	}

	go checkPacket(winDivert, packetChan)

	<-ctx.Done() // Wait for context to be done
}
