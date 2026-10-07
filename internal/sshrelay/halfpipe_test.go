package sshrelay

import (
	"io"
	"testing"
	"time"
)

func TestHalfPipePreservesResponseAfterWriteClose(t *testing.T) {
	client, server := newHalfPipePair()
	defer client.Close()
	defer server.Close()
	requestDone := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := io.ReadAll(server)
		requestDone <- struct {
			data []byte
			err  error
		}{data, err}
	}()
	if _, err := io.WriteString(client, "request"); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request := <-requestDone
	if request.err != nil || string(request.data) != "request" {
		t.Fatalf("server request=%q err=%v", request.data, request.err)
	}
	responseDone := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := io.ReadAll(client)
		responseDone <- struct {
			data []byte
			err  error
		}{data, err}
	}()
	if _, err := io.WriteString(server, "response"); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response := <-responseDone
	if response.err != nil || string(response.data) != "response" {
		t.Fatalf("client response=%q err=%v", response.data, response.err)
	}
}

func TestHalfPipeDeadlineInterruptsBlockedRead(t *testing.T) {
	client, server := newHalfPipePair()
	defer client.Close()
	defer server.Close()
	if err := client.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	if timeout, ok := err.(interface{ Timeout() bool }); !ok || !timeout.Timeout() {
		t.Fatalf("blocked read error=%v; want timeout", err)
	}
}
