package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	for i := 0; i < 2000; i++ {
		r, w, err := os.Pipe()
		if err != nil {
			panic(err)
		}
		finished := make(chan error, 1)
		go func() {
			time.Sleep(time.Millisecond)
			_, err := w.Write([]byte{1})
			if closeErr := w.Close(); err == nil {
				err = closeErr
			}
			finished <- err
		}()
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			panic(err)
		}
		if err := r.Close(); err != nil {
			panic(err)
		}
		if err := <-finished; err != nil {
			panic(err)
		}
	}
	fmt.Println("stdlib pipe/timer netpoll PASS")
}
