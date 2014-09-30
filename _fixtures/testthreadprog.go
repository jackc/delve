package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

func gofunc(wg *sync.WaitGroup) {
	runtime.LockOSThread()
	time.Sleep(time.Second)
	fmt.Println(500)
	wg.Done()
}

func main() {
	runtime.LockOSThread()
	wg := new(sync.WaitGroup)

	wg.Add(1)
	go gofunc(wg)
	wg.Wait()
}
