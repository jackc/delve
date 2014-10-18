package main

import (
	"fmt"
	"runtime"
	"sync"
)

func anotherthread(wg *sync.WaitGroup) {
	fmt.Println("setbreakpoint")
	wg.Done()
}

func main() {
	runtime.LockOSThread()
	var wg sync.WaitGroup
	wg.Add(1)
	go anotherthread(&wg)
	wg.Wait()
}
