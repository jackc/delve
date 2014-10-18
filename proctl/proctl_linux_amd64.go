// Package proctl provides functions for attaching to and manipulating
// a process during the debug session.
package proctl

import (
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/derekparker/delve/dwarf/frame"
	"github.com/derekparker/delve/vendor/elf"
)

// Struct representing a debugged process. Holds onto pid, register values,
// process struct and process state.
type DebuggedProcess struct {
	Pid           int
	Process       *os.Process
	Executable    *elf.File
	Symbols       []elf.Symbol
	GoSymTable    *gosym.Table
	FrameEntries  *frame.FrameDescriptionEntries
	Threads       []*ThreadContext
	CurrentThread *ThreadContext
}

// Returns a new DebuggedProcess struct with sensible defaults.
func NewDebugProcess(pid int) (*DebuggedProcess, error) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}

	debuggedProc := DebuggedProcess{
		Pid:     pid,
		Process: proc,
	}

	for _, tid := range threadIds(pid) {
		err = syscall.PtraceAttach(tid)
		if err != nil {
			return nil, err
		}

		ps, err := wait(tid)
		if err != nil {
			return nil, err
		}

		tctxt := &ThreadContext{
			Id:          tid,
			Process:     &debuggedProc,
			Regs:        new(syscall.PtraceRegs),
			BreakPoints: make(map[uint64]*BreakPoint),
			Status:      ps,
		}

		if tid == pid {
			debuggedProc.CurrentThread = tctxt
		}

		debuggedProc.Threads = append(debuggedProc.Threads, tctxt)
	}

	err = debuggedProc.LoadInformation()
	if err != nil {
		return nil, err
	}

	return &debuggedProc, nil
}

// Returns the status of the current main thread context.
func (dbp *DebuggedProcess) Status() *syscall.WaitStatus {
	return dbp.CurrentThread.Status
}

// Returns the breakpoints of the current main thread context.
func (dbp *DebuggedProcess) BreakPoints() map[uint64]*BreakPoint {
	return dbp.CurrentThread.BreakPoints
}

// Finds the executable from /proc/<pid>/exe and then
// uses that to parse the following information:
// * Dwarf .debug_frame section
// * Dwarf .debug_line section
// * Go symbol table.
func (dbp *DebuggedProcess) LoadInformation() error {
	var (
		wg  sync.WaitGroup
		err error
	)

	err = dbp.findExecutable()
	if err != nil {
		return err
	}

	wg.Add(2)
	go dbp.parseDebugFrame(&wg)
	go dbp.obtainGoSymbols(&wg)

	wg.Wait()

	return nil
}

// Steps through process.
func (dbp *DebuggedProcess) Step() (err error) {
	return dbp.CurrentThread.Step()
}

// Step over function calls.
func (dbp *DebuggedProcess) Next() error {
	return dbp.CurrentThread.Next()
}

// Continue process until next breakpoint.
func (dbp *DebuggedProcess) Continue() error {
	return dbp.CurrentThread.Continue()
}

// Obtains register values from the debugged process.
func (dbp *DebuggedProcess) Registers() (*syscall.PtraceRegs, error) {
	return dbp.CurrentThread.Registers()
}

type InvalidAddressError struct {
	address uintptr
}

func (iae InvalidAddressError) Error() string {
	return fmt.Sprintf("Invalid address %#v\n", iae.address)
}

// Sets a breakpoint in the running process.
func (dbp *DebuggedProcess) Break(addr uintptr) (*BreakPoint, error) {
	return dbp.CurrentThread.Break(addr)
}

// Clears a breakpoint.
func (dbp *DebuggedProcess) Clear(pc uint64) (*BreakPoint, error) {
	return dbp.CurrentThread.Clear(pc)
}

func (dbp *DebuggedProcess) CurrentPC() (uint64, error) {
	return dbp.CurrentThread.CurrentPC()
}

// Returns the value of the named symbol.
func (dbp *DebuggedProcess) EvalSymbol(name string) (*Variable, error) {
	return dbp.CurrentThread.EvalSymbol(name)
}

func (dbp *DebuggedProcess) findExecutable() error {
	procpath := fmt.Sprintf("/proc/%d/exe", dbp.Pid)

	f, err := os.OpenFile(procpath, 0, os.ModePerm)
	if err != nil {
		return err
	}

	elffile, err := elf.NewFile(f)
	if err != nil {
		return err
	}

	dbp.Executable = elffile

	return nil
}

func (dbp *DebuggedProcess) parseDebugFrame(wg *sync.WaitGroup) {
	defer wg.Done()

	debugFrame, err := dbp.Executable.Section(".debug_frame").Data()
	if err != nil {
		fmt.Println("could not get .debug_frame section", err)
		os.Exit(1)
	}

	dbp.FrameEntries = frame.Parse(debugFrame)
}

func (dbp *DebuggedProcess) obtainGoSymbols(wg *sync.WaitGroup) {
	defer wg.Done()

	var (
		symdat  []byte
		pclndat []byte
		err     error
	)

	if sec := dbp.Executable.Section(".gosymtab"); sec != nil {
		symdat, err = sec.Data()
		if err != nil {
			fmt.Println("could not get .gosymtab section", err)
			os.Exit(1)
		}
	}

	if sec := dbp.Executable.Section(".gopclntab"); sec != nil {
		pclndat, err = sec.Data()
		if err != nil {
			fmt.Println("could not get .gopclntab section", err)
			os.Exit(1)
		}
	}

	pcln := gosym.NewLineTable(pclndat, dbp.Executable.Section(".text").Addr)
	tab, err := gosym.NewTable(symdat, pcln)
	if err != nil {
		fmt.Println("could not get initialize line table", err)
		os.Exit(1)
	}

	dbp.GoSymTable = tab
}

// Takes an offset from RSP and returns the address of the
// instruction the currect function is going to return to.
func (dbp *DebuggedProcess) ReturnAddressFromOffset(offset int64) uint64 {
	regs, err := dbp.Registers()
	if err != nil {
		panic("Could not obtain register values")
	}

	retaddr := int64(regs.Rsp) + offset
	data := make([]byte, 8)
	syscall.PtracePeekText(dbp.Pid, uintptr(retaddr), data)
	return binary.LittleEndian.Uint64(data)
}

func wait(pid int) (*syscall.WaitStatus, error) {
	var status syscall.WaitStatus
	var rusage syscall.Rusage

	_, e := syscall.Wait4(pid, &status, 0, &rusage)
	if e != nil {
		return nil, e
	}

	return &status, nil
}
