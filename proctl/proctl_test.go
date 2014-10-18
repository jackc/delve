package proctl_test

import (
	"bytes"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/derekparker/delve/helper"
	"github.com/derekparker/delve/proctl"
)

func dataAtAddr(pid int, addr uint64) ([]byte, error) {
	data := make([]byte, 1)
	_, err := syscall.PtracePeekData(pid, uintptr(addr), data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func assertNoError(err error, t *testing.T, s string) {
	if err != nil {
		t.Fatal(s, ":", err)
	}
}

func currentPC(p *proctl.DebuggedProcess, t *testing.T) uint64 {
	pc, err := p.CurrentPC()
	if err != nil {
		t.Fatal(err)
	}

	return pc
}

func currentLineNumber(p *proctl.DebuggedProcess, t *testing.T) (string, int) {
	pc := currentPC(p, t)
	f, l, _ := p.GoSymTable.PCToLine(pc)

	return f, l
}

func TestAttachProcess(t *testing.T) {
	helper.WithTestProcess("../_fixtures/testprog", t, func(p *proctl.DebuggedProcess) {
		if !p.Status().Stopped() {
			t.Errorf("Process was not stopped correctly")
		}
	})
}

func TestStep(t *testing.T) {
	helper.WithTestProcess("../_fixtures/testprog", t, func(p *proctl.DebuggedProcess) {
		if p.Status().Exited() {
			t.Fatal("Process already exited")
		}

		regs := helper.GetRegisters(p, t)
		rip := regs.PC()

		err := p.Step()
		assertNoError(err, t, "Step()")

		regs = helper.GetRegisters(p, t)
		if rip >= regs.PC() {
			t.Errorf("Expected %#v to be greater than %#v", regs.PC(), rip)
		}
	})
}

func TestContinue(t *testing.T) {
	helper.WithTestProcess("../_fixtures/continuetestprog", t, func(p *proctl.DebuggedProcess) {
		if p.Status().Exited() {
			t.Fatal("Process already exited")
		}

		err := p.Continue()
		assertNoError(err, t, "Continue()")

		if p.Status().ExitStatus() != 0 {
			t.Fatal("Process did not exit successfully")
		}
	})
}

func TestBreakPoint(t *testing.T) {
	helper.WithTestProcess("../_fixtures/testprog", t, func(p *proctl.DebuggedProcess) {
		sleepytimefunc := p.GoSymTable.LookupFunc("main.sleepytime")
		sleepyaddr := sleepytimefunc.Entry

		bp, err := p.Break(uintptr(sleepyaddr))
		assertNoError(err, t, "Break()")

		breakpc := bp.Addr + 1
		err = p.Continue()
		assertNoError(err, t, "Continue()")

		regs := helper.GetRegisters(p, t)

		pc := regs.PC()
		if pc != breakpc {
			t.Fatalf("Break not respected:\nPC:%d\nFN:%d\n", pc, breakpc)
		}

		err = p.Step()
		assertNoError(err, t, "Step()")

		regs = helper.GetRegisters(p, t)

		pc = regs.PC()
		if pc == breakpc {
			t.Fatalf("Step not respected:\nPC:%d\nFN:%d\n", pc, breakpc)
		}
	})
}

func TestBreakPointInSeperateGoRoutine(t *testing.T) {
	helper.WithTestProcess("../_fixtures/testthreads", t, func(p *proctl.DebuggedProcess) {
		_, err := p.Break(0x400c19)
		if err != nil {
			t.Fatal(err)
		}

		err = p.Continue()
		if err != nil {
			t.Fatal(err)
		}

		pc, err := p.CurrentPC()
		if err != nil {
			t.Fatal(err)
		}

		f, l, _ := p.GoSymTable.PCToLine(pc)
		if f != "testthreads.go" && l != 10 {
			t.Fatal("Program did not hit breakpoint")
		}
	})
}

func TestBreakPointWithNonExistantFunction(t *testing.T) {
	helper.WithTestProcess("../_fixtures/testprog", t, func(p *proctl.DebuggedProcess) {
		_, err := p.Break(uintptr(0))
		if err == nil {
			t.Fatal("Should not be able to break at non existant function")
		}
	})
}

func TestClearBreakPoint(t *testing.T) {
	helper.WithTestProcess("../_fixtures/testprog", t, func(p *proctl.DebuggedProcess) {
		fn := p.GoSymTable.LookupFunc("main.sleepytime")
		bp, err := p.Break(uintptr(fn.Entry))
		assertNoError(err, t, "Break()")

		int3, err := dataAtAddr(p.Pid, bp.Addr)
		if err != nil {
			t.Fatal(err)
		}

		bp, err = p.Clear(fn.Entry)
		assertNoError(err, t, "Clear()")

		data, err := dataAtAddr(p.Pid, bp.Addr)
		if err != nil {
			t.Fatal(err)
		}

		if bytes.Equal(data, int3) {
			t.Fatalf("Breakpoint was not cleared data: %#v, int3: %#v", data, int3)
		}

		if len(p.BreakPoints()) != 0 {
			t.Fatal("Breakpoint not removed internally")
		}
	})
}

func TestNext(t *testing.T) {
	var (
		err            error
		executablePath = "../_fixtures/testnextprog"
	)

	testcases := []struct {
		begin, end int
	}{
		{19, 20},
		{20, 23},
		{23, 24},
		{24, 26},
		{26, 31},
		{31, 23},
		{23, 24},
		{24, 26},
		{26, 31},
		{31, 23},
		{23, 24},
		{24, 26},
		{26, 27},
		{27, 34},
		{34, 35},
		{35, 41},
		{41, 40},
		{40, 41},
	}

	fp, err := filepath.Abs("../_fixtures/testnextprog.go")
	if err != nil {
		t.Fatal(err)
	}

	helper.WithTestProcess(executablePath, t, func(p *proctl.DebuggedProcess) {
		pc, _, _ := p.GoSymTable.LineToPC(fp, testcases[0].begin)
		_, err := p.Break(uintptr(pc))
		assertNoError(err, t, "Break()")
		assertNoError(p.Continue(), t, "Continue()")

		for _, tc := range testcases {
			f, ln := currentLineNumber(p, t)
			if ln != tc.begin {
				t.Fatalf("Program not stopped at correct spot expected %d was %s:%d", tc.begin, f, ln)
			}

			assertNoError(p.Next(), t, "Next() returned an error")

			f, ln = currentLineNumber(p, t)
			if ln != tc.end {
				t.Fatalf("Program did not continue to correct next location expected %d was %s:%d", tc.end, f, ln)
			}
		}

		if len(p.BreakPoints()) != 1 {
			t.Fatal("Not all breakpoints were cleaned up")
		}
	})
}

func TestVariableEvaluation(t *testing.T) {
	executablePath := "../_fixtures/testvariables"

	fp, err := filepath.Abs(executablePath + ".go")
	if err != nil {
		t.Fatal(err)
	}

	testcases := []struct {
		name    string
		value   string
		varType string
	}{
		{"a1", "foo", "struct string"},
		{"a2", "6", "int"},
		{"a3", "7.23", "float64"},
		{"a4", "[2]int [1 2]", "[97]int"}, // There is a weird bug in the Go dwarf parser that is grabbing the wrong size for an array.
		{"a5", "len: 5 cap: 5 [1 2 3 4 5]", "struct []int"},
		{"a6", "main.FooBar {Baz: 8, Bur: word}", "main.FooBar"},
		{"a7", "*main.FooBar {Baz: 5, Bur: strum}", "*main.FooBar"},
		{"baz", "bazburzum", "struct string"},
	}

	helper.WithTestProcess(executablePath, t, func(p *proctl.DebuggedProcess) {
		pc, _, _ := p.GoSymTable.LineToPC(fp, 21)

		_, err := p.Break(uintptr(pc))
		assertNoError(err, t, "Break() returned an error")

		err = p.Continue()
		assertNoError(err, t, "Continue() returned an error")

		for _, tc := range testcases {
			variable, err := p.EvalSymbol(tc.name)
			assertNoError(err, t, "Variable() returned an error")

			if variable.Name != tc.name {
				t.Fatalf("Expected %s got %s\n", tc.name, variable.Name)
			}

			if variable.Type != tc.varType {
				t.Fatalf("Expected %s got %s\n", tc.varType, variable.Type)
			}

			if variable.Value != tc.value {
				t.Fatalf("Expected %#v got %#v\n", tc.value, variable.Value)
			}
		}
	})
}
