package main

import (
	"errors"
	"testing"
)

type exitPanic struct {
	code int
}

func (panicValue exitPanic) Error() string {
	return "exit"
}

func TestMainExitsOnCommandError(t *testing.T) {
	originalExecute := executeRootCommand
	originalExit := exitProcess
	defer func() {
		executeRootCommand = originalExecute
		exitProcess = originalExit
	}()

	executeRootCommand = func() error {
		return errors.New("execute.failed")
	}

	exitCode := 0
	exitProcess = func(code int) {
		exitCode = code
		panic(exitPanic{code: code})
	}

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("expected exit to be triggered")
		}
		panicValue, ok := recovered.(exitPanic)
		if !ok {
			t.Fatalf("unexpected panic: %T", recovered)
		}
		if panicValue.code != 1 || exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}
	}()

	main()
}

func TestMainReturnsWhenCommandSucceeds(t *testing.T) {
	originalExecute := executeRootCommand
	originalExit := exitProcess
	defer func() {
		executeRootCommand = originalExecute
		exitProcess = originalExit
	}()

	executeRootCommand = func() error {
		return nil
	}

	exitCalled := false
	exitProcess = func(code int) {
		exitCalled = true
		panic(exitPanic{code: code})
	}

	main()

	if exitCalled {
		t.Fatalf("expected exit not to be called")
	}
}
