// Copyright 2017 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !nomeminfo
// +build freebsd dragonfly

package collector

import (
	"fmt"
	"sync"
	"unsafe"
)

// #cgo LDFLAGS: -lkvm
// #include "kvm_bsd.h"
import "C"

type processStatus struct {
	name   string
	status string
}

/** kvm is the driver to interface with BSD kvm system calls to build metrics from. */
type kvm struct {
	mu      sync.Mutex
	isValid bool
	d       *C.struct___kvm
}

func NewKvm() kvm {
	var k kvm

	if C._kvm_open(&k.d) == 0 {
		k.isValid = true
	}

	return k
}

func (k *kvm) SwapUsedPages() (value uint64, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.isValid {
		return 0, fmt.Errorf("couldn't get kvm swap used pages")
	}

	if C._kvm_swap_used_pages(k.d, (*C.uint64_t)(&value)) != 0 {
		k.error()
		return 0, fmt.Errorf("couldn't get kvm swap used pages")
	}

	return value, nil
}

func (k *kvm) ProcessStatusCounts() (out map[processStatus]int, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.isValid {
		return nil, fmt.Errorf("couldn't get kvm process count")
	}

	var stateList *C.struct_proc_state = nil
	var stateListCount C.int

	ret := C._kvm_get_procstats(k.d, &stateList, &stateListCount)
	if stateList != nil {
		defer C.free(unsafe.Pointer(stateList))
	}
	if ret != 0 {
		k.error()
		return nil, fmt.Errorf("couldn't get kvm process count")
	}

	out = make(map[processStatus]int)

	start := uintptr(unsafe.Pointer(stateList))
	for i := uintptr(0); i < uintptr(stateListCount); i++ {
		processState := (*C.struct_proc_state)(unsafe.Pointer(start + (i * C.sizeof_struct_proc_state)))
		out[processStatus{
			name:   C.GoString(processState.name),
			status: C.GoString(processState.status),
		}]++
	}

	return out, nil
}

func (k *kvm) error() {
	// Called only from within a mutex.
	C._kvm_close(&k.d)
	k.isValid = false
}
