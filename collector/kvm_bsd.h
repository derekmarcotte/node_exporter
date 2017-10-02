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

#include <stdlib.h>
#include <sys/types.h>
#include <kvm.h>

typedef struct proc_state {
	char *name;
	char *status;
} proc_state_t;

int _kvm_open(kvm_t **out);
int _kvm_close(kvm_t **kd);

int _kvm_swap_used_pages(kvm_t *kd, uint64_t *out);
int _kvm_get_procstats(kvm_t *kd, proc_state_t **out, int *nentries);
