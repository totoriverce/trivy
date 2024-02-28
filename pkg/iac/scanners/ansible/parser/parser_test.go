package parser

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProject(t *testing.T) {
	fsys := os.DirFS(filepath.Join("testdata", "sample-proj"))

	project, err := New(fsys, ".").Parse()
	require.NoError(t, err)

	tasks := project.ListTasks()
	assert.Len(t, tasks, 4)
}

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name          string
		fsys          fs.FS
		expectedTasks []string
	}{
		{
			name: "tasks in play",
			fsys: fstest.MapFS{
				"playbook.yaml": {
					Data: []byte(`---
- hosts: localhost
  pre_tasks:
    - name: Pre-task
      debug:
        msg: test
  tasks:
    - name: Task
      debug:
        msg: test
  post_tasks:
    - name: Post-task
      debug:
        msg: test
`),
				},
			},
			expectedTasks: []string{"Pre-task", "Task", "Post-task"},
		},
		{
			name: "tasks in role",
			fsys: fstest.MapFS{
				"playbook.yaml": {
					Data: []byte(`---
- hosts: localhost
  roles:
    - test
`),
				},
				"roles/test/tasks/main.yaml": {
					Data: []byte(`---
- name: Test task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Test task"},
		},
		{
			name: "role with dependencies",
			fsys: fstest.MapFS{
				"playbook.yaml": {
					Data: []byte(`---
- hosts: localhost
  roles:
    - test
`),
				},
				"roles/test/tasks/main.yaml": {
					Data: []byte(`---
- name: Role task
  debug:
    msg: Test task
`),
				},
				"roles/test/meta/main.yaml": {
					Data: []byte(`---
dependencies:
  - role: role2
`),
				},
				"roles/role2/tasks/main.yaml": {
					Data: []byte(`---
- name: Dependent task
  debug:
    msg: Test task
`),
				},
			},
			expectedTasks: []string{"Dependent task", "Role task"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project, err := New(tt.fsys, ".").Parse()
			require.NoError(t, err)

			tasks := project.ListTasks()

			taskNames := lo.Map(tasks, func(task *Task, _ int) string {
				return task.name()
			})
			assert.Equal(t, tt.expectedTasks, taskNames)
		})
	}
}
