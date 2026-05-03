package multiagent

import (
	"context"
	"fmt"

	"cyberstrike-ai/internal/security"

	"github.com/cloudwego/eino/adk/filesystem"
	"github.com/cloudwego/eino/schema"
)

// einoStreamingShellWrap 包装 Eino filesystem 使用的 StreamingShell（cloudwego eino-ext local.Local）。
// 官方 execute 工具默认走 ExecuteStreaming 且不设 RunInBackendGround；末尾带 & 时子进程仍与管道相连，
// streamStdout 按行读取会在无换行输出时长时间阻塞（与 MCP 工具 exec 的独立实现不同）。
// 对「完全后台」命令自动开启 RunInBackendGround，与 local.runCmdInBackground 行为对齐。
type einoStreamingShellWrap struct {
	inner filesystem.StreamingShell
}

func (w *einoStreamingShellWrap) ExecuteStreaming(ctx context.Context, input *filesystem.ExecuteRequest) (*schema.StreamReader[*filesystem.ExecuteResponse], error) {
	if w.inner == nil {
		return nil, fmt.Errorf("einoStreamingShellWrap: inner shell is nil")
	}
	if input == nil {
		return w.inner.ExecuteStreaming(ctx, nil)
	}
	req := *input
	if security.IsBackgroundShellCommand(req.Command) && !req.RunInBackendGround {
		req.RunInBackendGround = true
	}
	return w.inner.ExecuteStreaming(ctx, &req)
}
