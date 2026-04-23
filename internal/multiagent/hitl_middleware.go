package multiagent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
)

type hitlInterceptorKey struct{}

type HITLToolInterceptor func(ctx context.Context, toolName, arguments string) (string, error)

type humanRejectError struct {
	reason string
}

func (e *humanRejectError) Error() string {
	if strings.TrimSpace(e.reason) == "" {
		return "rejected by user"
	}
	return "rejected by user: " + strings.TrimSpace(e.reason)
}

func NewHumanRejectError(reason string) error {
	return &humanRejectError{reason: strings.TrimSpace(reason)}
}

func IsHumanRejectError(err error) bool {
	var target *humanRejectError
	return errors.As(err, &target)
}

func WithHITLToolInterceptor(ctx context.Context, fn HITLToolInterceptor) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, hitlInterceptorKey{}, fn)
}

func hitlToolCallMiddleware() compose.InvokableToolMiddleware {
	return func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
		return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
			if input != nil {
				if fn, ok := ctx.Value(hitlInterceptorKey{}).(HITLToolInterceptor); ok && fn != nil {
					edited, err := fn(ctx, input.Name, input.Arguments)
					if err != nil {
						if IsHumanRejectError(err) {
							// Human rejection should be a soft tool result so the model can continue iterating.
							msg := fmt.Sprintf("[HITL Reject] Tool '%s' was rejected by human reviewer. Reason: %s\nPlease adjust parameters/plan and continue without this call.",
								input.Name, strings.TrimSpace(err.Error()))
							// transfer_to_agent 在 Eino 中标记为 returnDirectly：工具成功后 ReAct 子图会直接 END，
							// 并依赖真实工具内的 SendToolGenAction 触发移交。HITL 拒绝时不会执行真实工具，
							// 若仍走 returnDirectly 分支，监督者会在无 Transfer 动作的情况下结束，模型不再迭代。
							if strings.EqualFold(strings.TrimSpace(input.Name), adk.TransferToAgentToolName) {
								_ = compose.ProcessState[*adk.State](ctx, func(_ context.Context, st *adk.State) error {
									if st == nil {
										return nil
									}
									st.ReturnDirectlyToolCallID = ""
									st.HasReturnDirectly = false
									st.ReturnDirectlyEvent = nil
									return nil
								})
							}
							return &compose.ToolOutput{Result: msg}, nil
						}
						return nil, err
					}
					if edited != "" {
						input.Arguments = edited
					}
				}
			}
			return next(ctx, input)
		}
	}
}
