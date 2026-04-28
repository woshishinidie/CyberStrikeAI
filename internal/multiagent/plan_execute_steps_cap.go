package multiagent

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/cloudwego/eino/adk/prebuilt/planexecute"
)

// plan_execute 的 Replanner / Executor prompt 会线性拼接每步 Result；无界时易撑爆上下文。
// 此处仅约束「写入模型 prompt 的视图」，不修改 Eino session 中的原始 ExecutedSteps。

const (
	planExecuteMaxStepResultRunes = 12000
	planExecuteKeepLastSteps      = 16
)

func truncateRunesWithSuffix(s string, maxRunes int, suffix string) string {
	if maxRunes <= 0 || s == "" {
		return s
	}
	rs := []rune(s)
	if len(rs) <= maxRunes {
		return s
	}
	return string(rs[:maxRunes]) + suffix
}

// capPlanExecuteExecutedSteps 折叠较早步骤、截断单步过长结果，供 prompt 使用。
func capPlanExecuteExecutedSteps(steps []planexecute.ExecutedStep) []planexecute.ExecutedStep {
	if len(steps) == 0 {
		return steps
	}
	out := make([]planexecute.ExecutedStep, 0, len(steps)+1)
	start := 0
	if len(steps) > planExecuteKeepLastSteps {
		start = len(steps) - planExecuteKeepLastSteps
		var b strings.Builder
		b.WriteString(fmt.Sprintf("（上文已完成 %d 步；此处仅保留步骤标题以节省上下文，完整输出已省略。后续 %d 步仍保留正文。）\n",
			start, planExecuteKeepLastSteps))
		for i := 0; i < start; i++ {
			b.WriteString(fmt.Sprintf("- %s\n", steps[i].Step))
		}
		out = append(out, planexecute.ExecutedStep{
			Step:   "[Earlier steps — titles only]",
			Result: strings.TrimRight(b.String(), "\n"),
		})
	}
	suffix := "\n…[step result truncated]"
	for i := start; i < len(steps); i++ {
		e := steps[i]
		if utf8.RuneCountInString(e.Result) > planExecuteMaxStepResultRunes {
			e.Result = truncateRunesWithSuffix(e.Result, planExecuteMaxStepResultRunes, suffix)
		}
		out = append(out, e)
	}
	return out
}
