//go:build !windows

package consent

import "context"

func defaultViewOnlyUserPrompt(ctx context.Context, req PromptRequest) (PromptDecision, error) {
	if err := ctx.Err(); err != nil {
		return PromptDecision{}, err
	}
	return PromptDecision{Granted: false, InteractiveSession: "view-only-attended-consent-unavailable"}, nil
}
