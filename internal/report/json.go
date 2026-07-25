package report

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/balyakin/crawlledger/internal/atomicfile"
)

func WriteJSON(ctx context.Context, root *os.Root, name string, model Model) ([]string, error) {
	return atomicfile.WriteNew(ctx, root, name, 0o600, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(model)
	})
}
