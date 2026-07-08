package registry

import (
	"buf.build/go/protovalidate"
	"github.com/cockroachdb/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// NewWarmValidator creates a proto validator pre-compiled for every message
// type in the talos v2alpha1 API. protovalidate compiles CEL validation rules
// lazily per message type, so without warmup the first request per type pays
// a multi-ms compile cost inside the request span. Warming at startup moves
// that cost out of the request path.
//
// dynamicpb messages share descriptors with the generated types, so the
// compiled cache built here is hit when validating real requests. Lazy
// compilation stays enabled on purpose: other packages (e.g. webhooks) may
// validate message types outside this file and must keep working.
func NewWarmValidator() (protovalidate.Validator, error) {
	descriptors := talosv2alpha1.File_api_talos_v2alpha1_talos_proto.Messages()
	messages := make([]proto.Message, 0, descriptors.Len())
	for i := range descriptors.Len() {
		messages = append(messages, dynamicpb.NewMessage(descriptors.Get(i)))
	}

	validator, err := protovalidate.New(protovalidate.WithMessages(messages...))
	if err != nil {
		return nil, errors.Wrap(err, "create proto validator")
	}
	return validator, nil
}
