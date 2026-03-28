package gomat

import (
	"context"
	"errors"
	"net"

	"github.com/power2go-com-br/gomat/mattertlv"
)

// SubscriptionReport represents a single report received on a subscription.
type SubscriptionReport struct {
	Tlv     mattertlv.TlvItem // parsed TLV payload
	Payload []byte            // raw payload bytes
	IsEvent bool              // true if this came from EventReports (tag 2), false for AttributeReports (tag 1)
}

// SubscriptionChannel abstracts the send/receive operations needed for subscriptions.
// SecureChannel implements this interface.
type SubscriptionChannel interface {
	Send(data []byte) error
	Receive() (DecodedGeneric, error)
}

// isTimeoutError checks if an error is a network timeout.
func isTimeoutError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// classifyReport determines if a ReportData contains event or attribute reports.
// EventReports are at tag 2, AttributeReports are at tag 1.
func classifyReport(tlv mattertlv.TlvItem) bool {
	return tlv.GetItemWithTag(2) != nil
}

// SubscribeAndReceive sends a subscribe request on the given channel,
// handles the initial handshake (ReportData + StatusResponse), and returns
// a channel that emits SubscriptionReport values for each incoming ReportData.
//
// The channel is closed when:
//   - ctx is cancelled
//   - the session drops (receive returns a non-timeout error)
//
// The caller must read from the channel to prevent backpressure.
// Buffer size is 16 to absorb short bursts.
func SubscribeAndReceive(ctx context.Context, sc SubscriptionChannel, request []byte) (<-chan SubscriptionReport, error) {
	// Send the subscribe request
	if err := sc.Send(request); err != nil {
		return nil, err
	}

	// Receive initial ReportData (primed data)
	initial, err := sc.Receive()
	if err != nil {
		return nil, err
	}
	if initial.ProtocolHeader.Opcode != INTERACTION_OPCODE_REPORT_DATA {
		return nil, errors.New("expected ReportData for initial subscription response")
	}

	// Send StatusResponse with iflag=1 to acknowledge the initial report
	sr := EncodeIMStatusResponse(initial.ProtocolHeader.ExchangeId, 1)
	if err := sc.Send(sr); err != nil {
		return nil, err
	}

	ch := make(chan SubscriptionReport, 16)

	go func() {
		defer close(ch)
		for {
			if ctx.Err() != nil {
				return
			}

			r, err := sc.Receive()
			if err != nil {
				if isTimeoutError(err) {
					continue
				}
				// Non-timeout error — session dropped
				return
			}

			switch r.ProtocolHeader.Opcode {
			case INTERACTION_OPCODE_REPORT_DATA:
				sr := EncodeIMStatusResponse(r.ProtocolHeader.ExchangeId, 0)
				_ = sc.Send(sr)

				report := SubscriptionReport{
					Tlv:     r.Tlv,
					Payload: r.Payload,
					IsEvent: classifyReport(r.Tlv),
				}

				select {
				case ch <- report:
				case <-ctx.Done():
					return
				}

			case INTERACTION_OPCODE_SUBSC_RSP:
				continue
			case INTERACTION_OPCODE_STATUS_RSP:
				continue
			}
		}
	}()

	return ch, nil
}
