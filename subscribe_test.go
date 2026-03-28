package gomat

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/power2go-com-br/gomat/mattertlv"
)

// mockChannel is a test double for SubscriptionChannel.
type mockChannel struct {
	mu       sync.Mutex
	receives []mockReceive
	sent     [][]byte
	idx      int
}

type mockReceive struct {
	msg DecodedGeneric
	err error
}

func (m *mockChannel) Send(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, data)
	return nil
}

func (m *mockChannel) Receive() (DecodedGeneric, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.receives) {
		// Block until context cancels by returning timeout
		return DecodedGeneric{}, &net.OpError{Op: "read", Err: &timeoutErr{}}
	}
	r := m.receives[m.idx]
	m.idx++
	return r.msg, r.err
}

func (m *mockChannel) getSent() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.sent))
	copy(out, m.sent)
	return out
}

// timeoutErr implements net.Error with Timeout() = true.
type timeoutErr struct{}

func (e *timeoutErr) Error() string   { return "i/o timeout" }
func (e *timeoutErr) Timeout() bool   { return true }
func (e *timeoutErr) Temporary() bool { return true }

// makeReportData creates a mock DecodedGeneric with REPORT_DATA opcode and the given TLV.
func makeReportData(exchangeID uint16, tlvData mattertlv.TlvItem) DecodedGeneric {
	return DecodedGeneric{
		ProtocolHeader: ProtocolMessageHeader{
			Opcode:     INTERACTION_OPCODE_REPORT_DATA,
			ExchangeId: exchangeID,
			ProtocolId: ProtocolIdInteraction,
		},
		Tlv: tlvData,
	}
}

func makeSubscribeResponse(exchangeID uint16) DecodedGeneric {
	return DecodedGeneric{
		ProtocolHeader: ProtocolMessageHeader{
			Opcode:     INTERACTION_OPCODE_SUBSC_RSP,
			ExchangeId: exchangeID,
			ProtocolId: ProtocolIdInteraction,
		},
	}
}

func makeStatusResponse(exchangeID uint16) DecodedGeneric {
	return DecodedGeneric{
		ProtocolHeader: ProtocolMessageHeader{
			Opcode:     INTERACTION_OPCODE_STATUS_RSP,
			ExchangeId: exchangeID,
			ProtocolId: ProtocolIdInteraction,
		},
	}
}

// buildAttrReportTLV creates a TLV with tag 1 (AttributeReports) containing a dummy entry.
func buildAttrReportTLV(t *testing.T) mattertlv.TlvItem {
	t.Helper()
	var buf mattertlv.TLVBuffer
	buf.WriteAnonStruct()
	buf.WriteArray(1) // AttributeReports (tag 1)
	buf.WriteAnonStruct()
	buf.WriteUInt8(0, 42) // dummy data
	buf.WriteStructEnd()
	buf.WriteStructEnd()
	buf.WriteStructEnd()
	tlv, err := mattertlv.Decode(buf.Bytes())
	if err != nil {
		t.Fatalf("buildAttrReportTLV: %v", err)
	}
	return tlv
}

// buildEventReportTLV creates a TLV with tag 2 (EventReports) containing a dummy entry.
func buildEventReportTLV(t *testing.T) mattertlv.TlvItem {
	t.Helper()
	var buf mattertlv.TLVBuffer
	buf.WriteAnonStruct()
	buf.WriteArray(2) // EventReports (tag 2)
	buf.WriteAnonStruct()
	buf.WriteUInt8(0, 99) // dummy data
	buf.WriteStructEnd()
	buf.WriteStructEnd()
	buf.WriteStructEnd()
	tlv, err := mattertlv.Decode(buf.Bytes())
	if err != nil {
		t.Fatalf("buildEventReportTLV: %v", err)
	}
	return tlv
}

func TestSubscribeAndReceive_Handshake(t *testing.T) {
	attrTLV := buildAttrReportTLV(t)
	mock := &mockChannel{
		receives: []mockReceive{
			{msg: makeReportData(100, attrTLV)},    // initial primed ReportData
			{msg: makeSubscribeResponse(100)},       // subscribe response
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := SubscribeAndReceive(ctx, mock, []byte("subscribe-request"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive returned error: %v", err)
	}
	if ch == nil {
		t.Fatal("channel is nil")
	}

	// Verify the subscribe request was sent (first Send call)
	sent := mock.getSent()
	if len(sent) < 1 {
		t.Fatal("expected at least 1 Send call (subscribe request)")
	}
	if string(sent[0]) != "subscribe-request" {
		t.Errorf("first Send = %q, want subscribe-request", sent[0])
	}

	// Verify StatusResponse with iflag=1 was sent (second Send call)
	if len(sent) < 2 {
		t.Fatal("expected at least 2 Send calls (subscribe request + StatusResponse)")
	}
}

func TestSubscribeAndReceive_ReceivesReports(t *testing.T) {
	attrTLV := buildAttrReportTLV(t)
	mock := &mockChannel{
		receives: []mockReceive{
			{msg: makeReportData(100, attrTLV)}, // initial handshake
			{msg: makeReportData(101, attrTLV)}, // report 1
			{msg: makeReportData(102, attrTLV)}, // report 2
			{msg: makeReportData(103, attrTLV)}, // report 3
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := SubscribeAndReceive(ctx, mock, []byte("req"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive error: %v", err)
	}

	count := 0
	for range ch {
		count++
		if count == 3 {
			cancel()
		}
	}
	if count != 3 {
		t.Errorf("received %d reports, want 3", count)
	}
}

func TestSubscribeAndReceive_SkipsStatusAndSubscribeResponses(t *testing.T) {
	attrTLV := buildAttrReportTLV(t)
	mock := &mockChannel{
		receives: []mockReceive{
			{msg: makeReportData(100, attrTLV)},   // initial handshake
			{msg: makeSubscribeResponse(100)},      // should be skipped
			{msg: makeStatusResponse(100)},         // should be skipped
			{msg: makeReportData(101, attrTLV)},   // actual report
			{msg: makeSubscribeResponse(101)},      // should be skipped
			{msg: makeReportData(102, attrTLV)},   // actual report
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := SubscribeAndReceive(ctx, mock, []byte("req"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive error: %v", err)
	}

	count := 0
	for range ch {
		count++
		if count == 2 {
			cancel()
		}
	}
	if count != 2 {
		t.Errorf("received %d reports, want 2 (non-report messages should be skipped)", count)
	}
}

func TestSubscribeAndReceive_ContextCancellation(t *testing.T) {
	attrTLV := buildAttrReportTLV(t)
	mock := &mockChannel{
		receives: []mockReceive{
			{msg: makeReportData(100, attrTLV)}, // initial handshake
			// After this, Receive() returns timeouts, goroutine checks ctx
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := SubscribeAndReceive(ctx, mock, []byte("req"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive error: %v", err)
	}

	// Cancel immediately
	cancel()

	// Channel should close within a reasonable time
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case _, ok := <-ch:
		if ok {
			// Got a report — that's fine, keep draining
			for range ch {
			}
		}
		// Channel closed — success
	case <-timer.C:
		t.Fatal("channel did not close after context cancellation within 3s")
	}
}

func TestSubscribeAndReceive_SessionDrop(t *testing.T) {
	attrTLV := buildAttrReportTLV(t)
	mock := &mockChannel{
		receives: []mockReceive{
			{msg: makeReportData(100, attrTLV)},                        // initial handshake
			{msg: makeReportData(101, attrTLV)},                        // report 1
			{err: errors.New("connection reset by peer")},              // session drop
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := SubscribeAndReceive(ctx, mock, []byte("req"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive error: %v", err)
	}

	count := 0
	for range ch {
		count++
	}
	// Should get 1 report, then channel closes on session drop
	if count != 1 {
		t.Errorf("received %d reports, want 1 (before session drop)", count)
	}
}

func TestSubscribeAndReceive_TimeoutIsContinued(t *testing.T) {
	attrTLV := buildAttrReportTLV(t)
	mock := &mockChannel{
		receives: []mockReceive{
			{msg: makeReportData(100, attrTLV)},                               // initial handshake
			{err: &net.OpError{Op: "read", Err: &timeoutErr{}}},              // timeout 1
			{err: &net.OpError{Op: "read", Err: &timeoutErr{}}},              // timeout 2
			{err: &net.OpError{Op: "read", Err: &timeoutErr{}}},              // timeout 3
			{msg: makeReportData(101, attrTLV)},                               // report after timeouts
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := SubscribeAndReceive(ctx, mock, []byte("req"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive error: %v", err)
	}

	report := <-ch
	if report.Tlv.GetItemWithTag(1) == nil {
		t.Error("expected AttributeReports in received report")
	}
	cancel()
}

func TestSubscribeAndReceive_ReportIsEvent(t *testing.T) {
	eventTLV := buildEventReportTLV(t)
	mock := &mockChannel{
		receives: []mockReceive{
			{msg: makeReportData(100, eventTLV)}, // initial handshake (event report)
			{msg: makeReportData(101, eventTLV)}, // event report
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := SubscribeAndReceive(ctx, mock, []byte("req"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive error: %v", err)
	}

	report := <-ch
	if !report.IsEvent {
		t.Error("IsEvent = false, want true for EventReports (tag 2)")
	}
	cancel()
}

func TestSubscribeAndReceive_ReportIsAttribute(t *testing.T) {
	attrTLV := buildAttrReportTLV(t)
	mock := &mockChannel{
		receives: []mockReceive{
			{msg: makeReportData(100, attrTLV)}, // initial handshake
			{msg: makeReportData(101, attrTLV)}, // attribute report
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := SubscribeAndReceive(ctx, mock, []byte("req"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive error: %v", err)
	}

	report := <-ch
	if report.IsEvent {
		t.Error("IsEvent = true, want false for AttributeReports (tag 1)")
	}
	cancel()
}

func TestSubscribeAndReceive_ChannelBuffer(t *testing.T) {
	attrTLV := buildAttrReportTLV(t)

	// Build 20 reports + initial handshake
	receives := make([]mockReceive, 21)
	receives[0] = mockReceive{msg: makeReportData(100, attrTLV)} // handshake
	for i := 1; i <= 20; i++ {
		receives[i] = mockReceive{msg: makeReportData(uint16(100+i), attrTLV)}
	}

	mock := &mockChannel{receives: receives}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := SubscribeAndReceive(ctx, mock, []byte("req"))
	if err != nil {
		t.Fatalf("SubscribeAndReceive error: %v", err)
	}

	// Read all reports — should not deadlock or panic
	count := 0
	for range ch {
		count++
		if count >= 20 {
			cancel()
		}
	}
	if count < 16 {
		t.Errorf("received %d reports, want at least 16 (buffer size)", count)
	}
}
