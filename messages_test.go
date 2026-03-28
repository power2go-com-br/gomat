package gomat

import (
	"testing"

	"github.com/power2go-com-br/gomat/mattertlv"
)

// decodeTLVPayload strips the protocol message header and decodes the TLV payload.
// The protocol header is 6 bytes (exchangeFlags + opcode + exchangeId + protocolId).
func decodeTLVPayload(t *testing.T, raw []byte) mattertlv.TlvItem {
	t.Helper()
	// Protocol message header: 1 (flags) + 1 (opcode) + 2 (exchangeId) + 2 (protocolId) = 6 bytes
	if len(raw) < 6 {
		t.Fatalf("raw message too short: %d bytes", len(raw))
	}
	tlvBytes := raw[6:]
	tlv, err := mattertlv.Decode(tlvBytes)
	if err != nil {
		t.Fatalf("TLV decode failed: %v", err)
	}
	return tlv
}

// --- Step 1: Configurable intervals on event subscription ---

func TestEncodeIMSubscribeRequestEvents_CustomIntervals(t *testing.T) {
	raw := EncodeIMSubscribeRequestEvents(1, 0x0091, 0, 5, 30)
	tlv := decodeTLVPayload(t, raw)

	// Tag 1 = MinIntervalFloorSeconds
	minInterval := tlv.GetItemWithTag(1)
	if minInterval == nil {
		t.Fatal("tag 1 (MinInterval) not found")
	}
	if minInterval.GetInt() != 5 {
		t.Errorf("MinInterval = %d, want 5", minInterval.GetInt())
	}

	// Tag 2 = MaxIntervalCeilingSeconds
	maxInterval := tlv.GetItemWithTag(2)
	if maxInterval == nil {
		t.Fatal("tag 2 (MaxInterval) not found")
	}
	if maxInterval.GetInt() != 30 {
		t.Errorf("MaxInterval = %d, want 30", maxInterval.GetInt())
	}
}

func TestEncodeIMSubscribeRequestEvents_DefaultIntervals(t *testing.T) {
	// The legacy wrapper should use defaults of 10/50
	raw := EncodeIMSubscribeRequest(1, 0x0091, 0)
	tlv := decodeTLVPayload(t, raw)

	minInterval := tlv.GetItemWithTag(1)
	if minInterval == nil {
		t.Fatal("tag 1 (MinInterval) not found")
	}
	if minInterval.GetInt() != 10 {
		t.Errorf("MinInterval = %d, want 10", minInterval.GetInt())
	}

	maxInterval := tlv.GetItemWithTag(2)
	if maxInterval == nil {
		t.Fatal("tag 2 (MaxInterval) not found")
	}
	if maxInterval.GetInt() != 50 {
		t.Errorf("MaxInterval = %d, want 50", maxInterval.GetInt())
	}
}

func TestEncodeIMSubscribeRequestEvents_MatchesLegacy(t *testing.T) {
	legacy := EncodeIMSubscribeRequest(1, 0x0091, 0)
	newFunc := EncodeIMSubscribeRequestEvents(1, 0x0091, 0, 10, 50)

	if len(legacy) != len(newFunc) {
		t.Fatalf("length mismatch: legacy=%d, new=%d", len(legacy), len(newFunc))
	}
	for i := range legacy {
		if legacy[i] != newFunc[i] {
			t.Errorf("byte %d differs: legacy=0x%02x, new=0x%02x", i, legacy[i], newFunc[i])
		}
	}
}

// --- Step 2: Attribute subscription encoding ---

func TestEncodeIMSubscribeRequestAttrs_SingleAttr(t *testing.T) {
	raw := EncodeIMSubscribeRequestAttrs(1, 0x0090, []uint32{5}, 10, 50)
	tlv := decodeTLVPayload(t, raw)

	// Tag 3 = AttributeRequests array
	attrReqs := tlv.GetItemWithTag(3)
	if attrReqs == nil {
		t.Fatal("tag 3 (AttributeRequests) not found")
	}

	children := attrReqs.GetChild()
	if len(children) != 1 {
		t.Fatalf("AttributeRequests has %d entries, want 1", len(children))
	}

	// AttributePathIB: tag 2=endpoint, tag 3=cluster, tag 4=attribute
	entry := children[0]
	ep := entry.GetItemWithTag(2)
	if ep == nil {
		t.Fatal("AttributePathIB tag 2 (endpoint) not found")
	}
	if ep.GetInt() != 1 {
		t.Errorf("endpoint = %d, want 1", ep.GetInt())
	}

	cl := entry.GetItemWithTag(3)
	if cl == nil {
		t.Fatal("AttributePathIB tag 3 (cluster) not found")
	}
	if cl.GetInt() != 0x0090 {
		t.Errorf("cluster = 0x%x, want 0x0090", cl.GetInt())
	}

	attr := entry.GetItemWithTag(4)
	if attr == nil {
		t.Fatal("AttributePathIB tag 4 (attribute) not found")
	}
	if attr.GetInt() != 5 {
		t.Errorf("attribute = %d, want 5", attr.GetInt())
	}
}

func TestEncodeIMSubscribeRequestAttrs_MultipleAttrs(t *testing.T) {
	attrs := []uint32{5, 3, 4} // ActivePower, Voltage, ActiveCurrent
	raw := EncodeIMSubscribeRequestAttrs(1, 0x0090, attrs, 10, 50)
	tlv := decodeTLVPayload(t, raw)

	attrReqs := tlv.GetItemWithTag(3)
	if attrReqs == nil {
		t.Fatal("tag 3 (AttributeRequests) not found")
	}

	children := attrReqs.GetChild()
	if len(children) != 3 {
		t.Fatalf("AttributeRequests has %d entries, want 3", len(children))
	}

	for i, wantAttr := range attrs {
		attr := children[i].GetItemWithTag(4)
		if attr == nil {
			t.Fatalf("entry %d: AttributePathIB tag 4 (attribute) not found", i)
		}
		if uint32(attr.GetInt()) != wantAttr {
			t.Errorf("entry %d: attribute = %d, want %d", i, attr.GetInt(), wantAttr)
		}
	}
}

func TestEncodeIMSubscribeRequestAttrs_NoTag4(t *testing.T) {
	raw := EncodeIMSubscribeRequestAttrs(1, 0x0090, []uint32{5}, 10, 50)
	tlv := decodeTLVPayload(t, raw)

	// Tag 4 = EventRequests — must NOT be present in attribute-only subscription
	eventReqs := tlv.GetItemWithTag(4)
	if eventReqs != nil {
		t.Error("tag 4 (EventRequests) should not be present in attribute-only subscription")
	}
}

func TestEncodeIMSubscribeRequestAttrs_PathTagsAreCorrect(t *testing.T) {
	// Regression guard: AttributePathIB uses different tags than EventPathIB
	// AttributePathIB: endpoint=tag2, cluster=tag3, attribute=tag4
	// EventPathIB:     endpoint=tag1, cluster=tag2, event=tag3
	raw := EncodeIMSubscribeRequestAttrs(1, 0x0090, []uint32{5}, 10, 50)
	tlv := decodeTLVPayload(t, raw)

	attrReqs := tlv.GetItemWithTag(3)
	if attrReqs == nil {
		t.Fatal("tag 3 (AttributeRequests) not found")
	}
	entry := attrReqs.GetChild()[0]

	// Tag 1 should NOT be present (that's EventPathIB's endpoint tag)
	if entry.GetItemWithTag(1) != nil {
		t.Error("AttributePathIB should not have tag 1 (EventPathIB endpoint)")
	}

	// Tag 2 = endpoint (AttributePathIB)
	if entry.GetItemWithTag(2) == nil {
		t.Error("AttributePathIB should have tag 2 (endpoint)")
	}

	// Tag 3 = cluster (AttributePathIB)
	if entry.GetItemWithTag(3) == nil {
		t.Error("AttributePathIB should have tag 3 (cluster)")
	}

	// Tag 4 = attribute (AttributePathIB)
	if entry.GetItemWithTag(4) == nil {
		t.Error("AttributePathIB should have tag 4 (attribute)")
	}
}

// --- Step 3: Combined attribute + event subscription encoding ---

func TestEncodeIMSubscribeRequestFull_Combined(t *testing.T) {
	raw := EncodeIMSubscribeRequestFull(SubscribeRequestOptions{
		Endpoint:     1,
		MinInterval:  5,
		MaxInterval:  30,
		AttrCluster:  0x0090,
		Attrs:        []uint32{5},
		EventCluster: 0x0091,
		Events:       []uint32{0},
	})
	tlv := decodeTLVPayload(t, raw)

	// Both tag 3 (AttributeRequests) and tag 4 (EventRequests) must be present
	attrReqs := tlv.GetItemWithTag(3)
	if attrReqs == nil {
		t.Fatal("tag 3 (AttributeRequests) not found in combined subscription")
	}
	if len(attrReqs.GetChild()) != 1 {
		t.Errorf("AttributeRequests has %d entries, want 1", len(attrReqs.GetChild()))
	}

	eventReqs := tlv.GetItemWithTag(4)
	if eventReqs == nil {
		t.Fatal("tag 4 (EventRequests) not found in combined subscription")
	}
	if len(eventReqs.GetChild()) != 1 {
		t.Errorf("EventRequests has %d entries, want 1", len(eventReqs.GetChild()))
	}
}

func TestEncodeIMSubscribeRequestFull_AttrsOnly(t *testing.T) {
	raw := EncodeIMSubscribeRequestFull(SubscribeRequestOptions{
		Endpoint:    1,
		MinInterval: 10,
		MaxInterval: 50,
		AttrCluster: 0x0090,
		Attrs:       []uint32{5, 3, 4},
	})
	tlv := decodeTLVPayload(t, raw)

	if tlv.GetItemWithTag(3) == nil {
		t.Fatal("tag 3 (AttributeRequests) not found")
	}
	if tlv.GetItemWithTag(4) != nil {
		t.Error("tag 4 (EventRequests) should not be present when Events is empty")
	}
}

func TestEncodeIMSubscribeRequestFull_EventsOnly(t *testing.T) {
	raw := EncodeIMSubscribeRequestFull(SubscribeRequestOptions{
		Endpoint:     1,
		MinInterval:  10,
		MaxInterval:  50,
		EventCluster: 0x0091,
		Events:       []uint32{0, 1},
		EventUrgent:  true,
	})
	tlv := decodeTLVPayload(t, raw)

	if tlv.GetItemWithTag(3) != nil {
		t.Error("tag 3 (AttributeRequests) should not be present when Attrs is empty")
	}
	if tlv.GetItemWithTag(4) == nil {
		t.Fatal("tag 4 (EventRequests) not found")
	}
	if len(tlv.GetItemWithTag(4).GetChild()) != 2 {
		t.Errorf("EventRequests has %d entries, want 2", len(tlv.GetItemWithTag(4).GetChild()))
	}
}

func TestEncodeIMSubscribeRequestFull_IntervalDefaults(t *testing.T) {
	raw := EncodeIMSubscribeRequestFull(SubscribeRequestOptions{
		Endpoint:    1,
		AttrCluster: 0x0090,
		Attrs:       []uint32{5},
		// MinInterval and MaxInterval are 0 — should default to 10/50
	})
	tlv := decodeTLVPayload(t, raw)

	minInterval := tlv.GetItemWithTag(1)
	if minInterval == nil {
		t.Fatal("tag 1 (MinInterval) not found")
	}
	if minInterval.GetInt() != 10 {
		t.Errorf("MinInterval = %d, want 10 (default)", minInterval.GetInt())
	}

	maxInterval := tlv.GetItemWithTag(2)
	if maxInterval == nil {
		t.Fatal("tag 2 (MaxInterval) not found")
	}
	if maxInterval.GetInt() != 50 {
		t.Errorf("MaxInterval = %d, want 50 (default)", maxInterval.GetInt())
	}
}

func TestEncodeIMSubscribeRequestFull_EnergyMeterUseCase(t *testing.T) {
	// The exact matter-controller scenario: subscribe to power attributes + energy events
	raw := EncodeIMSubscribeRequestFull(SubscribeRequestOptions{
		Endpoint:     1,
		MinInterval:  5,
		MaxInterval:  30,
		AttrCluster:  0x0090, // Electrical Power Measurement
		Attrs:        []uint32{5, 3, 4}, // ActivePower, Voltage, ActiveCurrent
		EventCluster: 0x0091, // Electrical Energy Measurement
		Events:       []uint32{0, 1}, // CumulativeEnergyMeasured, PeriodicEnergyMeasured
		EventUrgent:  true,
	})
	tlv := decodeTLVPayload(t, raw)

	// Verify intervals
	if tlv.GetItemWithTag(1).GetInt() != 5 {
		t.Errorf("MinInterval = %d, want 5", tlv.GetItemWithTag(1).GetInt())
	}
	if tlv.GetItemWithTag(2).GetInt() != 30 {
		t.Errorf("MaxInterval = %d, want 30", tlv.GetItemWithTag(2).GetInt())
	}

	// Verify 3 attribute paths
	attrReqs := tlv.GetItemWithTag(3)
	if attrReqs == nil {
		t.Fatal("tag 3 (AttributeRequests) not found")
	}
	attrChildren := attrReqs.GetChild()
	if len(attrChildren) != 3 {
		t.Fatalf("AttributeRequests has %d entries, want 3", len(attrChildren))
	}
	for i, wantAttr := range []uint32{5, 3, 4} {
		entry := attrChildren[i]
		if uint32(entry.GetItemWithTag(3).GetInt()) != 0x0090 {
			t.Errorf("attr entry %d: cluster = 0x%x, want 0x0090", i, entry.GetItemWithTag(3).GetInt())
		}
		if uint32(entry.GetItemWithTag(4).GetInt()) != wantAttr {
			t.Errorf("attr entry %d: attribute = %d, want %d", i, entry.GetItemWithTag(4).GetInt(), wantAttr)
		}
	}

	// Verify 2 event paths
	eventReqs := tlv.GetItemWithTag(4)
	if eventReqs == nil {
		t.Fatal("tag 4 (EventRequests) not found")
	}
	eventChildren := eventReqs.GetChild()
	if len(eventChildren) != 2 {
		t.Fatalf("EventRequests has %d entries, want 2", len(eventChildren))
	}
	for i, wantEvent := range []uint32{0, 1} {
		entry := eventChildren[i]
		if uint32(entry.GetItemWithTag(2).GetInt()) != 0x0091 {
			t.Errorf("event entry %d: cluster = 0x%x, want 0x0091", i, entry.GetItemWithTag(2).GetInt())
		}
		if uint32(entry.GetItemWithTag(3).GetInt()) != wantEvent {
			t.Errorf("event entry %d: event = %d, want %d", i, entry.GetItemWithTag(3).GetInt(), wantEvent)
		}
	}

	// Verify IsFabricFiltered and InteractionModelRevision
	fabFiltered := tlv.GetItemWithTag(7)
	if fabFiltered == nil {
		t.Fatal("tag 7 (IsFabricFiltered) not found")
	}
	if fabFiltered.GetBool() != false {
		t.Error("IsFabricFiltered should be false")
	}
}

// --- StatusResponse encoding ---

func TestEncodeIMStatusResponse_HasInteractionModelRevision(t *testing.T) {
	// matter.js rejects StatusResponse messages that are missing the
	// interactionModelRevision field (tag 0xff). Verify it's present.
	raw := EncodeIMStatusResponse(0x1234, 0)
	tlv := decodeTLVPayload(t, raw)

	// Verify status (tag 0) is present and zero (success)
	status := tlv.GetItemWithTag(0)
	if status == nil {
		t.Fatal("tag 0 (Status) not found")
	}
	if status.GetInt() != 0 {
		t.Errorf("Status = %d, want 0", status.GetInt())
	}

	// Verify InteractionModelRevision (tag 0xff) is present
	imRev := tlv.GetItemWithTag(0xff)
	if imRev == nil {
		t.Fatal("tag 0xff (InteractionModelRevision) not found — matter.js requires this field")
	}
	if imRev.GetInt() < 1 {
		t.Errorf("InteractionModelRevision = %d, want >= 1", imRev.GetInt())
	}
}

func TestEncodeIMStatusResponse_ExchangeIdAndFlags(t *testing.T) {
	raw := EncodeIMStatusResponse(0xABCD, 1)
	if len(raw) < 6 {
		t.Fatalf("message too short: %d bytes", len(raw))
	}
	// Protocol header: exchangeFlags(1) + opcode(1) + exchangeId(2) + protocolId(2)
	wantFlags := byte(4 | 1)
	if raw[0] != wantFlags {
		t.Errorf("exchangeFlags = 0x%02x, want 0x%02x", raw[0], wantFlags)
	}
	if Opcode(raw[1]) != INTERACTION_OPCODE_STATUS_RSP {
		t.Errorf("opcode = 0x%02x, want 0x%02x", raw[1], INTERACTION_OPCODE_STATUS_RSP)
	}
	gotExchangeID := uint16(raw[2]) | uint16(raw[3])<<8
	if gotExchangeID != 0xABCD {
		t.Errorf("exchangeID = 0x%04x, want 0xABCD", gotExchangeID)
	}
}
