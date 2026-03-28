package symbols

import "testing"

func TestEnergyClusterConstants(t *testing.T) {
	if ClusterElectricalPowerMeasurement != 0x0090 {
		t.Errorf("ClusterElectricalPowerMeasurement = 0x%x, want 0x0090", ClusterElectricalPowerMeasurement)
	}
	if ClusterElectricalEnergyMeasurement != 0x0091 {
		t.Errorf("ClusterElectricalEnergyMeasurement = 0x%x, want 0x0091", ClusterElectricalEnergyMeasurement)
	}
}

func TestEnergyAttributeConstants(t *testing.T) {
	if AttrActivePower != 5 {
		t.Errorf("AttrActivePower = %d, want 5", AttrActivePower)
	}
	if AttrVoltage != 3 {
		t.Errorf("AttrVoltage = %d, want 3", AttrVoltage)
	}
	if AttrActiveCurrent != 4 {
		t.Errorf("AttrActiveCurrent = %d, want 4", AttrActiveCurrent)
	}
}

func TestEnergyEventConstants(t *testing.T) {
	if EventCumulativeEnergyMeasured != 0 {
		t.Errorf("EventCumulativeEnergyMeasured = %d, want 0", EventCumulativeEnergyMeasured)
	}
	if EventPeriodicEnergyMeasured != 1 {
		t.Errorf("EventPeriodicEnergyMeasured = %d, want 1", EventPeriodicEnergyMeasured)
	}
}
