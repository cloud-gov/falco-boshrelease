package models

import (
	"errors"
	"strings"
	"time"

	"code.cloudfoundry.org/bbs/format"
)

const (
	ActualLRPStateUnclaimed = "UNCLAIMED"
	ActualLRPStateClaimed   = "CLAIMED"
	ActualLRPStateRunning   = "RUNNING"
	ActualLRPStateCrashed   = "CRASHED"

	CrashResetTimeout            = 5 * time.Minute
	RetireActualLRPRetryAttempts = 5
)

var ActualLRPStates = []string{
	ActualLRPStateUnclaimed,
	ActualLRPStateClaimed,
	ActualLRPStateRunning,
	ActualLRPStateCrashed,
}

type ActualLRPChange struct {
	Before *ActualLRPGroup
	After  *ActualLRPGroup
}

type ActualLRPFilter struct {
	Domain string
	CellID string
}

func NewActualLRPKey(processGuid string, index int32, domain string) ActualLRPKey {
	return ActualLRPKey{processGuid, index, domain}
}

func NewActualLRPInstanceKey(instanceGuid string, cellId string) ActualLRPInstanceKey {
	return ActualLRPInstanceKey{instanceGuid, cellId}
}

func NewActualLRPNetInfo(address string, instanceAddress string, ports ...*PortMapping) ActualLRPNetInfo {
	return ActualLRPNetInfo{address, ports, instanceAddress}
}

func EmptyActualLRPNetInfo() ActualLRPNetInfo {
	return NewActualLRPNetInfo("", "")
}

func (info ActualLRPNetInfo) Empty() bool {
	return info.Address == "" && len(info.Ports) == 0
}

func (*ActualLRPNetInfo) Version() format.Version {
	return format.V0
}

func NewPortMapping(hostPort, containerPort uint32) *PortMapping {
	return &PortMapping{
		HostPort:      hostPort,
		ContainerPort: containerPort,
	}
}

func (key ActualLRPInstanceKey) Empty() bool {
	return key.InstanceGuid == "" && key.CellId == ""
}

const StaleUnclaimedActualLRPDuration = 30 * time.Second

func (actual ActualLRP) ShouldStartUnclaimed(now time.Time) bool {
	if actual.State != ActualLRPStateUnclaimed {
		return false
	}

	if now.Sub(time.Unix(0, actual.Since)) > StaleUnclaimedActualLRPDuration {
		return true
	}

	return false
}

func (actual ActualLRP) CellIsMissing(cellSet CellSet) bool {
	if actual.State == ActualLRPStateUnclaimed ||
		actual.State == ActualLRPStateCrashed {
		return false
	}

	return !cellSet.HasCellID(actual.CellId)
}

func (actual ActualLRP) ShouldRestartImmediately(calc RestartCalculator) bool {
	if actual.State != ActualLRPStateCrashed {
		return false
	}

	return calc.ShouldRestart(0, 0, actual.CrashCount)
}

func (actual ActualLRP) ShouldRestartCrash(now time.Time, calc RestartCalculator) bool {
	if actual.State != ActualLRPStateCrashed {
		return false
	}

	return calc.ShouldRestart(now.UnixNano(), actual.Since, actual.CrashCount)
}

func (before ActualLRP) AllowsTransitionTo(lrpKey *ActualLRPKey, instanceKey *ActualLRPInstanceKey, newState string) bool {
	if !before.ActualLRPKey.Equal(lrpKey) {
		return false
	}

	var valid bool
	switch before.State {
	case ActualLRPStateUnclaimed:
		valid = newState == ActualLRPStateUnclaimed ||
			newState == ActualLRPStateClaimed ||
			newState == ActualLRPStateRunning
	case ActualLRPStateClaimed:
		valid = newState == ActualLRPStateUnclaimed && instanceKey.Empty() ||
			newState == ActualLRPStateClaimed && before.ActualLRPInstanceKey.Equal(instanceKey) ||
			newState == ActualLRPStateRunning ||
			newState == ActualLRPStateCrashed && before.ActualLRPInstanceKey.Equal(instanceKey)
	case ActualLRPStateRunning:
		valid = newState == ActualLRPStateUnclaimed && instanceKey.Empty() ||
			newState == ActualLRPStateClaimed && before.ActualLRPInstanceKey.Equal(instanceKey) ||
			newState == ActualLRPStateRunning && before.ActualLRPInstanceKey.Equal(instanceKey) ||
			newState == ActualLRPStateCrashed && before.ActualLRPInstanceKey.Equal(instanceKey)
	case ActualLRPStateCrashed:
		valid = newState == ActualLRPStateUnclaimed && instanceKey.Empty() ||
			newState == ActualLRPStateClaimed && before.ActualLRPInstanceKey.Equal(instanceKey) ||
			newState == ActualLRPStateRunning && before.ActualLRPInstanceKey.Equal(instanceKey)
	}

	return valid
}

func NewRunningActualLRPGroup(actualLRP *ActualLRP) *ActualLRPGroup {
	return &ActualLRPGroup{
		Instance: actualLRP,
	}
}

func NewEvacuatingActualLRPGroup(actualLRP *ActualLRP) *ActualLRPGroup {
	return &ActualLRPGroup{
		Evacuating: actualLRP,
	}
}

func (group ActualLRPGroup) Resolve() (*ActualLRP, bool) {
	switch {
	case group.Instance == nil && group.Evacuating == nil:
		panic(ErrActualLRPGroupInvalid)

	case group.Instance == nil:
		return group.Evacuating, true

	case group.Evacuating == nil:
		return group.Instance, false

	case group.Instance.State == ActualLRPStateRunning || group.Instance.State == ActualLRPStateCrashed:
		return group.Instance, false

	default:
		return group.Evacuating, true
	}
}

func NewUnclaimedActualLRP(lrpKey ActualLRPKey, since int64) *ActualLRP {
	return &ActualLRP{
		ActualLRPKey: lrpKey,
		State:        ActualLRPStateUnclaimed,
		Since:        since,
	}
}

func NewClaimedActualLRP(lrpKey ActualLRPKey, instanceKey ActualLRPInstanceKey, since int64) *ActualLRP {
	return &ActualLRP{
		ActualLRPKey:         lrpKey,
		ActualLRPInstanceKey: instanceKey,
		State:                ActualLRPStateClaimed,
		Since:                since,
	}
}

func NewRunningActualLRP(lrpKey ActualLRPKey, instanceKey ActualLRPInstanceKey, netInfo ActualLRPNetInfo, since int64) *ActualLRP {
	return &ActualLRP{
		ActualLRPKey:         lrpKey,
		ActualLRPInstanceKey: instanceKey,
		ActualLRPNetInfo:     netInfo,
		State:                ActualLRPStateRunning,
		Since:                since,
	}
}

func (*ActualLRP) Version() format.Version {
	return format.V0
}

func (actual ActualLRP) Validate() error {
	var validationError ValidationError

	err := actual.ActualLRPKey.Validate()
	if err != nil {
		validationError = validationError.Append(err)
	}

	if actual.Since == 0 {
		validationError = validationError.Append(ErrInvalidField{"since"})
	}

	switch actual.State {
	case ActualLRPStateUnclaimed:
		if !actual.ActualLRPInstanceKey.Empty() {
			validationError = validationError.Append(errors.New("instance key cannot be set when state is unclaimed"))
		}
		if !actual.ActualLRPNetInfo.Empty() {
			validationError = validationError.Append(errors.New("net info cannot be set when state is unclaimed"))
		}

	case ActualLRPStateClaimed:
		if err := actual.ActualLRPInstanceKey.Validate(); err != nil {
			validationError = validationError.Append(err)
		}
		if !actual.ActualLRPNetInfo.Empty() {
			validationError = validationError.Append(errors.New("net info cannot be set when state is claimed"))
		}
		if strings.TrimSpace(actual.PlacementError) != "" {
			validationError = validationError.Append(errors.New("placement error cannot be set when state is claimed"))
		}

	case ActualLRPStateRunning:
		if err := actual.ActualLRPInstanceKey.Validate(); err != nil {
			validationError = validationError.Append(err)
		}
		if err := actual.ActualLRPNetInfo.Validate(); err != nil {
			validationError = validationError.Append(err)
		}
		if strings.TrimSpace(actual.PlacementError) != "" {
			validationError = validationError.Append(errors.New("placement error cannot be set when state is running"))
		}

	case ActualLRPStateCrashed:
		if !actual.ActualLRPInstanceKey.Empty() {
			validationError = validationError.Append(errors.New("instance key cannot be set when state is crashed"))
		}
		if !actual.ActualLRPNetInfo.Empty() {
			validationError = validationError.Append(errors.New("net info cannot be set when state is crashed"))
		}
		if strings.TrimSpace(actual.PlacementError) != "" {
			validationError = validationError.Append(errors.New("placement error cannot be set when state is crashed"))
		}

	default:
		validationError = validationError.Append(ErrInvalidField{"state"})
	}

	if !validationError.Empty() {
		return validationError
	}

	return nil
}

func (key *ActualLRPKey) Validate() error {
	var validationError ValidationError

	if key.ProcessGuid == "" {
		validationError = validationError.Append(ErrInvalidField{"process_guid"})
	}

	if key.Index < 0 {
		validationError = validationError.Append(ErrInvalidField{"index"})
	}

	if key.Domain == "" {
		validationError = validationError.Append(ErrInvalidField{"domain"})
	}

	if !validationError.Empty() {
		return validationError
	}

	return nil
}

func (key *ActualLRPNetInfo) Validate() error {
	var validationError ValidationError

	if key.Address == "" {
		return validationError.Append(ErrInvalidField{"address"})
	}

	return nil
}

func (key *ActualLRPInstanceKey) Validate() error {
	var validationError ValidationError

	if key.CellId == "" {
		validationError = validationError.Append(ErrInvalidField{"cell_id"})
	}

	if key.InstanceGuid == "" {
		validationError = validationError.Append(ErrInvalidField{"instance_guid"})
	}

	if !validationError.Empty() {
		return validationError
	}

	return nil
}
