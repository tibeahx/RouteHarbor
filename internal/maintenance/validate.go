package maintenance

import "errors"

func ValidateRequest(request Request, start bool) error {
	if request.Action != "install" && request.Action != "upgrade" && request.Action != "remove" {
		return errors.New("maintenance_action_invalid")
	}
	if len(request.Components) == 0 || len(request.Components) > 5 {
		return errors.New("maintenance_components_invalid")
	}
	seen := map[string]bool{}
	for _, component := range request.Components {
		switch component {
		case "routeharbor",
			"routeharbor-sing-box",
			"routeharbor-xray",
			"routeharbor-conntrack",
			"routeharbor-continuity":
		case "routeharbor-guard":
			return errors.New("maintenance_guard_replacement_unsupported")
		default:
			return errors.New("maintenance_component_unsupported")
		}
		if seen[component] {
			return errors.New("maintenance_duplicate_component")
		}
		seen[component] = true
	}
	if request.Action == "remove" {
		if request.BundleID != "" ||
			(request.RemovalPolicy != "preserve-closed" && request.RemovalPolicy != "restore-direct") {
			return errors.New("maintenance_removal_policy_required")
		}
	} else if !hexID.MatchString(request.BundleID) || request.RemovalPolicy != "" {
		return errors.New("maintenance_bundle_id_invalid")
	}
	if (start || request.ExpectedInstalledDigest != "") &&
		!hashID.MatchString(request.ExpectedInstalledDigest) {
		return errors.New("maintenance_installed_digest_required")
	}
	return nil
}

func ValidateWire(request WireRequest) error {
	switch request.Action {
	case "capabilities", "bundles":
		if request.ID != "" || request.Request != nil {
			return errors.New("maintenance_request_invalid")
		}
	case "plan":
		if request.ID != "" || request.Request == nil {
			return errors.New("maintenance_request_invalid")
		}
		return ValidateRequest(*request.Request, false)
	case "start":
		if !hexID.MatchString(request.ID) || request.Request == nil {
			return errors.New("maintenance_request_invalid")
		}
		return ValidateRequest(*request.Request, true)
	case "status":
		if !hexID.MatchString(request.ID) || request.Request != nil {
			return errors.New("maintenance_request_invalid")
		}
	default:
		return errors.New("maintenance_action_invalid")
	}
	return nil
}
