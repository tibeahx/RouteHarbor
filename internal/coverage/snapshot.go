package coverage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/tibeahx/OpenRHP/internal/adapter"
	"github.com/tibeahx/OpenRHP/internal/platform"
)

type wirelessSnapshot struct {
	APSection string            `json:"ap_section"`
	WDS       *string           `json:"wds"`
	WDSOwner  *string           `json:"wds_owner"`
	Mesh      map[string]string `json:"mesh"`
}

var meshFields = []string{
	"openrhp_owner",
	"device",
	"mode",
	"network",
	"mesh_id",
	"encryption",
	"key",
	"disabled",
}

func (b *UCIBackend) Snapshot(ctx context.Context, p Plan) (Snapshot, error) {
	if err := ValidatePlan(p); err != nil {
		return nil, err
	}
	data, err := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "wireless"}, nil)
	if err != nil {
		return nil, errors.New("gateway_wireless_snapshot_failed")
	}
	w := parseUCI(data)
	s := wirelessSnapshot{APSection: p.APSection}
	if value, ok := w["wireless."+p.APSection+".wds"]; ok {
		s.WDS = &value
	}
	if value, ok := w["wireless."+p.APSection+".openrhp_wds_owner"]; ok {
		s.WDSOwner = &value
	}
	if w["wireless."+meshSection] != "" {
		if w["wireless."+meshSection] != "wifi-iface" ||
			w["wireless."+meshSection+".openrhp_owner"] != "1" {
			return nil, errors.New("gateway_wireless_ownership_conflict")
		}
		s.Mesh = map[string]string{}
		for key := range w {
			if !strings.HasPrefix(key, "wireless."+meshSection+".") {
				continue
			}
			field := strings.TrimPrefix(key, "wireless."+meshSection+".")
			known := false
			for _, name := range meshFields {
				known = known || field == name
			}
			if !known {
				return nil, errors.New("gateway_owned_mesh_has_unrecognized_settings")
			}
		}
		for _, field := range meshFields {
			value, err := b.get(ctx, "wireless."+meshSection+"."+field)
			if err != nil {
				return nil, err
			}
			s.Mesh[field] = value
		}
	}
	data, err = json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if err := validateSnapshot(s); err != nil {
		return nil, err
	}
	return Snapshot{"wireless": data}, nil
}

// Restore touches only the selected AP's WDS flags and the single owned mesh
// section. It never imports a whole wireless package over unrelated AP edits.
func (b *UCIBackend) Restore(ctx context.Context, snapshot Snapshot) error {
	data, ok := snapshot["wireless"]
	if !ok || len(snapshot) != 1 || len(data) == 0 || len(data) > 256<<10 {
		return errors.New("invalid_gateway_snapshot")
	}
	var s wirelessSnapshot
	if adapter.StrictDecode(data, &s) != nil || validateSnapshot(s) != nil {
		return errors.New("invalid_gateway_snapshot")
	}
	current, err := b.Runner.Run(ctx, "/sbin/uci", []string{"-X", "-q", "show", "wireless"}, nil)
	if err != nil {
		return errors.New("gateway_wireless_discovery_failed")
	}
	w := parseUCI(current)
	if w["wireless."+s.APSection] != "wifi-iface" {
		return errors.New("gateway_adopted_ap_missing")
	}
	if w["wireless."+meshSection] != "" && w["wireless."+meshSection+".openrhp_owner"] != "1" {
		return errors.New("gateway_wireless_ownership_conflict")
	}
	var lines strings.Builder
	for _, field := range []struct {
		name  string
		value *string
	}{{"wds", s.WDS}, {"openrhp_wds_owner", s.WDSOwner}} {
		key := "wireless." + s.APSection + "." + field.name
		if field.value != nil {
			lines.WriteString("set " + key + "=" + quoteUCI(*field.value) + "\n")
		} else if _, exists := w[key]; exists {
			lines.WriteString("delete " + key + "\n")
		}
	}
	if w["wireless."+meshSection] != "" {
		lines.WriteString("delete wireless." + meshSection + "\n")
	}
	if s.Mesh != nil {
		lines.WriteString("set wireless." + meshSection + "='wifi-iface'\n")
		for _, field := range meshFields {
			lines.WriteString("set wireless." + meshSection + "." + field + "=" + quoteUCI(
				s.Mesh[field],
			) + "\n")
		}
	}
	if lines.String() != "" {
		if _, err := b.Runner.Run(
			ctx,
			"/sbin/uci",
			[]string{"-q", "batch"},
			[]byte(lines.String()),
		); err != nil {
			return errors.New("gateway_wireless_restore_failed")
		}
	}
	return b.reload(ctx)
}

func validateSnapshot(s wirelessSnapshot) error {
	if !platform.ValidInterfaceName(s.APSection) {
		return errors.New("invalid_gateway_snapshot")
	}
	for _, value := range []*string{s.WDS, s.WDSOwner} {
		if value != nil && *value != "0" && *value != "1" {
			return errors.New("invalid_gateway_snapshot")
		}
	}
	if s.Mesh == nil {
		return nil
	}
	if len(s.Mesh) != len(meshFields) || s.Mesh["openrhp_owner"] != "1" ||
		!platform.ValidInterfaceName(s.Mesh["device"]) ||
		!platform.ValidInterfaceName(s.Mesh["network"]) ||
		s.Mesh["mode"] != "mesh" ||
		s.Mesh["encryption"] != "sae" ||
		!cleanText(s.Mesh["mesh_id"], 1, 32) ||
		!cleanText(s.Mesh["key"], 8, 63) ||
		(s.Mesh["disabled"] != "0" && s.Mesh["disabled"] != "1") {
		return errors.New("invalid_gateway_snapshot")
	}
	return nil
}
