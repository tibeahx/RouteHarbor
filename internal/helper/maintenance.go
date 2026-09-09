package helper

import (
	"context"
	"errors"

	"github.com/tibeahx/OpenRHP/internal/maintenance"
)

// MaintenanceClient forwards only typed, local, administrator-approved operations.
type MaintenanceClient struct{ Client *Client }

func (c MaintenanceClient) invoke(
	ctx context.Context,
	request maintenance.WireRequest,
) (maintenance.WireResponse, error) {
	if c.Client == nil {
		return maintenance.WireResponse{}, errors.New("maintenance_unavailable")
	}
	response, err := c.Client.call(ctx, Request{Operation: "maintenance", Maintenance: &request})
	if err != nil {
		return maintenance.WireResponse{}, err
	}
	if response.Maintenance == nil {
		return maintenance.WireResponse{}, errors.New("invalid_helper_response")
	}
	return *response.Maintenance, nil
}

func (c MaintenanceClient) Capabilities(ctx context.Context) (map[string]any, error) {
	r, e := c.invoke(ctx, maintenance.WireRequest{Action: "capabilities"})
	return r.Capabilities, e
}

func (c MaintenanceClient) Bundles(ctx context.Context) ([]maintenance.BundleSummary, error) {
	r, e := c.invoke(ctx, maintenance.WireRequest{Action: "bundles"})
	return r.Bundles, e
}

func (c MaintenanceClient) Plan(
	ctx context.Context,
	q maintenance.Request,
) (maintenance.Plan, error) {
	r, e := c.invoke(ctx, maintenance.WireRequest{Action: "plan", Request: &q})
	if e != nil {
		return maintenance.Plan{}, e
	}
	if r.Plan == nil {
		return maintenance.Plan{}, errors.New("invalid_helper_response")
	}
	return *r.Plan, nil
}

func (c MaintenanceClient) Start(
	ctx context.Context,
	id string,
	q maintenance.Request,
) (maintenance.Operation, error) {
	r, e := c.invoke(ctx, maintenance.WireRequest{Action: "start", ID: id, Request: &q})
	if e != nil {
		return maintenance.Operation{}, e
	}
	if r.Operation == nil {
		return maintenance.Operation{}, errors.New("invalid_helper_response")
	}
	return *r.Operation, nil
}

func (c MaintenanceClient) Status(ctx context.Context, id string) (maintenance.Operation, error) {
	r, e := c.invoke(ctx, maintenance.WireRequest{Action: "status", ID: id})
	if e != nil {
		return maintenance.Operation{}, e
	}
	if r.Operation == nil {
		return maintenance.Operation{}, errors.New("invalid_helper_response")
	}
	return *r.Operation, nil
}

func serveMaintenance(
	ctx context.Context,
	service maintenance.Service,
	request maintenance.WireRequest,
) (*maintenance.WireResponse, error) {
	if err := maintenance.ValidateWire(request); err != nil {
		return nil, err
	}
	if service == nil {
		return nil, errors.New("maintenance_unavailable")
	}
	var response maintenance.WireResponse
	var err error
	switch request.Action {
	case "capabilities":
		response.Capabilities, err = service.Capabilities(ctx)
	case "bundles":
		response.Bundles, err = service.Bundles(ctx)
	case "plan":
		value, e := service.Plan(ctx, *request.Request)
		response.Plan, err = &value, e
	case "start":
		value, e := service.Start(ctx, request.ID, *request.Request)
		response.Operation, err = &value, e
	case "status":
		value, e := service.Status(ctx, request.ID)
		response.Operation, err = &value, e
	default:
		err = errors.New("maintenance_action_invalid")
	}
	return &response, err
}
