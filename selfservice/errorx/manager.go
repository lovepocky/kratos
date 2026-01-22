// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package errorx

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/kratos/x/nosurfx"

	"github.com/ory/kratos/driver/config"

	"github.com/ory/x/urlx"

	"github.com/ory/kratos/x"
)

type (
	managerDependencies interface {
		PersistenceProvider
		x.LoggingProvider
		x.WriterProvider
		nosurfx.CSRFTokenGeneratorProvider
		config.Provider
	}

	Manager struct {
		d managerDependencies
	}

	ManagementProvider interface {
		// SelfServiceErrorManager returns the errorx.Manager.
		SelfServiceErrorManager() *Manager
	}
)

func NewManager(d managerDependencies) *Manager {
	return &Manager{d: d}
}

// Create is a simple helper that saves all errors in the store and returns the
// error url, appending the error ID.
func (m *Manager) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, err error) (string, error) {
	m.d.Logger().WithError(err).WithRequest(r).Errorf("An error occurred and is being forwarded to the error user interface.")

	id, addErr := m.d.SelfServiceErrorPersister().CreateErrorContainer(ctx, m.d.GenerateCSRFToken(r), err)
	if addErr != nil {
		return "", addErr
	}
	q := url.Values{}
	q.Set("id", id.String())

	// Check if the request is from FuxPixelLab app by user-agent
	errorURL := m.d.Config().SelfServiceFlowErrorURL(ctx)
	userAgent := r.Header.Get("User-Agent")
	m.d.Logger().WithField("user_agent", userAgent).Debug("Checking user-agent for error URL determination")

	// Check if user-agent contains "fuxpixel" (case-insensitive)
	userAgentLower := strings.ToLower(userAgent)
	if strings.Contains(userAgentLower, "fuxpixel") {
		// Use Flutter deep link scheme for FuxPixelLab app
		if parsedURL, parseErr := url.Parse("https://error"); parseErr == nil {
			errorURL = parsedURL
			m.d.Logger().WithField("error_url", errorURL.String()).Debug("Using Flutter deep link for FuxPixelLab app")
		} else {
			m.d.Logger().WithError(parseErr).Warn("Failed to parse Flutter deep link URL, using default error URL")
		}
	} else {
		m.d.Logger().WithField("default_error_url", errorURL.String()).Debug("Using default error URL for non-FuxPixelLab request")
	}

	finalURL := urlx.CopyWithQuery(errorURL, q).String()
	m.d.Logger().WithField("final_error_url", finalURL).Debug("Generated final error URL")
	return finalURL, nil
}

// Forward is a simple helper that saves all errors in the store and forwards the HTTP Request
// to the error url, appending the error ID.
func (m *Manager) Forward(ctx context.Context, w http.ResponseWriter, r *http.Request, err error) {
	if x.IsJSONRequest(r) {
		m.d.Writer().WriteError(w, r, err)
		return
	}

	to, errCreate := m.Create(ctx, w, r, err)
	if errCreate != nil {
		// Everything failed. Resort to standard error output.
		m.d.Logger().WithError(errCreate).WithRequest(r).Error("Failed to create error container.")
		m.d.Writer().WriteError(w, r, err)
		return
	}

	if x.AcceptsJSON(r) {
		m.d.Writer().WriteError(w, r, err)
		return
	}

	http.Redirect(w, r, to, http.StatusSeeOther)
}
