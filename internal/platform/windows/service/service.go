package service

import (
	"fmt"
	"strings"
)

const (
	DefaultName        = "EndpointAgent"
	DefaultDisplayName = "Endpoint Agent"
	DefaultDescription = "Endpoint management platform agent"
)

type Options struct {
	Name        string
	DisplayName string
	Description string
}

type StatusSnapshot struct {
	Name  string
	State string
}

func DefaultOptions() Options {
	return Options{
		Name:        DefaultName,
		DisplayName: DefaultDisplayName,
		Description: DefaultDescription,
	}
}

func (o Options) Normalized() Options {
	if strings.TrimSpace(o.Name) == "" {
		o.Name = DefaultName
	}
	if strings.TrimSpace(o.DisplayName) == "" {
		o.DisplayName = DefaultDisplayName
	}
	if strings.TrimSpace(o.Description) == "" {
		o.Description = DefaultDescription
	}
	o.Name = strings.TrimSpace(o.Name)
	o.DisplayName = strings.TrimSpace(o.DisplayName)
	o.Description = strings.TrimSpace(o.Description)
	return o
}

func (s StatusSnapshot) String() string {
	if s.State == "" {
		return fmt.Sprintf("%s: unknown", s.Name)
	}
	return fmt.Sprintf("%s: %s", s.Name, s.State)
}
