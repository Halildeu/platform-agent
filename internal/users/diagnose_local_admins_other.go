//go:build !windows

package users

// DiagnoseLocalAdmins is Windows-only: it inspects the local SAM Administrators
// alias and the machine account-domain SID. On other platforms it returns
// ErrLocalUserListingUnsupported so the agent still builds/tests on the dev host.
func DiagnoseLocalAdmins() (LocalAdminDiagnostic, error) {
	return LocalAdminDiagnostic{}, ErrLocalUserListingUnsupported
}
